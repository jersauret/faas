import os
import secrets
import string
import base64
import json
from cryptography.fernet import Fernet
import pyotp
import qrcode
from io import BytesIO
import psycopg2
from psycopg2 import sql
from datetime import datetime, timedelta
from flask import Flask, request

# --- Configuration et Initialisation (via ENV uniquement, pas de secrets OpenFaaS) ---
ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY", "qndx3Dv5HwpBO1CYytW7SNQe19qjMDJvN2nXMB9Dhaw=").encode()
cipher_suite = Fernet(ENCRYPTION_KEY)

DB_HOST = os.getenv("DB_HOST", "postgresql.database.svc.cluster.local")
DB_NAME = os.getenv("DB_NAME", "your_database_name")
DB_USER = os.getenv("DB_USER", "user")
DB_PASSWORD = os.getenv("DB_PASSWORD", "votreMotDePasseFort")

# --- Fonctions utilitaires ---

def generate_secure_password(length=24):
    """Genère un mot de passe securise."""
    characters = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(secrets.choice(characters) for i in range(length))
    return password

def generate_qr_code_base64(data):
    """Genère un QR code à partir des donnees et le retourne en base64."""
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(data)
    qr.make(fit=True)

    img = qr.make_image(fill_color="black", back_color="white")
    buffered = BytesIO()
    img.save(buffered, format="PNG")
    return base64.b64encode(buffered.getvalue()).decode("utf-8")

# --- Fonction principale de la handler ---

TEMPLATE_FORM = '''
<html>
<head>
    <title>COFREPA Cloud - Account Creation</title>
    <style>
        body { font-family: Arial, sans-serif; background: #f4f4f4; }
        .container { max-width: 400px; margin: 60px auto; background: #fff; padding: 30px; border-radius: 8px; box-shadow: 0 2px 8px #ccc; }
        h2 { text-align: center; color: #2c3e50; }
        label { display: block; margin-bottom: 8px; }
        input[type="text"] { width: 100%; padding: 8px; margin-bottom: 16px; border: 1px solid #ccc; border-radius: 4px; }
        button { width: 100%; padding: 10px; background: #2980b9; color: #fff; border: none; border-radius: 4px; font-size: 16px; cursor: pointer; }
        button:hover { background: #3498db; }
        .footer { text-align: center; margin-top: 20px; color: #888; font-size: 13px; }
    </style>
</head>
<body>
    <div class="container">
        <h2>COFREPA Cloud Account Creation</h2>
        <form method="POST" onsubmit="submitForm(event)">
            <label for="username">Username:</label>
            <input type="text" id="username" name="username" required />
            <button type="submit">Generate Password</button>
        </form>
        <div class="footer">Service provided by COFREPA Cloud</div>
    </div>
    <script>
    function submitForm(event) {
        event.preventDefault();
        const username = document.getElementById('username').value;
        fetch(window.location.pathname, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username })
        })
        .then(response => response.json())
        .then(data => {
            if(data.status === 'success') {
                document.body.innerHTML = `<div class='container'><h2>Account Created</h2><p>${data.message}</p><p><b>Username:</b> ${data.username}</p><p><b>Password:</b> ${data.password}</p><p><b>Password QR:</b><br><img src='${data.password_qr_code}' style='max-width:100%;height:auto;' /></p><p><b>2FA QR:</b><br><img src='${data["2fa_qr_code"]}' style='max-width:100%;height:auto;' /></p><div class='footer'>Service provided by COFREPA Cloud</div></div>`;
            } else {
                alert(data.message);
            }
        })
        .catch(() => alert('An error occurred. Please try again.'));
    }
    </script>
</body>
</html>
'''

def handle(data):
    try:
        # Check if the request is for the admin users route
        if request.path == '/admin/users':
            return admin_view_users()

        # Default behavior for account creation
        req = json.loads(data) if data else {}
        if not req or "username" not in req or not req["username"].strip():
            return TEMPLATE_FORM, 200, {'Content-Type': 'text/html'}

        username = req["username"].strip()
        password = generate_secure_password()

        # Generate QR codes
        password_qr_code = generate_qr_code_base64(f"Password: {password}")
        secret = pyotp.random_base32()
        totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(username, issuer_name="COFREPA")
        twofa_qr_code = generate_qr_code_base64(totp_uri)

        # 1. Verifier si l'utilisateur existe dejà (bonne pratique)
        with psycopg2.connect(host=DB_HOST, database=DB_NAME, user=DB_USER, password=DB_PASSWORD) as conn:
            with conn.cursor() as cur:
                # Always ensure the users table exists before querying or inserting
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS users (
                        id SERIAL PRIMARY KEY,
                        username VARCHAR(255) UNIQUE NOT NULL,
                        encrypted_password TEXT NOT NULL,
                        totp_secret TEXT NOT NULL,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        status VARCHAR(32) DEFAULT 'active',
                        expiration_time TIMESTAMP
                    );
                """)
                conn.commit()
                # Now check if the user exists
                cur.execute(sql.SQL("SELECT COUNT(*) FROM users WHERE username = %s"), [username])
                if cur.fetchone()[0] > 0:
                    return json.dumps({"status": "error", "message": f"User '{username}' already exists."}), 409
                # check if this user is expired as a simple check with expiration_time < datetime.now()
                cur.execute(sql.SQL("SELECT COUNT(*) FROM users WHERE username = %s AND expiration_time < NOW()"), [username])
                if cur.fetchone()[0] > 0:
                    # redirect to renew credentials
                    return json.dumps({"status": "expired", "message": "Your account has expired. Please renew your access.", "redirect": "/renew-credentials"}), 403

        # 3. Chiffrer le mot de passe (ATTENTION: Ceci n'est pas un HASH !)
        encrypted_password = cipher_suite.encrypt(password.encode()).decode()

        # 4. Stocker les informations de l'utilisateur dans PostgreSQL
        with psycopg2.connect(host=DB_HOST, database=DB_NAME, user=DB_USER, password=DB_PASSWORD) as conn:
            with conn.cursor() as cur:
                # Table already ensured above, just insert
                expiration_time = datetime.now() + timedelta(minutes=2)
                cur.execute(
                    sql.SQL("INSERT INTO users (username, encrypted_password, totp_secret, expiration_time) VALUES (%s, %s, %s, %s)"),
                    [username, encrypted_password, secret, expiration_time]
                )
                conn.commit()

        # 6. Retourner la reponse
        return json.dumps({
            "status": "success",
            "message": "Account successfully created.",
            "username": username,
            "password": password,
            "password_qr_code": f"data:image/png;base64,{password_qr_code}",
            "2fa_qr_code": f"data:image/png;base64,{twofa_qr_code}"
        }), 201

    except psycopg2.Error as db_error:
        print(f"Database error: {db_error}")
        return json.dumps({"status": "error", "message": f"Database error: {str(db_error)}"}), 500

def admin_view_users():
    try:
        with psycopg2.connect(host=DB_HOST, database=DB_NAME, user=DB_USER, password=DB_PASSWORD) as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT username, status, expiration_time FROM users")
                users = cur.fetchall()
                if not users:
                    return json.dumps({"status": "success", "users": [], "message": "No users found."}), 200, {'Content-Type': 'application/json'}
                user_list = [
                    {"username": row[0], "status": row[1], "expiration_time": row[2].strftime('%Y-%m-%d %H:%M:%S') if row[2] else None}
                    for row in users
                ]
                table_rows = ''.join(
                    f'<tr><td>{user["username"]}</td><td>{user["status"] or "N/A"}</td><td>{user["expiration_time"] or "N/A"}</td></tr>'
                    for user in user_list
                )
                html = f"""
                <html>
                <head>
                    <title>Admin View - Users</title>
                    <style>
                        body {{ font-family: Arial, sans-serif; background: #f4f4f4; }}
                        .container {{ max-width: 800px; margin: 40px auto; background: #fff; padding: 20px; border-radius: 8px; box-shadow: 0 2px 8px #ccc; }}
                        h2 {{ text-align: center; color: #2c3e50; }}
                        table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
                        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                        th {{ background-color: #2980b9; color: white; }}
                        tr:nth-child(even) {{ background-color: #f2f2f2; }}
                        tr:hover {{ background-color: #ddd; }}
                    </style>
                </head>
                <body>
                    <div class="container">
                        <h2>Admin View - Users</h2>
                        <table>
                            <thead>
                                <tr>
                                    <th>Username</th>
                                    <th>Status</th>
                                    <th>Expiration Time</th>
                                </tr>
                            </thead>
                            <tbody>
                                {table_rows}
                            </tbody>
                        </table>
                    </div>
                </body>
                </html>
                """
                return html, 200, {'Content-Type': 'text/html'}
    except psycopg2.Error as e:
        return json.dumps({"status": "error", "message": f"Database error: {str(e)}"}), 500, {'Content-Type': 'application/json'}
    except Exception as e:
        return json.dumps({"status": "error", "message": f"An unexpected error occurred: {str(e)}"}), 500, {'Content-Type': 'application/json'}