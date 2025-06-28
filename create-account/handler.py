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

# --- Helper to read OpenFaaS secrets ---
def read_secret(secret_name, default=None):
    secret_path = f"/var/openfaas/secrets/{secret_name}"
    try:
        with open(secret_path, "r") as f:
            return f.read().strip()
    except FileNotFoundError:
        return os.getenv(secret_name.upper(), default)

# --- Configuration et Initialisation (via Secrets Kubernetes) ---
ENCRYPTION_KEY = read_secret("encryption_key", "qndx3Dv5HwpBO1CYytW7SNQe19qjMDJvN2nXMB9Dhaw=").encode()
cipher_suite = Fernet(ENCRYPTION_KEY)

DB_HOST = read_secret("db_host", "postgresql.database.svc.cluster.local")
DB_NAME = read_secret("db_name", "your_database_name")
DB_USER = read_secret("db_user", "user")
DB_PASSWORD = read_secret("db_password", "votreMotDePasseFort")

# --- Fonctions utilitaires ---

def generate_secure_password(length=24):
    """Génère un mot de passe sécurisé."""
    characters = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(secrets.choice(characters) for i in range(length))
    return password

def generate_qr_code_base64(data):
    """Génère un QR code à partir des données et le retourne en base64."""
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
                document.body.innerHTML = `<div class='container'><h2>Account Created</h2><p>${data.message}</p><p><b>Username:</b> ${data.username}</p><p><b>Password QR:</b><br><img src='${data.password_qr_code}' /></p><p><b>2FA QR:</b><br><img src='${data["2fa_qr_code"]}' /></p><div class='footer'>Service provided by COFREPA Cloud</div></div>`;
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
        req = json.loads(data) if data else {}
        # If no username, return an HTML form for user input
        if not req or "username" not in req or not req["username"].strip():
            return TEMPLATE_FORM, 200, {'Content-Type': 'text/html'}
        username = req["username"].strip()

        # 1. Vérifier si l'utilisateur existe déjà (bonne pratique)
        with psycopg2.connect(host=DB_HOST, database=DB_NAME, user=DB_USER, password=DB_PASSWORD) as conn:
            with conn.cursor() as cur:
                # Always ensure the users table exists before querying or inserting
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS users (
                        id SERIAL PRIMARY KEY,
                        username VARCHAR(255) UNIQUE NOT NULL,
                        encrypted_password TEXT NOT NULL,
                        totp_secret TEXT NOT NULL,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    );
                """)
                conn.commit()
                # Now check if the user exists
                cur.execute(sql.SQL("SELECT COUNT(*) FROM users WHERE username = %s"), [username])
                if cur.fetchone()[0] > 0:
                    return json.dumps({"status": "error", "message": f"User '{username}' already exists."}), 409

        # 2. Générer le mot de passe sécurisé et le secret 2FA
        generated_password = generate_secure_password()
        # Clé secrète pour le TOTP. Label pour l'application TOTP (ex: Google Authenticator)
        # Format: otpauth://totp/Label:user@domain?secret=SECRET&issuer=IssuerName
        totp_secret = pyotp.random_base32()
        totp_uri = pyotp.totp.TOTP(totp_secret).provisioning_uri(
            name=username,
            issuer_name="COFRAPCloud"
        )

        # 3. Chiffrer le mot de passe (ATTENTION: Ceci n'est pas un HASH !)
        encrypted_password = cipher_suite.encrypt(generated_password.encode()).decode()

        # 4. Stocker les informations de l'utilisateur dans PostgreSQL
        with psycopg2.connect(host=DB_HOST, database=DB_NAME, user=DB_USER, password=DB_PASSWORD) as conn:
            with conn.cursor() as cur:
                # Table already ensured above, just insert
                cur.execute(
                    sql.SQL("INSERT INTO users (username, encrypted_password, totp_secret) VALUES (%s, %s, %s)"),
                    [username, encrypted_password, totp_secret]
                )
                conn.commit()

        # 5. Générer les QR codes
        # Le QR code du mot de passe peut être une simple chaîne de texte
        password_qr_b64 = generate_qr_code_base64(generated_password)
        # Le QR code 2FA utilise l'URI de provisionnement
        totp_qr_b64 = generate_qr_code_base64(totp_uri)

        # 6. Retourner la réponse
        return json.dumps({
            "status": "success",
            "message": (
                "Account created successfully for user '{0}'. "
                "Please scan the QR codes to save your password and configure 2FA. "
                "Service powered by COFREPA Cloud."
            ).format(username),
            "username": username,
            "password_qr_code": f"data:image/png;base64,{password_qr_b64}",
            "2fa_qr_code": f"data:image/png;base64,{totp_qr_b64}"
        }), 201

    except psycopg2.Error as e:
        print(f"Database error: {e}")
        return json.dumps({"status": "error", "message": f"Database error: {str(e)} (COFREPA Cloud)"}), 500
    except Exception as e:
        print(f"Unhandled error: {e}")
        return json.dumps({"status": "error", "message": f"An unexpected error occurred: {str(e)} (COFREPA Cloud)"}), 500
