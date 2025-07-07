import base64
import os
import json
from datetime import datetime, timedelta
from cryptography.fernet import Fernet
import pyotp
import qrcode
from io import BytesIO
import psycopg2
from psycopg2 import sql

def load_renew_form():
    with open(os.path.join(os.path.dirname(__file__), 'renew_form.html'), encoding='utf-8') as f:
        return f.read()

# --- Configuration et Initialisation (via ENV uniquement, pas de secrets OpenFaaS) ---
ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY", "qndx3Dv5HwpBO1CYytW7SNQe19qjMDJvN2nXMB9Dhaw=").encode()
cipher_suite = Fernet(ENCRYPTION_KEY)

DB_HOST = os.getenv("DB_HOST", "postgresql.database.svc.cluster.local")
DB_NAME = os.getenv("DB_NAME", "your_database_name")
DB_USER = os.getenv("DB_USER", "user")
DB_PASSWORD = os.getenv("DB_PASSWORD", "votreMotDePasseFort")

MAX_CREDENTIAL_AGE = timedelta(days=180)  # 6 mois

# Generation QR code
def generate_qr_code_base64(data):
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

def handle(data):
    try:
        from flask import request
        
        # If GET request and we have a username parameter, show form with prefilled username
        if request.method == 'GET' and request.args.get('username'):
            username = request.args.get('username')
            html = load_renew_form()
            html = html.replace('<input type="text" id="username" name="username" required />', 
                              f'<input type="text" id="username" name="username" value="{username}" required />')
            return html, 200, {'Content-Type': 'text/html'}
            
        # If no data, return the empty form
        req = json.loads(data) if data else {}
        username = req.get("username", "").strip()
        if not username:
            return load_renew_form(), 200, {'Content-Type': 'text/html'}
        with psycopg2.connect(host=DB_HOST, database=DB_NAME, user=DB_USER, password=DB_PASSWORD) as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT id, created_at, expiration_time FROM users WHERE username = %s
                """, [username])
                row = cur.fetchone()
                if not row:
                    return json.dumps({"status": "error", "message": "Utilisateur inconnu. (COFREPA Cloud)"}), 404
                user_id, created_at, expiration_time = row
                # Verification expiration
                if created_at is None or expiration_time > datetime.now():
                    return json.dumps({"status": "error", "message": "Les credentials ne sont pas expires. (COFREPA Cloud)"}), 400
                # Générer nouveaux credentials
                new_password = ''.join(pyotp.random_base32()[:24])
                new_encrypted_password = cipher_suite.encrypt(new_password.encode()).decode()
                new_totp_secret = pyotp.random_base32()
                new_totp_uri = pyotp.totp.TOTP(new_totp_secret).provisioning_uri(
                    name=username,
                    issuer_name="COFRAPCloud"
                )
                # Mettre à jour l'utilisateur
                cur.execute("""
                    UPDATE users SET encrypted_password=%s, totp_secret=%s, created_at=NOW(), expiration_time= NOW() + INTERVAL '2 minutes', status='active' WHERE id=%s
                """, [new_encrypted_password, new_totp_secret, user_id])
                conn.commit()
                # Générer QR codes
                password_qr_b64 = generate_qr_code_base64(new_password)
                totp_qr_b64 = generate_qr_code_base64(new_totp_uri)
        return json.dumps({
            "status": "success",
            "message": "Credentials renouvelés avec succès. Veuillez scanner les nouveaux QR codes pour votre mot de passe et 2FA. (COFREPA Cloud)",
            "username": username,
            "password": new_password,  # Add the actual password
            "password_qr_code": f"data:image/png;base64,{password_qr_b64}",
            "2fa_qr_code": f"data:image/png;base64,{totp_qr_b64}"
        }), 200
    except Exception as e:
        return json.dumps({"status": "error", "message": f"Erreur inattendue: {str(e)} (COFREPA Cloud)"}), 500
