import os
import json
from datetime import datetime, timedelta
from cryptography.fernet import Fernet
import pyotp
import psycopg2
from psycopg2 import sql

# Charger le template HTML externe
def load_auth_form():
    with open(os.path.join(os.path.dirname(__file__), 'auth_form.html'), encoding='utf-8') as f:
        return f.read()

# --- Configuration et Initialisation (via ENV uniquement, pas de secrets OpenFaaS) ---
ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY", "qndx3Dv5HwpBO1CYytW7SNQe19qjMDJvN2nXMB9Dhaw=").encode()
cipher_suite = Fernet(ENCRYPTION_KEY)

DB_HOST = os.getenv("DB_HOST", "postgresql.database.svc.cluster.local")
DB_NAME = os.getenv("DB_NAME", "your_database_name")
DB_USER = os.getenv("DB_USER", "user")
DB_PASSWORD = os.getenv("DB_PASSWORD", "votreMotDePasseFort")

MAX_CREDENTIAL_AGE = timedelta(days=180)  # 6 mois

# --- Fonction principale ---
def handle(data):
    try:
        req = json.loads(data) if data else {}
        username = req.get("username", "").strip()
        password = req.get("password", "").strip()
        code_2fa = req.get("code_2fa", "").strip()
        # Si aucun champ n'est fourni, afficher le formulaire HTML
        if not username and not password and not code_2fa:
            return load_auth_form(), 200, {'Content-Type': 'text/html'}
        # Si username fourni mais pas les autres, demander la suite
        if username and not password and not code_2fa:
            # Verifier existence utilisateur
            with psycopg2.connect(host=DB_HOST, database=DB_NAME, user=DB_USER, password=DB_PASSWORD) as conn:
                with conn.cursor() as cur:
                    cur.execute("SELECT 1 FROM users WHERE username = %s", [username])
                    if not cur.fetchone():
                        return json.dumps({"status": "error", "message": "Utilisateur inconnu. (COFREPA Cloud)"}), 401
            return json.dumps({"status": "need_password", "message": "Veuillez entrer votre mot de passe et code 2FA."}), 200
        # Authentification complète
        if not username or not password or not code_2fa:
            return json.dumps({"status": "error", "message": "Veuillez fournir username, password et code_2FA. (COFREPA Cloud)"}), 400
        with psycopg2.connect(host=DB_HOST, database=DB_NAME, user=DB_USER, password=DB_PASSWORD) as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT encrypted_password, totp_secret, created_at FROM users WHERE username = %s
                """, [username])
                row = cur.fetchone()
                if not row:
                    return json.dumps({"status": "error", "message": "Utilisateur inconnu. (COFREPA Cloud)"}), 401
                encrypted_password, totp_secret, created_at = row
                # Verification expiration
                if created_at is None or (datetime.utcnow() - created_at) > MAX_CREDENTIAL_AGE:
                    return json.dumps({
                        "status": "expired",
                        "message": "Credentials expires. Redirection vers renouvellement. (COFREPA Cloud)",
                        "redirect": "/renew-password"
                    }), 403
                # Verification mot de passe
                try:
                    decrypted_password = cipher_suite.decrypt(encrypted_password.encode()).decode()
                except Exception:
                    return json.dumps({"status": "error", "message": "Erreur de dechiffrement. (COFREPA Cloud)"}), 401
                if password != decrypted_password:
                    return json.dumps({"status": "error", "message": "Mot de passe incorrect. (COFREPA Cloud)"}), 401
                # Verification 2FA
                totp = pyotp.TOTP(totp_secret)
                if not totp.verify(code_2fa):
                    return json.dumps({"status": "error", "message": "Code 2FA invalide. (COFREPA Cloud)"}), 401
        return json.dumps({"status": "success", "message": "Authentification reussie. (COFREPA Cloud)"}), 200
    except Exception as e:
        return json.dumps({"status": "error", "message": f"Erreur inattendue: {str(e)} (COFREPA Cloud)"}), 500
