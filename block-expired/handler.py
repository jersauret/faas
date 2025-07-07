import os
import json
from datetime import datetime, timedelta
from cryptography.fernet import Fernet
import psycopg2
from psycopg2 import sql

def load_block_form():
    with open(os.path.join(os.path.dirname(__file__), 'block_form.html'), encoding='utf-8') as f:
        return f.read()

# Audit log helper
def log_audit(username, event, status, db_conn):
    with db_conn.cursor() as cur:
        cur.execute("""
            CREATE TABLE IF NOT EXISTS audit_log (
                id SERIAL PRIMARY KEY,
                username VARCHAR(255),
                event VARCHAR(255),
                status VARCHAR(32),
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)
        db_conn.commit()
        cur.execute(
            "INSERT INTO audit_log (username, event, status) VALUES (%s, %s, %s)",
            [username, event, status]
        )
        db_conn.commit()

# --- Configuration et Initialisation (via ENV uniquement, pas de secrets OpenFaaS) ---
ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY", "qndx3Dv5HwpBO1CYytW7SNQe19qjMDJvN2nXMB9Dhaw=").encode()
cipher_suite = Fernet(ENCRYPTION_KEY)

DB_HOST = os.getenv("DB_HOST", "postgresql.database.svc.cluster.local")
DB_NAME = os.getenv("DB_NAME", "your_database_name")
DB_USER = os.getenv("DB_USER", "user")
DB_PASSWORD = os.getenv("DB_PASSWORD", "votreMotDePasseFort")

MAX_CREDENTIAL_AGE = timedelta(days=180)  # 6 mois

def handle(data):
    try:
        req = json.loads(data) if data else {}
        username = req.get("username", "").strip()
        password = req.get("password", "").strip()
        code_2fa = req.get("code_2fa", "").strip()
        # Si aucun champ n'est fourni, afficher le formulaire HTML
        if not username and not password and not code_2fa:
            return load_block_form(), 200, {'Content-Type': 'text/html'}
        if not username or not password or not code_2fa:
            return json.dumps({"status": "error", "message": "Veuillez fournir username, password et code_2fa. (COFREPA Cloud)"}), 400
        with psycopg2.connect(host=DB_HOST, database=DB_NAME, user=DB_USER, password=DB_PASSWORD) as conn:
            with conn.cursor() as cur:
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
                cur.execute("SELECT id, encrypted_password, totp_secret, created_at, status, expiration_time FROM users WHERE username = %s", [username])
                row = cur.fetchone()
                if not row:
                    log_audit(username, "login_attempt", "user_not_found", conn)
                    return json.dumps({"status": "error", "message": "Utilisateur inconnu. (COFREPA Cloud)"}), 401
                user_id, encrypted_password, totp_secret, created_at, user_status, expiration_time = row
                # Blocage si status expired
                if user_status == "expired":
                    log_audit(username, "login_attempt", "account_expired_blocked", conn)
                    return json.dumps({"status": "expired", "message": "Compte bloque (credentials expires). Veuillez renouveler vos accès. (COFREPA Cloud)", "redirect": "/renew-credentials"}), 403
                # Verification expiration
                if created_at is None or (datetime.now() - created_at) > MAX_CREDENTIAL_AGE:
                    # Marquer le compte comme expire
                    cur.execute("UPDATE users SET status='expired' WHERE id=%s", [user_id])
                    conn.commit()
                    log_audit(username, "login_attempt", "account_expired_blocked", conn)
                    return json.dumps({"status": "expired", "message": "Compte bloque (credentials expires). Veuillez renouveler vos accès. (COFREPA Cloud)", "redirect": "/renew-credentials"}), 403
                # Check expiration time
                if expiration_time and expiration_time < datetime.now():
                    cur.execute("UPDATE users SET status='expired' WHERE id=%s", [user_id])
                    conn.commit()
                    log_audit(username, "login_attempt", "account_expired_blocked", conn)
                    return json.dumps({"status": "expired", "message": "Votre compte a expiré. Veuillez renouveler vos accès.", "redirect": "/renew-access"}), 403
                # Verification mot de passe
                try:
                    decrypted_password = cipher_suite.decrypt(encrypted_password.encode()).decode()
                except Exception:
                    log_audit(username, "login_attempt", "decrypt_error", conn)
                    return json.dumps({"status": "error", "message": "Erreur de dechiffrement. (COFREPA Cloud)"}), 401
                if password != decrypted_password:
                    log_audit(username, "login_attempt", "bad_password", conn)
                    return json.dumps({"status": "error", "message": "Mot de passe incorrect. (COFREPA Cloud)"}), 401
                # Verification 2FA
                import pyotp
                totp = pyotp.TOTP(totp_secret)
                if not totp.verify(code_2fa):
                    log_audit(username, "login_attempt", "bad_2fa", conn)
                    return json.dumps({"status": "error", "message": "Code 2FA invalide. (COFREPA Cloud)"}), 401
                log_audit(username, "login_attempt", "success", conn)
        return json.dumps({"status": "success", "message": "Authentification reussie. (COFREPA Cloud)"}), 200
    except Exception as e:
        return json.dumps({"status": "error", "message": f"Erreur inattendue: {str(e)} (COFREPA Cloud)"}), 500
