import os
import json
from datetime import datetime, timedelta
from cryptography.fernet import Fernet
import pyotp
import psycopg2
from psycopg2 import sql
from flask import request  # Import Flask request object

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

MAX_CREDENTIAL_AGE = timedelta(minutes=2)  # 6 mois

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
        # Username-only phase
        if username and not password and not code_2fa:
            with psycopg2.connect(host=DB_HOST, database=DB_NAME, user=DB_USER, password=DB_PASSWORD) as conn:
                with conn.cursor() as cur:
                    # Check if user exists and get their status and expiration time
                    cur.execute("SELECT id, status, expiration_time FROM users WHERE username = %s", [username])
                    user = cur.fetchone()
                    if not user:
                        return json.dumps({"status": "error", "message": "Utilisateur inconnu. (COFREPA Cloud)"}), 401
                    
                    # Check if user is expired
                    user_id, status, expiration_time = user
                    if status == "expired" or (expiration_time and expiration_time < datetime.now()):
                        # Update status to expired if not already
                        cur.execute("UPDATE users SET status='expired' WHERE id=%s", [user_id])
                        conn.commit()
                        return json.dumps({
                            "status": "expired",
                            "message": "Vos identifiants ont expiré. Veuillez renouveler vos identifiants. (COFREPA Cloud)",
                            "redirect": "/function/renew-credentials"
                        }), 403
            return json.dumps({"status": "need_password", "message": "Veuillez entrer votre mot de passe et code 2FA."}), 200
        # Authentification complète
        if not username or not password or not code_2fa:
            return json.dumps({"status": "error", "message": "Veuillez fournir username, password et code_2FA. (COFREPA Cloud)"}), 400
        with psycopg2.connect(host=DB_HOST, database=DB_NAME, user=DB_USER, password=DB_PASSWORD) as conn:
            with conn.cursor() as cur:
                # First check if user exists and get their status
                cur.execute("SELECT id, encrypted_password, totp_secret, status, expiration_time FROM users WHERE username = %s", [username])
                user = cur.fetchone()
                
                if not user:
                    return json.dumps({"status": "error", "message": "Utilisateur inconnu. (COFREPA Cloud)"}), 401

                user_id, encrypted_password, totp_secret, status, expiration_time = user

                # Check if user is expired
                if status == "expired" or (expiration_time < datetime.now()):
                    # Update status to expired if not already
                    cur.execute("UPDATE users SET status='expired' WHERE id=%s", [user_id])
                    conn.commit()
                    headers = {
                        'Content-Type': 'application/json',
                        'Location': '/function/renew-credentials'
                    }
                    return json.dumps({
                        "status": "expired",
                        "message": "Vos identifiants ont expiré. Veuillez renouveler vos identifiants. (COFREPA Cloud)",
                        "redirect": "/function/renew-credentials"
                    }), 307, headers  # Using 307 Temporary Redirect to maintain the POST method

                # Only proceed with password check if we have password in request
                if password:
                    try:
                        decrypted_password = cipher_suite.decrypt(encrypted_password.encode()).decode()
                        if password != decrypted_password:
                            return json.dumps({"status": "error", "message": "Mot de passe incorrect. (COFREPA Cloud)"}), 401

                        # Verify 2FA
                        totp = pyotp.TOTP(totp_secret)
                        if not totp.verify(code_2fa):
                            return json.dumps({"status": "error", "message": "Code 2FA invalide. (COFREPA Cloud)"}), 401

                        return json.dumps({
                            "status": "success",
                            "message": "Authentification réussie. (COFREPA Cloud)"
                        }), 200

                    except Exception as e:
                        return json.dumps({"status": "error", "message": "Erreur de déchiffrement. (COFREPA Cloud)"}), 500
                else:
                    return json.dumps({"status": "need_password", "message": "Veuillez fournir votre mot de passe et le code 2FA."}), 200

    except Exception as e:
        return json.dumps({"status": "error", "message": f"Erreur inattendue: {str(e)} (COFREPA Cloud)"}), 500
