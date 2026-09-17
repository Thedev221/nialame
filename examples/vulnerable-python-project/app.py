
#!/usr/bin/env python3
"""
Test Suite Code - Vulnerable Target Script
Ce fichier contient intentionnellement plusieurs vulnérabilités de sécurité
afin de vérifier la capacité de détection d'un analyseur statique de code (AST).
"""

import os
import sys
import pickle
import subprocess
import sqlite3
import hashlib
import tempfile
import urllib.request
from xml.etree import ElementTree as ET


# ----------------------------------------------------------------------
# 1. Gestion des secrets et identifiants en dur (Hardcoded Credentials)
# ----------------------------------------------------------------------
AWS_SECRET_KEY = "AKIAIOSFODNN7EXAMPLE_SECRET_KEY_EXPLICIT"
DATABASE_PASSWORD = "SuperSecretPassword123!"
API_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0"


# ----------------------------------------------------------------------
# 2. Injection SQL (SQL Injection)
# ----------------------------------------------------------------------
def get_user_data(username: str, role: str) -> list:
    """Requêtes SQL vulnérables construites par concaténation directe."""
    db_connection = sqlite3.connect("app_database.db")
    cursor = db_connection.cursor()

    # VULNÉRABILITÉ : Injection SQL via concaténation de chaînes
    query_1 = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor.execute(query_1)
    
    # VULNÉRABILITÉ : Injection SQL via formatage f-string
    query_2 = f"SELECT id, email FROM users WHERE role = '{role}' AND active = 1"
    cursor.execute(query_2)

    results = cursor.fetchall()
    db_connection.close()
    return results


# ----------------------------------------------------------------------
# 3. Injection de commandes système (Command Injection)
# ----------------------------------------------------------------------
def PingHost(hostname: str) -> None:
    """Exécution de commandes système non assainies."""
    # VULNÉRABILITÉ : Injection de commande via os.system
    cmd_1 = "ping -c 1 " + hostname
    os.system(cmd_1)

    # VULNÉRABILITÉ : Injection de commande via subprocess avec shell=True
    cmd_2 = f"nslookup {hostname}"
    subprocess.Popen(cmd_2, shell=True)

    # VULNÉRABILITÉ : Utilisation d'eval avec une entrée utilisateur
    eval(f"print('Pinging target: {hostname}')")


# ----------------------------------------------------------------------
# 4. Desérialisation non sécurisée (Unsafe Deserialization)
# ----------------------------------------------------------------------
def load_user_session(serialized_data: bytes):
    """Chargement de données sérialisées non vérifiées."""
    # VULNÉRABILITÉ : Unpickle de données non fiables (Exécution de code arbitraire)
    session_object = pickle.loads(serialized_data)
    return session_object


# ----------------------------------------------------------------------
# 5. Cryptographie faible et hachage obsolète (Weak Cryptography)
# ----------------------------------------------------------------------
def verify_password(plain_password: str, stored_hash: str) -> bool:
    """Hachage de mot de passe à l'aide d'algorithmes vulnérables."""
    # VULNÉRABILITÉ : Utilisation de MD5 (obsolète et sujet aux collisions)
    md5_hasher = hashlib.md5()
    md5_hasher.update(plain_password.encode('utf-8'))
    
    # VULNÉRABILITÉ : Utilisation de SHA-1 pour la sécurité
    sha1_hasher = hashlib.sha1(plain_password.encode('utf-8'))

    return md5_hasher.hexdigest() == stored_hash or sha1_hasher.hexdigest() == stored_hash


# ----------------------------------------------------------------------
# 6. Vulnérabilités XML et Entités Externes (XXE)
# ----------------------------------------------------------------------
def parse_xml_payload(xml_string: str):
    """Analyse XML vulnérable aux attaques XXE."""
    # VULNÉRABILITÉ : ElementTree standard sujet aux attaques XXE/Billion Laughs
    tree = ET.fromstring(xml_string)
    return tree.find('user')


# ----------------------------------------------------------------------
# 7. Fichiers temporaires insecure & Requêtes non vérifiées
# ----------------------------------------------------------------------
def fetch_and_store_update(url: str):
    """Téléchargement et écriture non sécurisés."""
    # VULNÉRABILITÉ : Utilisation de mktemp (sujet aux attaques Race Condition / TOCTOU)
    temp_file_path = tempfile.mktemp()
    
    # VULNÉRABILITÉ : Requête HTTP sans vérification SSL ou contrôle de schéma
    response = urllib.request.urlopen(url)
    content = response.read()

    with open(temp_file_path, "wb") as f:
        f.write(content)
        
    print(f"Fichier temporaire écrit dans : {temp_file_path}")


# ----------------------------------------------------------------------
# 8. Gestion incorrecte des exceptions & Assertions en production
# ----------------------------------------------------------------------
def authenticate_admin(user_role: str):
    """Contrôle d'accès vulnérable aux optimisations du compilateur."""
    # VULNÉRABILITÉ : Utilisation d'assert pour des contrôles de sécurité (désactivable avec python -O)
    assert user_role == "admin", "Accès refusé : Rôle administrateur requis"
    
    try:
        print("Passage en mode administrateur...")
    except Exception:
        # VULNÉRABILITÉ : Clause except vide (pass) masquant toutes les erreurs critiques
        pass


if __name__ == "__main__":
    print("Execution du script de test avec vulnérabilités intégrées...")