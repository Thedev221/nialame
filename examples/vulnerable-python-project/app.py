"""Petit projet Python volontairement vulnérable, utilisé pour démontrer
la détection Tier 1 de Nialame AI. Ne jamais utiliser ce code en production.
"""
import os
import pickle

import sqlite3


def get_user(conn: sqlite3.Connection, user_id: str):
    # NIA-SQLI-001 attendu : concaténation dans une requête SQL.
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return conn.execute(query).fetchone()


def run_backup_command(target_dir: str):
    # NIA-CMD-001 attendu : exécution shell non sûre.
    os.system(f"tar -czf backup.tar.gz {target_dir}")


def load_cached_session(raw_bytes: bytes):
    # NIA-DESER-001 attendu : désérialisation non sûre.
    return pickle.loads(raw_bytes)


def evaluate_user_formula(formula: str):
    # NIA-EVAL-001 attendu : eval sur une entrée utilisateur.
    return eval(formula)
