import sqlite3
import json
import logging
import os
import shutil
from typing import List, Dict
from models import VulnerabilityIntelligence

IS_VERCEL = bool(os.environ.get("VERCEL"))
BUNDLED_DB = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vuln_intel.db")
# On Vercel only /tmp is writable. The bundled database is copied there once per instance as a starting point.
DB_NAME = os.environ.get("DB_PATH", "/tmp/vuln_intel.db" if IS_VERCEL else "vuln_intel.db")

def init_db():
    try:
        if IS_VERCEL and not os.path.exists(DB_NAME) and os.path.exists(BUNDLED_DB):
            shutil.copyfile(BUNDLED_DB, DB_NAME)
        with sqlite3.connect(DB_NAME) as conn:
            conn.execute('''CREATE TABLE IF NOT EXISTS visited_urls (
                            url TEXT PRIMARY KEY,
                            pub_date TEXT
                        )''')
            conn.execute('''CREATE TABLE IF NOT EXISTS vulnerabilities (
                            cve_id TEXT PRIMARY KEY,
                            data TEXT
                        )''')
    except Exception as e:
        logging.error(f"Database initialization failed: {e}")

def is_visited(url: str) -> bool:
    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.execute("SELECT 1 FROM visited_urls WHERE url = ?", (url,))
        return cursor.fetchone() is not None

def mark_visited(url: str, pub_date: str):
    with sqlite3.connect(DB_NAME) as conn:
        conn.execute("INSERT OR REPLACE INTO visited_urls (url, pub_date) VALUES (?, ?)", (url, pub_date))

def save_vulnerability(intel: VulnerabilityIntelligence):
    cve_id = intel.vulnerability_summary.cve_id
    if not cve_id or cve_id == "UNKNOWN":
        return
    with sqlite3.connect(DB_NAME) as conn:
        conn.execute("INSERT OR REPLACE INTO vulnerabilities (cve_id, data) VALUES (?, ?)", 
                     (cve_id, intel.model_dump_json()))

def get_all_vulnerabilities() -> List[Dict]:
    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.execute("SELECT data FROM vulnerabilities ORDER BY rowid DESC")
        return [json.loads(row[0]) for row in cursor.fetchall()]