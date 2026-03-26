import sqlite3
import json
import logging
from typing import List, Dict
from models import VulnerabilityIntelligence

DB_NAME = "vuln_intel.db"

def init_db():
    try:
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