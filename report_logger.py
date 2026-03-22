import sqlite3
from datetime import datetime
import os

DB_PATH = 'data/reports.db'

def init_db():
    """Create database and table if not exists"""
    os.makedirs('data', exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS phishing_reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            confidence REAL NOT NULL,
            timestamp TEXT NOT NULL,
            user_email TEXT
        )
    ''')
    conn.commit()
    conn.close()

def log_report(url, confidence, user_email=None):
    """Log a flagged phishing URL"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO phishing_reports (url, confidence, timestamp, user_email)
        VALUES (?, ?, ?, ?)
    ''', (url, confidence, datetime.now().strftime('%Y-%m-%d %H:%M:%S'), user_email))
    conn.commit()
    conn.close()

def get_all_reports():
    """Fetch all reports for admin dashboard"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM phishing_reports ORDER BY timestamp DESC')
    rows = cursor.fetchall()
    conn.close()
    return rows

def get_report_count():
    """Total number of phishing URLs detected"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT COUNT(*) FROM phishing_reports')
    count = cursor.fetchone()[0]
    conn.close()
    return count