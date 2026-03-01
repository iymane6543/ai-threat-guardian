import sqlite3
from datetime import datetime

def init_db():
    conn = sqlite3.connect('threatguardian.db')
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS analyses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            src_bytes REAL,
            dst_bytes REAL,
            count REAL,
            serror_rate REAL,
            is_threat INTEGER,
            severity TEXT,
            score REAL
        )
    ''')
    conn.commit()
    conn.close()

def save_analysis(src_bytes, dst_bytes, count, serror_rate, is_threat, severity, score):
    conn = sqlite3.connect('threatguardian.db')
    c = conn.cursor()
    c.execute('''
        INSERT INTO analyses 
        (timestamp, src_bytes, dst_bytes, count, serror_rate, is_threat, severity, score)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        src_bytes, dst_bytes, count, serror_rate,
        1 if is_threat else 0,
        severity, score
    ))
    conn.commit()
    conn.close()

def get_all_analyses():
    conn = sqlite3.connect('threatguardian.db')
    c = conn.cursor()
    c.execute('SELECT * FROM analyses ORDER BY id DESC LIMIT 50')
    rows = c.fetchall()
    conn.close()
    return rows

def get_stats():
    conn = sqlite3.connect('threatguardian.db')
    c = conn.cursor()
    c.execute('SELECT COUNT(*) FROM analyses')
    total = c.fetchone()[0]
    c.execute('SELECT COUNT(*) FROM analyses WHERE is_threat = 1')
    attaques = c.fetchone()[0]
    conn.close()
    return {
        "total": total,
        "attaques": attaques,
        "normaux": total - attaques
    }