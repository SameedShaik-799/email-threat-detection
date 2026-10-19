import sqlite3
import pandas as pd

def display_database():
    conn = sqlite3.connect('threats.db')
    
    print("\n" + "="*80)
    print("       THREATSCAN AI - SQLITE AUDIT DATABASE (threats.db)")
    print("="*80)
    
    # 1. Total statistics
    total = conn.execute("SELECT COUNT(*) FROM scan_logs").fetchone()[0]
    print(f"\n[+] Total Emails Logged in Database: {total}")
    
    # 2. Class breakdown
    breakdown = conn.execute("SELECT predicted_threat, COUNT(*) FROM scan_logs GROUP BY predicted_threat").fetchall()
    print("\n[+] Breakdown by Threat Category:")
    for threat, count in breakdown:
        print(f"    - {threat:<10}: {count} records")
        
    # 3. Recent 10 Records
    print("\n[+] Latest 10 Database Records (Table: scan_logs):")
    print("-" * 80)
    df = pd.read_sql_query("SELECT id, timestamp, substr(subject, 1, 28) as subject, sender_domain, predicted_threat, round(confidence, 1) as conf_pct, url_count, has_attachment FROM scan_logs ORDER BY id DESC LIMIT 10", conn)
    df['subject'] = df['subject'].apply(lambda s: s.encode('ascii', errors='replace').decode('ascii') if isinstance(s, str) else s)
    print(df.to_string(index=False))
    print("="*80 + "\n")
    
    conn.close()

if __name__ == '__main__':
    display_database()
