import sqlite3
import os

# تحديد مسار قاعدة البيانات (تأكد إنه صح)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
# افترضنا إن القاعدة بره مجلد app بخطوة زي ما الكود بتاعك بيقول
DB_PATH = os.path.join(BASE_DIR, "../vscan_analytics.db")

try:
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    print(f"🔌 Connected to database at: {DB_PATH}")
    
    # إضافة عمود user_id لجدول scan_history
    try:
        cursor.execute("ALTER TABLE scan_history ADD COLUMN user_id INTEGER REFERENCES users(id)")
        print("✅ Added 'user_id' column to 'scan_history' table.")
    except sqlite3.OperationalError as e:
        print(f"ℹ️ Note: {e} (Maybe column already exists)")

    conn.commit()
    conn.close()
    print("🚀 Database fixed successfully!")

except Exception as e:
    print(f"❌ Error: {e}")
