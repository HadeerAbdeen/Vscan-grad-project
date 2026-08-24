from app.database import init_db
import os

print("🔄 Initializing Database...")
try:
    init_db()
    print(f"✅ Database created successfully at: {os.getcwd()}/vscan_analytics.db")
except Exception as e:
    print(f"❌ Error: {e}")
