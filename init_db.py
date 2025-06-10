import sqlite3

conn = sqlite3.connect('certificates.db')
cursor = conn.cursor()

# جدول المستخدمين
cursor.execute("""
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    phone TEXT
)
""")

# جدول الشهادات
cursor.execute("""
CREATE TABLE IF NOT EXISTS certificates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cert_id TEXT UNIQUE,
    subject TEXT NOT NULL,
    issuer TEXT NOT NULL,
    serial_number TEXT NOT NULL,
    valid_from TEXT NOT NULL,
    valid_to TEXT NOT NULL,
    public_key TEXT,
    pem TEXT NOT NULL
)
""")

# التحقق من الأعمدة الإضافية
cursor.execute("PRAGMA table_info(certificates)")
columns = [col[1] for col in cursor.fetchall()]

# إضافة user_email
if 'user_email' not in columns:
    cursor.execute("ALTER TABLE certificates ADD COLUMN user_email TEXT")
    print("✅ تمت إضافة user_email.")
else:
    print("ℹ️ user_email موجود.")

# ✅ إضافة is_revoked (موجود عندك، لكن نتحقق فقط)
if 'is_revoked' not in columns:
    cursor.execute("ALTER TABLE certificates ADD COLUMN is_revoked INTEGER DEFAULT 0")
    print("✅ تمت إضافة is_revoked.")
else:
    print("ℹ️ is_revoked موجود.")

# ✅ إضافة status فقط (جديد) مع الإبقاء على is_revoked
if 'status' not in columns:
    cursor.execute("ALTER TABLE certificates ADD COLUMN status TEXT DEFAULT 'valid'")
    print("✅ تمت إضافة status.")
else:
    print("ℹ️ status موجود.")

conn.commit()
conn.close()
print("✅ تم تحديث قاعدة البيانات.")
