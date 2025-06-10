import sqlite3

# فتح الاتصال بقاعدة البيانات
conn = sqlite3.connect('pki.db')
cursor = conn.cursor()

# تنفيذ استعلام SELECT
cursor.execute("SELECT id, subject, issuer, serial_number, valid_from, valid_to FROM certificates")

# جلب كل النتائج
certs = cursor.fetchall()

# عرض النتائج
for cert in certs:
    print("ID:", cert[0])
    print("Subject:", cert[1])
    print("Issuer:", cert[2])
    print("Serial Number:", cert[3])
    print("Valid From:", cert[4])
    print("Valid To:", cert[5])
    print("-" * 40)

# إغلاق الاتصال
conn.close()
