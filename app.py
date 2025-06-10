from flask import Flask, render_template, request, send_file, redirect, url_for, session
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509 import NameOID, CertificateSigningRequestBuilder
from cryptography import x509
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import io
import os
import sqlite3
from functools import wraps
from dotenv import load_dotenv
import uuid

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'your_secret_key_here')
storage = {}

# حماية الصفحات
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_email' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# تسجيل مستخدم جديد
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form['email']
        password = generate_password_hash(request.form['password'])
        phone = request.form['phone']

        conn = sqlite3.connect('certificates.db')
        cursor = conn.cursor()
        try:
            cursor.execute("INSERT INTO users (email, password, phone) VALUES (?, ?, ?)",
                           (email, password, phone))
            conn.commit()
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            return "❌ البريد الإلكتروني مُستعمل مسبقاً."
        finally:
            conn.close()
    return render_template('signup.html')

# تسجيل الدخول
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        conn = sqlite3.connect('certificates.db')
        cursor = conn.cursor()
        cursor.execute("SELECT password FROM users WHERE email = ?", (email,))
        row = cursor.fetchone()
        conn.close()

        if row and check_password_hash(row[0], password):
            session['user_email'] = email
            return redirect(url_for('generate_csr'))
        else:
            return "❌ البريد الإلكتروني أو كلمة المرور غير صحيحة."

    return render_template('login.html')

# تسجيل الخروج
@app.route('/logout')
def logout():
    session.pop('user_email', None)
    return redirect(url_for('login'))


# الصفحة الرئيسية: توليد المفتاح و CSR
@app.route('/', methods=['GET', 'POST'])
@login_required
def generate_csr():
    if request.method == 'POST':
        common_name = request.form['common_name']
        organization = request.form['organization']
        organizational_unit = request.form['organizational_unit']
        country = request.form['country']
        email = request.form['email']

        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        csr_builder = CertificateSigningRequestBuilder().subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, organizational_unit),
            x509.NameAttribute(NameOID.COUNTRY_NAME, country),
            x509.NameAttribute(NameOID.EMAIL_ADDRESS, email),
        ]))

        csr = csr_builder.sign(private_key, hashes.SHA256())

        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )

        csr_pem = csr.public_bytes(serialization.Encoding.PEM)

        storage['private_key'] = private_key_pem
        storage['csr'] = csr_pem

        return render_template('result.html',
                               private_key=private_key_pem.decode(),
                               csr=csr_pem.decode())
    return render_template('generate_csr.html')

# تحميل المفتاح الخاص
@app.route('/download/private_key')
@login_required
def download_private_key():
    if 'private_key' not in storage:
        return "No private key found.", 404
    return send_file(io.BytesIO(storage['private_key']),
                     mimetype='application/x-pem-file',
                     as_attachment=True,
                     download_name='private_key.pem')

# توقيع CSR وادخال الشهادة الموقعة في قاعدة البيانات
@app.route('/sign_csr', methods=['GET', 'POST'])
@login_required
def sign_csr():
    if request.method == 'POST':
        csr_file = request.files['csr_file']
        if not csr_file:
            return "⚠️ لم يتم تحميل ملف CSR", 400

        try:
            csr_data = csr_file.read()
            csr = x509.load_pem_x509_csr(csr_data)
        except Exception as e:
            return f"⚠️ Invalid CSR file: {e}", 400

        # Load CA key and certificate
        key_path = os.path.join("intermediate-ca", "private", "intermediate.key.pem")
        with open(key_path, "rb") as key_file:
            password = os.environ.get("CA_KEY_PASSWORD")
            if password:
                password = password.encode()  # خاصنا نحولو bytes
            ca_private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=password
            )
        with open("intermediate-ca/certs/intermediate.cert.pem", "rb") as cert_file:
            ca_cert = x509.load_pem_x509_certificate(cert_file.read())

        # Build signed certificate
        subject = csr.subject
        issuer = ca_cert.subject
        serial_number = x509.random_serial_number()
        valid_from = datetime.utcnow()
        valid_to = valid_from + timedelta(days=365)

        builder = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            csr.public_key()
        ).serial_number(
            serial_number
        ).not_valid_before(
            valid_from
        ).not_valid_after(
            valid_to
        )

        for extension in csr.extensions:
            builder = builder.add_extension(extension.value, extension.critical)

        signed_cert = builder.sign(private_key=ca_private_key, algorithm=hashes.SHA256())

        signed_cert_pem = signed_cert.public_bytes(serialization.Encoding.PEM)

        # Save to database
        conn = sqlite3.connect('certificates.db')
        cursor = conn.cursor()
        user_email = session['user_email']

        cursor.execute("""
            INSERT INTO certificates (subject, issuer, serial_number, valid_from, valid_to, public_key, pem, user_email)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            subject.rfc4514_string(),
            issuer.rfc4514_string(),
            str(serial_number),
            valid_from.strftime("%Y-%m-%d %H:%M:%S"),
            valid_to.strftime("%Y-%m-%d %H:%M:%S"),
            csr.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode(),
            signed_cert_pem.decode(),
            user_email
        ))

        cert_id = cursor.lastrowid
        conn.commit()
        conn.close()

        storage['signed_cert'] = signed_cert_pem
        storage['csr'] = csr_data

        return render_template(
            'signed_result.html',
            certificate=signed_cert_pem.decode(),
            uploaded_csr=csr_data.decode(),
            cert_id=cert_id
        )
    return render_template('sign_csr.html')

# تحميل ملف CSR الذي تم رفعه مسبقاً
@app.route('/download/uploaded_csr')
@login_required
def download_uploaded_csr():
    if 'csr' not in storage:
        return "لا يوجد ملف طلب توقيع مرفوع.", 404
    return send_file(io.BytesIO(storage['csr']),
                     mimetype='application/x-pem-file',
                     as_attachment=True,
                     download_name='uploaded_csr.pem')

# عرض معلومات شهادة معينة مع التحقق من المستخدم
@app.route('/certificate/<int:cert_id>')
@login_required
def show_certificate(cert_id):
    user_email = session['user_email']

    conn = sqlite3.connect('certificates.db')
    cursor = conn.cursor()
    cursor.execute("""
        SELECT subject, issuer, serial_number, valid_from, valid_to, public_key
        FROM certificates
        WHERE id = ? AND user_email = ?
    """, (cert_id, user_email))
    row = cursor.fetchone()
    conn.close()

    if not row:
        return "Certificate not found or access denied", 404

    cert_info = {
        "subject": row[0],
        "issuer": row[1],
        "serial_number": row[2],
        "valid_from": row[3],
        "valid_to": row[4],
        "public_key": row[5]
    }

    return render_template('show_certificate.html', cert_info=cert_info)

# تحميل الشهادة الموقعة
@app.route('/download/signed_cert')
@login_required
def download_signed_cert():
    if 'signed_cert' not in storage:
        return "No signed certificate found.", 404
    return send_file(io.BytesIO(storage['signed_cert']),
                     mimetype='application/x-pem-file',
                     as_attachment=True,
                     download_name='signed_certificate.pem')

 # عرض قائمة الشهادات للمستخدم فقط
@app.route('/certificates')
@login_required
def list_certificates():
    # جلب الإيميل ديال المستخدم المسجل الدخول من السيشن
    user_email = session['user_email']

    # فتح اتصال مع قاعدة البيانات certificates.db
    conn = sqlite3.connect('certificates.db')
    cursor = conn.cursor()

    # استعلام لجلب جميع الشهادات المرتبطة بهذا المستخدم
    cursor.execute("""
        SELECT id, subject, issuer, serial_number, valid_from, valid_to, user_email
        FROM certificates
        WHERE user_email = ?
    """, (user_email,))

    # تخزين النتائج في متغير certs
    certs = cursor.fetchall()

    # غلق اتصال قاعدة البيانات
    conn.close()

    # إرجاع صفحة HTML (قالب) مع تمرير الشهادات لي عرضها في الصفحة
    return render_template('certificates.html', certificates=certs)


# رفع شهادة جديدة وتسجيلها مع المستخدم
@app.route('/upload_certificate', methods=['GET', 'POST'])
@login_required
def upload_certificate():
    if request.method == 'POST':
        file = request.files.get('cert_file')
        if not file or file.filename == '':
            return "❌ لم يتم اختيار أي ملف.", 400

        try:
            cert_data = file.read()
            cert = x509.load_pem_x509_certificate(cert_data)

            subject = cert.subject.rfc4514_string()
            issuer = cert.issuer.rfc4514_string()
            serial_number = str(cert.serial_number)
            valid_from = cert.not_valid_before.strftime("%Y-%m-%d %H:%M:%S")
            valid_to = cert.not_valid_after.strftime("%Y-%m-%d %H:%M:%S")
            pem = cert.public_bytes(serialization.Encoding.PEM).decode()

            # استخراج المفتاح العمومي
            public_key = cert.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode()

            user_email = session['user_email']
            cert_id = str(uuid.uuid4())  # توليد cert_id فريد

            conn = sqlite3.connect('certificates.db')
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO certificates (
                    cert_id, subject, issuer, serial_number,
                    valid_from, valid_to, public_key, pem, user_email
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                cert_id, subject, issuer, serial_number,
                valid_from, valid_to, public_key, pem, user_email
            ))
            conn.commit()
            conn.close()

            return "✅ تم رفع الشهادة وتسجيلها بنجاح."
        except Exception as e:
            return f"❌ خطأ في معالجة الشهادة: {e}", 400

    return render_template('upload_certificate.html')


# حذف شهادة مؤمن بحيث فقط صاحب الشهادة يقدر يمسحها
@app.route('/delete/<int:cert_id>', methods=['POST'])
@login_required
def delete_certificate(cert_id):
    user_email = session['user_email']

    conn = sqlite3.connect('certificates.db')
    cursor = conn.cursor()

    # تحقق من أن الشهادة تابعة للمستخدم
    cursor.execute("SELECT id FROM certificates WHERE id = ? AND user_email = ?", (cert_id, user_email))
    cert = cursor.fetchone()

    if cert is None:
        conn.close()
        return "🚫 لا يمكنك حذف هذه الشهادة (غير موجودة أو ليس لديك صلاحية).", 403

    # الحذف
    cursor.execute("DELETE FROM certificates WHERE id = ? AND user_email = ?", (cert_id, user_email))
    conn.commit()
    conn.close()

    return redirect(url_for('list_certificates'))
@app.route('/revoke_certificate/<cert_id>', methods=['POST'])
@login_required
def revoke_certificate(cert_id):
    user_email = session.get('user_email')

    conn = sqlite3.connect('certificates.db')
    cursor = conn.cursor()

    cursor.execute('SELECT user_email, is_revoked FROM certificates WHERE cert_id = ?', (cert_id,))
    row = cursor.fetchone()

    if not row:
        conn.close()
        return "❌ الشهادة غير موجودة.", 404

    if row[0] != user_email:
        conn.close()
        return "⚠ ليس لديك الصلاحية لإلغاء هذه الشهادة.", 403

    if row[1] == 1:
        conn.close()
        return "ℹ الشهادة ملغاة من قبل.", 200

    cursor.execute('UPDATE certificates SET is_revoked = 1 WHERE cert_id = ?', (cert_id,))
    conn.commit()
    conn.close()
    return redirect(url_for('list_certificates'))     # باش يرجع للائحة الشهادات


if __name__ == '__main__':
    app.run(debug=True, port=5500, host='0.0.0.0', use_reloader=False)
