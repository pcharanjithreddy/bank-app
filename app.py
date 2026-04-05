from flask import Flask, render_template, request, redirect, session
from flask_pymongo import PyMongo
from flask_bcrypt import Bcrypt
from flask_mail import Mail, Message
import random, datetime, uuid

app = Flask(__name__)
app.secret_key = "secret"

# ---------------- CONFIG ----------------
app.config["MONGO_URI"] = "mongodb+srv://cybershieldbank_db_user:PVN673z81djeESfC@cluster0.rwkdcda.mongodb.net/bankapp?retryWrites=true&w=majority"

# EMAIL CONFIG
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = "cybershieldbank@gmail.com"
app.config['MAIL_PASSWORD'] = "mmxyfotzbqmjzpsx"

mongo = PyMongo(app)
bcrypt = Bcrypt(app)
mail = Mail(app)

otp_storage = {}

# ---------------- SEND EMAIL ----------------
def send_email(to, subject, body):
    msg = Message(subject,
                  sender=app.config['MAIL_USERNAME'],
                  recipients=[to])
    msg.body = body
    mail.send(msg)

# ---------------- HOME ----------------
@app.route('/')
def home():
    return redirect('/login')

# ---------------- REGISTER ----------------
@app.route('/register', methods=['GET','POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')

        hashed = bcrypt.generate_password_hash(password).decode('utf-8')

        otp = str(random.randint(100000,999999))
        expiry = datetime.datetime.now() + datetime.timedelta(seconds=90)

        otp_storage[email] = {
            "otp": otp,
            "expiry": expiry,
            "username": username,
            "password": hashed
        }

        session['email'] = email

        # ✅ SEND OTP TO EMAIL
        send_email(email, "OTP Verification",
                   f"Your OTP is {otp}\nValid for 90 seconds")

        return redirect('/verify-otp')

    return render_template('register.html')

# ---------------- OTP VERIFY ----------------
@app.route('/verify-otp', methods=['GET','POST'])
def verify_otp():
    email = session.get('email')

    if request.method == 'POST':
        user_otp = request.form.get('otp')
        data = otp_storage.get(email)

        if not data:
            return "OTP not found"

        if datetime.datetime.now() > data['expiry']:
            return "OTP expired"

        if user_otp == data['otp']:
            mongo.db.users.insert_one({
                "username": data['username'],
                "email": email,
                "password": data['password'],
                "failed_attempts": 0,
                "lock_until": None
            })

            otp_storage.pop(email, None)
            session.pop('email', None)

            return redirect('/login')

        return "Wrong OTP"

    return render_template('otp.html')

# ---------------- LOGIN ----------------
@app.route('/login', methods=['GET','POST'])
def login():

    if request.method == 'GET':
        a = random.randint(1, 9)
        b = random.randint(1, 9)
        session['captcha'] = str(a + b)
        return render_template('login.html', captcha=f"{a} + {b}")

    user_input = request.form.get('username')
    password = request.form.get('password')
    captcha_input = request.form.get('captcha')

    if captcha_input != session.get('captcha'):
        return "Wrong CAPTCHA"

    user = mongo.db.users.find_one({
        "$or": [{"email": user_input}, {"username": user_input}]
    })

    if not user:
        return "User not found"

    if bcrypt.check_password_hash(user['password'], password):
        session['user'] = user['username']
        return redirect('/dashboard')

    return "Wrong password"

# ---------------- DASHBOARD ----------------
@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect('/login')

    user = mongo.db.users.find_one({"username": session['user']})
    return render_template('dashboard.html', user=user)

# ---------------- LOGOUT ----------------
@app.route('/logout')
def logout():
    session.clear()
    return redirect('/login')

# ---------------- RUN ----------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)