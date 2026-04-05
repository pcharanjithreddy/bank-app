from flask import Flask, render_template, request, redirect, session
from flask_pymongo import PyMongo
from flask_bcrypt import Bcrypt
from flask_mail import Mail, Message
import random, datetime, uuid, os

app = Flask(__name__)
app.secret_key = "secret"

# ---------------- ENV CONFIG ----------------
app.config["MONGO_URI"] = os.environ.get(
    "MONGO_URI",
    "mongodb+srv://cybershieldbank_db_user:PVN673z81djeESfC@cluster0.rwkdcda.mongodb.net/bankapp?retryWrites=true&w=majority"
)

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get("MAIL_USERNAME")
app.config['MAIL_PASSWORD'] = os.environ.get("MAIL_PASSWORD")

mongo = PyMongo(app)
bcrypt = Bcrypt(app)
mail = Mail(app)

otp_storage = {}

# ---------------- EMAIL ----------------
def send_email(to, subject, body):
    try:
        if os.environ.get("RENDER") == "true":
            print(f"📧 EMAIL (SIMULATED): {body}")
            return

        msg = Message(subject,
                      sender=app.config['MAIL_USERNAME'],
                      recipients=[to])
        msg.body = body
        mail.send(msg)

    except Exception as e:
        print("MAIL ERROR:", e)

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

        send_email(email, "OTP Verification",
                   f"Your OTP is {otp}\nValid for 90 seconds")

        return redirect('/verify-otp')

    return render_template('register.html')

# ---------------- REGISTER OTP ----------------
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
                "lock_until": None,
                "recovery_token": None,
                "token_expiry": None
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

    # 🔒 LOCK CHECK
    if user.get("lock_until") and datetime.datetime.now() < user["lock_until"]:

        token = str(uuid.uuid4())

        mongo.db.users.update_one(
            {"_id": user["_id"]},
            {"$set": {
                "recovery_token": token,
                "token_expiry": datetime.datetime.now() + datetime.timedelta(minutes=10)
            }}
        )

        link = f"https://your-app.onrender.com/recover/{token}"

        send_email(user['email'], "Account Locked",
                   f"Your account is locked.\nRecovery link: {link}")

        return "Account locked! Recovery link sent"

    # ✅ CORRECT PASSWORD
    if bcrypt.check_password_hash(user['password'], password):

        mongo.db.users.update_one(
            {"_id": user["_id"]},
            {"$set": {"failed_attempts": 0}}
        )

        session['user'] = user['username']
        session['temp'] = False

        return redirect('/dashboard')

    # ❌ WRONG PASSWORD
    attempts = user.get("failed_attempts", 0) + 1

    if attempts >= 3:
        token = str(uuid.uuid4())

        mongo.db.users.update_one({"_id": user["_id"]}, {"$set": {
            "failed_attempts": attempts,
            "lock_until": datetime.datetime.now() + datetime.timedelta(hours=48),
            "recovery_token": token,
            "token_expiry": datetime.datetime.now() + datetime.timedelta(minutes=10)
        }})

        link = f"https://your-app.onrender.com/recover/{token}"

        send_email(user['email'], "Account Locked",
                   f"Recovery link: {link}")

        return "Account locked! Email sent"

    mongo.db.users.update_one({"_id": user["_id"]}, {"$set": {"failed_attempts": attempts}})

    return f"Wrong password! Attempts: {attempts}"

# ---------------- RECOVERY LINK ----------------
@app.route('/recover/<token>')
def recover(token):

    user = mongo.db.users.find_one({"recovery_token": token})

    if not user:
        return "Invalid link"

    if datetime.datetime.now() > user["token_expiry"]:
        return "Link expired"

    otp = str(random.randint(100000,999999))

    otp_storage[user['email']] = {
        "otp": otp,
        "expiry": datetime.datetime.now() + datetime.timedelta(seconds=90),
        "username": user['username']
    }

    session['email'] = user['email']

    send_email(user['email'], "Recovery OTP", f"Your OTP: {otp}")

    return redirect('/recovery-otp')

# ---------------- RECOVERY OTP ----------------
@app.route('/recovery-otp', methods=['GET','POST'])
def recovery_otp():
    email = session.get('email')

    if request.method == 'POST':
        user_otp = request.form.get('otp')
        data = otp_storage.get(email)

        if not data:
            return "OTP not found"

        if datetime.datetime.now() > data['expiry']:
            return "OTP expired"

        if user_otp == data['otp']:
            session['user'] = data['username']
            session['temp'] = True
            return redirect('/dashboard')

        return "Wrong OTP"

    return render_template('otp.html')

# ---------------- DASHBOARD ----------------
@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect('/login')

    user = mongo.db.users.find_one({"username": session['user']})
    return render_template('dashboard.html', user=user, temp=session.get('temp'))

# ---------------- LOGOUT ----------------
@app.route('/logout')
def logout():
    session.clear()
    return redirect('/login')

# ---------------- RUN ----------------
if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000)