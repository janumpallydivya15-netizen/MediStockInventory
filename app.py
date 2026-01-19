from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
import boto3
from boto3.dynamodb.conditions import Attr
from decimal import Decimal
from datetime import datetime, timedelta
import os
from functools import wraps
import uuid

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'your-secret-key-change-in-production')

# ================= AWS CONFIG =================
AWS_REGION = os.environ.get('AWS_REGION', 'ap-south-1')
DYNAMODB_TABLE_MEDICINES = os.environ.get('DYNAMODB_TABLE_MEDICINES', 'MediStock_Medicines')
DYNAMODB_TABLE_USERS = os.environ.get('DYNAMODB_TABLE_USERS', 'MediStock_Users')
SNS_TOPIC_ARN = os.environ.get('SNS_TOPIC_ARN', '')

dynamodb = boto3.resource('dynamodb', region_name=AWS_REGION)
sns_client = boto3.client('sns', region_name=AWS_REGION)

medicines_table = dynamodb.Table(DYNAMODB_TABLE_MEDICINES)
users_table = dynamodb.Table(DYNAMODB_TABLE_USERS)

# ================= HELPERS =================
def float_to_decimal(obj):
    if isinstance(obj, float):
        return Decimal(str(obj))
    elif isinstance(obj, dict):
        return {k: float_to_decimal(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [float_to_decimal(i) for i in obj]
    return obj

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in first', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

# ================= ROUTES =================
@app.route('/')
def index():
    return redirect(url_for('dashboard')) if 'user_id' in session else render_template('index.html')

# ================= SIGNUP =================
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        role = request.form.get('role', 'staff')

        if not all([username, email, password, confirm_password]):
            flash('All fields are required', 'danger')
            return redirect(url_for('signup'))

        if password != confirm_password:
            flash('Passwords do not match', 'danger')
            return redirect(url_for('signup'))

        if len(password) < 6:
            flash('Password must be at least 6 characters', 'danger')
            return redirect(url_for('signup'))

        try:
            # ✅ FIX: SCAN instead of QUERY
            response = users_table.scan(
                FilterExpression=Attr('email').eq(email)
            )

            if response.get('Items'):
                flash('Email already registered', 'danger')
                return redirect(url_for('signup'))

            user_id = str(uuid.uuid4())
            hashed_password = generate_password_hash(password)

            users_table.put_item(
                Item={
                    'user_id': user_id,
                    'username': username,
                    'email': email,
                    'password': hashed_password,
                    'role': role,
                    'created_at': datetime.now().isoformat()
                }
            )

            flash('Account created successfully. Please log in.', 'success')
            return redirect(url_for('login'))

        except Exception as e:
            flash(f'Error creating account: {str(e)}', 'danger')
            return redirect(url_for('signup'))

    return render_template('signup.html')

# ================= LOGIN =================
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        if not email or not password:
            flash('Email and password required', 'danger')
            return redirect(url_for('login'))

        try:
            # ✅ FIX: SCAN instead of QUERY
            response = users_table.scan(
                FilterExpression=Attr('email').eq(email)
            )

            users = response.get('Items', [])
            if not users:
                flash('Invalid email or password', 'danger')
                return redirect(url_for('login'))

            user = users[0]

            if check_password_hash(user['password'], password):
                session['user_id'] = user['user_id']
                session['username'] = user['username']
                session['role'] = user['role']
                flash(f'Welcome {user["username"]}', 'success')
                return redirect(url_for('dashboard'))

            flash('Invalid email or password', 'danger')
            return redirect(url_for('login'))

        except Exception as e:
            flash(f'Login error: {str(e)}', 'danger')
            return redirect(url_for('login'))

    return render_template('login.html')

# ================= LOGOUT =================
@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully', 'info')
    return redirect(url_for('index'))

# ================= DASHBOARD =================
@app.route('/dashboard')
@login_required
def dashboard():
    response = medicines_table.scan()
    medicines = response.get('Items', [])

    low_stock = [m for m in medicines if int(m.get('quantity', 0)) <= int(m.get('threshold', 0))]

    return render_template(
        'dashboard.html',
        total=len(medicines),
        low_stock=len(low_stock)
    )

# ================= MEDICINES =================
@app.route('/medicines')
@login_required
def medicines():
    response = medicines_table.scan()
    return render_template('medicines.html', medicines=response.get('Items', []))

@app.route('/medicines/add', methods=['GET', 'POST'])
@login_required
def add_medicine():
    if request.method == 'POST':
        medicine_id = str(uuid.uuid4())

        medicines_table.put_item(
            Item={
                'medicine_id': medicine_id,
                'name': request.form.get('name'),
                'category': request.form.get('category'),
                'quantity': int(request.form.get('quantity')),
                'threshold': int(request.form.get('threshold')),
                'expiration_date': request.form.get('expiration_date'),
                'created_at': datetime.now().isoformat()
            }
        )

        flash('Medicine added successfully', 'success')
        return redirect(url_for('medicines'))

    return render_template('add_medicine.html')

# ================= ALERTS =================
def send_low_stock_alert(name, qty, threshold):
    if not SNS_TOPIC_ARN:
        return
    sns_client.publish(
        TopicArn=SNS_TOPIC_ARN,
        Subject='MediStock Low Stock Alert',
        Message=f'{name} is low on stock ({qty}/{threshold})'
    )

# ================= MAIN =================
if __name__ == '__main__':
    app
