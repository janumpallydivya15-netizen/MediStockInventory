from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
import boto3
from boto3.dynamodb.conditions import Attr
from datetime import datetime, timedelta
from functools import wraps
import uuid
import os
from decimal import Decimal

# ================= APP =================
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'dev-secret-key')

# ================= AWS CONFIG =================
AWS_REGION = os.environ.get('AWS_REGION', 'ap-south-1')
DYNAMODB_TABLE_MEDICINES = os.environ.get('DYNAMODB_TABLE_MEDICINES', 'MediStock_Medicines')
DYNAMODB_TABLE_USERS = os.environ.get('DYNAMODB_TABLE_USERS', 'MediStock_Users')
SNS_TOPIC_ARN = "arn:aws:sns:ap-south-1:120121146931:MediStockAlertsFinal"
print("AWS_REGION =", AWS_REGION)
print("USERS TABLE =", DYNAMODB_TABLE_USERS)

dynamodb = boto3.resource('dynamodb', region_name=AWS_REGION)
sns_client = boto3.client('sns', region_name=AWS_REGION)

medicines_table = dynamodb.Table(DYNAMODB_TABLE_MEDICINES)
users_table = dynamodb.Table(DYNAMODB_TABLE_USERS)

# ================= HELPERS =================
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in first', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated


def send_low_stock_alert(medicine_name, current_stock, threshold):
    try:
        sns_client.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject=f"LOW STOCK ALERT: {medicine_name}",
            Message=f"""
LOW STOCK ALERT

Medicine: {medicine_name}
Current Stock: {current_stock}
Threshold: {threshold}
Time: {datetime.now()}
"""
        )
        print("✅ SNS alert sent")

    except Exception as e:
        print("❌ SNS ERROR:", e)


# ================= ROUTES =================
@app.route('/')
def index():
    return redirect(url_for('dashboard')) if 'user_id' in session else render_template('index.html')


# ================= SIGNUP =================
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form['email']

        existing = users_table.scan(FilterExpression=Attr('email').eq(email))
        if existing.get('Items'):
            flash('Email already registered', 'danger')
            return redirect(url_for('signup'))

        users_table.put_item(Item={
            'user_id': str(uuid.uuid4()),
            'username': request.form['username'],
            'email': email,
            'password': generate_password_hash(request.form['password']),
            'created_at': datetime.now().isoformat()
        })

        flash('Signup successful. Please login.', 'success')
        return redirect(url_for('login'))

    return render_template('signup.html')


# ================= LOGIN =================
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        response = users_table.scan(FilterExpression=Attr('email').eq(email))
        users = response.get('Items', [])

        if not users or not check_password_hash(users[0]['password'], password):
            flash('Invalid credentials', 'danger')
            return redirect(url_for('login'))

        session['user_id'] = users[0]['user_id']
        session['username'] = users[0]['username']

        flash('Login successful', 'success')
        return redirect(url_for('dashboard'))

    return render_template('login.html')


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))


# ================= DASHBOARD =================
@app.route('/dashboard')
@login_required
def dashboard():
    response = medicines_table.scan()
    medicines = response.get('Items', [])

    total_medicines = len(medicines)
    low_stock = sum(
        1 for m in medicines
        if int(m.get('quantity', 0)) <= int(m.get('threshold', 0))
    )
    out_of_stock = sum(
        1 for m in medicines
        if int(m.get('quantity', 0)) == 0
    )

    stats = {
        "total_medicines": total_medicines,
        "low_stock": low_stock,
        "out_of_stock": out_of_stock
    }

    return render_template(
        "dashboard.html",
        medicines=medicines,
        stats=stats
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
        medicines_table.put_item(Item={
            'medicine_id': str(uuid.uuid4()),
            'name': request.form['name'],
            'category': request.form['category'],
            'quantity': int(request.form['quantity']),
            'threshold': int(request.form['threshold']),
            'expiration_date': request.form['expiration_date'],
            'created_at': datetime.now().isoformat()
        })

        flash('Medicine added', 'success')
        return redirect(url_for('medicines'))

    return render_template('add_medicine.html')


# ================= EDIT MEDICINE =================
@app.route('/medicines/edit/<medicine_id>', methods=['GET', 'POST'])
@login_required
def edit_medicine(medicine_id):
    response = medicines_table.get_item(Key={'medicine_id': medicine_id})
    medicine = response.get('Item')

    if not medicine:
        flash('Medicine not found', 'danger')
        return redirect(url_for('medicines'))

    if request.method == 'POST':
        new_quantity = int(request.form['quantity'])
        threshold = int(request.form['threshold'])

        medicines_table.update_item(
            Key={'medicine_id': medicine_id},
            UpdateExpression='SET quantity=:q, threshold=:t, updated_at=:u',
            ExpressionAttributeValues={
                ':q': new_quantity,
                ':t': threshold,
                ':u': datetime.now().isoformat()
            }
        )

       if int(new_quantity) <= int(threshold):
            send_low_stock_alert(medicine['name'], new_quantity, threshold)

        flash('Medicine updated', 'success')
        return redirect(url_for('medicines'))

    return render_template('edit_medicine.html', medicine=medicine)


# ================= ALERTS =================
def send_low_stock_alert(medicine_name, current_stock, threshold):
    print("🚨 LOW STOCK FUNCTION CALLED")
    print("Medicine:", medicine_name)
    print("Stock:", current_stock, "Threshold:", threshold)

    try:
        response = sns_client.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject=f"LOW STOCK ALERT: {medicine_name}",
            Message=f"""
LOW STOCK ALERT

Medicine: {medicine_name}
Current Stock: {current_stock}
Threshold: {threshold}
Time: {datetime.now()}
"""
        )
        print("✅ SNS MESSAGE ID:", response['MessageId'])

    except Exception as e:
        print("❌ SNS ERROR:", e)



@app.route('/test-sns')
def test_sns():
    send_low_stock_alert("TEST MEDICINE", 2, 10)
    return "SNS test sent"


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)





