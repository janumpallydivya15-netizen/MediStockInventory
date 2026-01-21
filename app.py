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
SNS_TOPIC_ARN = "arn:aws:sns:ap-south-1:120121146931:MediStockAlerts"

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

def send_low_stock_alert(medicine_name, current_stock, threshold, user_email=None):
    """Send low stock alert via SNS topic or directly to user email"""
    try:
        message = f"""
LOW STOCK ALERT
Medicine: {medicine_name}
Current Stock: {current_stock}
Threshold: {threshold}
Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Action Required: Please restock {medicine_name} as soon as possible.
"""
        
        # Send to topic (all subscribers)
        sns_client.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject=f"LOW STOCK ALERT: {medicine_name}",
            Message=message
        )
        print(f"✅ SNS alert sent to topic for {medicine_name}")
        
        # Optionally send direct email if user email provided
        if user_email:
            send_email_to_user(user_email, f"LOW STOCK: {medicine_name}", message)
            
    except Exception as e:
        print("❌ SNS ERROR:", e)

def send_email_to_user(email, subject, message):
    """Send direct email notification to user"""
    try:
        sns_client.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject=subject,
            Message=message,
            MessageAttributes={
                'email': {
                    'DataType': 'String',
                    'StringValue': email
                }
            }
        )
        print(f"✅ Email sent to {email}")
    except Exception as e:
        print(f"❌ Email send error: {e}")

def subscribe_user_to_alerts(email):
    """Subscribe user email to SNS topic"""
    try:
        response = sns_client.subscribe(
            TopicArn=SNS_TOPIC_ARN,
            Protocol='email',
            Endpoint=email,
            ReturnSubscriptionArn=True
        )
        subscription_arn = response.get('SubscriptionArn', 'pending confirmation')
        print(f"✅ User {email} subscribed. ARN: {subscription_arn}")
        return subscription_arn
    except Exception as e:
        print(f"❌ Subscription error: {e}")
        return None

def unsubscribe_user_from_alerts(subscription_arn):
    """Unsubscribe user from SNS topic"""
    try:
        if subscription_arn and subscription_arn != 'pending confirmation':
            sns_client.unsubscribe(SubscriptionArn=subscription_arn)
            print(f"✅ Unsubscribed: {subscription_arn}")
            return True
    except Exception as e:
        print(f"❌ Unsubscribe error: {e}")
    return False

def send_expiry_alert(medicine_name, expiry_date, days_remaining, user_email=None):
    """Send expiry alert notification"""
    try:
        message = f"""
EXPIRY ALERT
Medicine: {medicine_name}
Expiry Date: {expiry_date}
Days Remaining: {days_remaining}
Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Action Required: Remove or use {medicine_name} before expiration.
"""
        
        sns_client.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject=f"EXPIRY ALERT: {medicine_name}",
            Message=message
        )
        print(f"✅ Expiry alert sent for {medicine_name}")
        
        if user_email:
            send_email_to_user(user_email, f"EXPIRY WARNING: {medicine_name}", message)
            
    except Exception as e:
        print("❌ Expiry alert error:", e)

def send_welcome_notification(email, username):
    """Send welcome email to new user"""
    try:
        message = f"""
Welcome to MediStock, {username}!

Your account has been successfully created.
You are now subscribed to receive important alerts about:
- Low stock notifications
- Medicine expiry warnings
- System updates

Email: {email}
Registered: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

Thank you for using MediStock!
"""
        
        send_email_to_user(email, "Welcome to MediStock", message)
        print(f"✅ Welcome email sent to {email}")
    except Exception as e:
        print(f"❌ Welcome email error: {e}")

def check_and_alert_expiring_medicines(user_id, user_email=None):
    """Check for medicines expiring soon and send alerts"""
    try:
        response = medicines_table.scan(
            FilterExpression=Attr('user_id').eq(user_id)
        )
        
        medicines = response.get('Items', [])
        today = datetime.now()
        alert_sent = False
        
        for med in medicines:
            if 'expiry_date' in med:
                try:
                    expiry = datetime.strptime(med['expiry_date'], '%Y-%m-%d')
                    days_remaining = (expiry - today).days
                    
                    # Alert if expiring within 30 days
                    if 0 < days_remaining <= 30:
                        send_expiry_alert(
                            med['name'],
                            med['expiry_date'],
                            days_remaining,
                            user_email
                        )
                        alert_sent = True
                except ValueError:
                    pass
        
        return alert_sent
    except Exception as e:
        print(f"❌ Expiry check error: {e}")
        return False

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
def update_medicine(medicine_id):
    response = medicines_table.get_item(Key={'medicine_id': medicine_id})
    medicine = response.get('Item')

if request.method == 'POST':
    new_quantity = int(request.form['quantity'])
    threshold = int(request.form['threshold'])

    try:
        medicines_table.update_item(
            Key={'medicine_id': medicine_id},
            UpdateExpression='SET quantity=:q, threshold=:t, updated_at=:u',
            ConditionExpression='attribute_exists(medicine_id)',
            ExpressionAttributeValues={
                ':q': new_quantity,
                ':t': threshold,
                ':u': datetime.now().isoformat()
            }
        )

        if new_quantity <= threshold:
            send_low_stock_alert(medicine['name'], new_quantity, threshold)

        flash('Medicine updated successfully', 'success')

    except medicines_table.meta.client.exceptions.ConditionalCheckFailedException:
        flash('Medicine not found. Update failed.', 'danger')

    return redirect(url_for('medicines'))


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








