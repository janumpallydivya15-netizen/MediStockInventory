from flask import Flask, render_template, request, redirect, url_for, session, flash
import boto3
from boto3.dynamodb.conditions import Key, Attr
import uuid
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
import os
from decimal import Decimal
from functools import wraps
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', os.urandom(24))

# Add context processor for datetime
@app.context_processor
def inject_now():
    return {'now': datetime.now()}

# Initialize AWS resources
dynamodb = boto3.resource('dynamodb', region_name='ap-south-1')  # Update to your AWS region
sns_client = boto3.client('sns', region_name='ap-south-1')

# DynamoDB Tables
medicines_table = dynamodb.Table('MediStock_Medicines')
users_table = dynamodb.Table('MediStock_Users')

# SNS Configuration
SNS_TOPIC_ARN = "arn:aws:sns:ap-south-1:120121146931:MediStockAlerts"

# Email settings
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
SENDER_EMAIL = "janumpallydivya15@gmail.com"  # Your email
SENDER_PASSWORD = "umpb bimb pahp axmc"  # Update with your Gmail app password



# Function to send email via SMTP
def send_email(to_email, subject, body):
    """Send email using Gmail SMTP"""
    msg = MIMEMultipart()
    msg['From'] = SENDER_EMAIL
    msg['To'] = to_email
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain'))

    try:
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(SENDER_EMAIL, SENDER_PASSWORD)
        text = msg.as_string()
        server.sendmail(SENDER_EMAIL, to_email, text)
        server.quit()
        print(f"✅ Email sent successfully to {to_email}")
        return True
    except Exception as e:
        print(f"❌ Failed to send email: {e}")
        return False

# Function to send low stock alert via SNS
def send_low_stock_alert(medicine_name, current_stock, threshold, user_email=None):
    """Send low stock alert via SNS topic and direct email"""
    try:
        message = f"""
LOW STOCK ALERT

Medicine: {medicine_name}
Current Stock: {current_stock}
Threshold: {threshold}
Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

Action Required: Please restock {medicine_name} as soon as possible.
"""
        
        # Send to SNS topic (all subscribers)
        response = sns_client.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject=f"LOW STOCK ALERT: {medicine_name}",
            Message=message
        )
        print(f"✅ SNS alert sent to topic for {medicine_name}. MessageId: {response['MessageId']}")
        
        # Send direct email if user email provided
        if user_email:
            send_email(user_email, f"LOW STOCK ALERT: {medicine_name}", message)
            
        return True
    except Exception as e:
        print(f"❌ SNS ERROR: {e}")
        # Fallback to direct email if SNS fails
        if user_email:
            return send_email(user_email, f"LOW STOCK ALERT: {medicine_name}", message)
        return False

# Function to send email to specific user
def send_email_to_user(email, subject, message):
    """Send direct email notification to user"""
    return send_email(email, subject, message)

# Function to subscribe user to SNS alerts
def subscribe_user_to_alerts(email):
    """Subscribe user email to SNS topic for alerts"""
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

# Function to unsubscribe user from alerts
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

# Function to send expiry alert
def send_expiry_alert(medicine_name, expiry_date, days_remaining, user_email=None):
    """Send expiry alert notification via SNS and email"""
    try:
        message = f"""
EXPIRY ALERT

Medicine: {medicine_name}
Expiry Date: {expiry_date}
Days Remaining: {days_remaining}
Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

Action Required: Remove or use {medicine_name} before expiration.
"""
        
        # Send to SNS topic
        response = sns_client.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject=f"EXPIRY ALERT: {medicine_name}",
            Message=message
        )
        print(f"✅ Expiry alert sent for {medicine_name}")
        
        # Send direct email
        if user_email:
            send_email(user_email, f"EXPIRY WARNING: {medicine_name}", message)
            
        return True
    except Exception as e:
        print(f"❌ Expiry alert error: {e}")
        # Fallback to direct email if SNS fails
        if user_email:
            return send_email(user_email, f"EXPIRY WARNING: {medicine_name}", message)
        return False

# Function to send welcome notification
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

Best regards,
MediStock Team
"""
        
        send_email(email, "Welcome to MediStock", message)
        print(f"✅ Welcome email sent to {email}")
        return True
    except Exception as e:
        print(f"❌ Welcome email error: {e}")
        return False

# Function to check and alert expiring medicines
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

# Helper function to check if user is logged in
def is_logged_in():
    return 'user_id' in session

# Decorator for login required routes
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not is_logged_in():
            flash('Please log in to access this page.', 'info')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Home route
@app.route('/')
def index():
    if is_logged_in():
        return redirect(url_for('dashboard'))
    return render_template('index.html', is_logged_in=is_logged_in())

# Registration Page
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form.get('confirm_password', '')
        
        # Basic Validation
        if not username or not email or not password:
            flash("All fields are mandatory! Please fill out the entire form.", "danger")
            return redirect(url_for('signup'))
            
        if confirm_password and password != confirm_password:
            flash("Passwords do not match! Please try again.", "danger")
            return redirect(url_for('signup'))

        # Check if user already exists
        response = users_table.scan(FilterExpression=Attr('email').eq(email))
        if response.get('Items'):
            flash("User already exists! Please log in.", "info")
            return redirect(url_for('login'))

        # Hash the password
        hashed_password = generate_password_hash(password)
        
        # Generate unique user ID
        user_id = str(uuid.uuid4())

        # Store user in DynamoDB
        users_table.put_item(
            Item={
                'user_id': user_id,
                'username': username,
                'email': email,
                'password': hashed_password,
                'created_at': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                'subscription_arn': ''
            }
        )

        # Subscribe user to SNS alerts
        subscription_arn = subscribe_user_to_alerts(email)
        if subscription_arn:
            users_table.update_item(
                Key={'user_id': user_id},
                UpdateExpression="SET subscription_arn = :arn",
                ExpressionAttributeValues={':arn': subscription_arn}
            )

        # Send welcome email
        send_welcome_notification(email, username)
        
        flash("Registration successful! You can now log in.", "success")
        return redirect(url_for('login'))
        
    return render_template('signup.html', is_logged_in=is_logged_in())

# Login Page
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        # Basic Validation
        if not email or not password:
            flash("Please enter both email and password.", "danger")
            return redirect(url_for('login'))

        # Fetch user data from DynamoDB
        response = users_table.scan(FilterExpression=Attr('email').eq(email))
        users = response.get('Items', [])

        if not users or not check_password_hash(users[0]['password'], password):
            flash("Incorrect email or password! Please try again.", "danger")
            return redirect(url_for('login'))

        user = users[0]

        # Store user info in session
        session['user_id'] = user['user_id']
        session['username'] = user['username']
        session['email'] = user['email']
        
        flash(f"Welcome back, {user['username']}!", "success")
        return redirect(url_for('dashboard'))
        
    return render_template('login.html', is_logged_in=is_logged_in())

# Logout route
@app.route('/logout')
def logout():
    session.clear()
    flash("You have been logged out successfully.", "info")
    return redirect(url_for('index'))

# Dashboard Page
@app.route('/dashboard')
@login_required
def dashboard():
    # Get all medicines
    response = medicines_table.scan()
    medicines = response.get('Items', [])

    # Calculate statistics
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

    # Check for expiring medicines
    check_and_alert_expiring_medicines(session['user_id'], session.get('email'))

    return render_template('dashboard.html', 
                          medicines=medicines, 
                          stats=stats,
                          is_logged_in=is_logged_in())

# Medicines List Page
@app.route('/medicines')
@login_required
def medicines():
    # Get all medicines from DynamoDB
    response = medicines_table.scan()
    medicines_list = response.get('Items', [])
    
    # Sort medicines by name
    medicines_list.sort(key=lambda x: x.get('name', ''))
    
    return render_template('medicines.html', 
                          medicines=medicines_list, 
                          is_logged_in=is_logged_in())

# Add Medicine Page
@app.route('/medicines/add', methods=['GET', 'POST'])
@login_required
def add_medicine():
    if request.method == 'POST':
        name = request.form['name']
        category = request.form['category']
        quantity = request.form['quantity']
        threshold = request.form['threshold']
        expiration_date = request.form['expiration_date']
        
        # Basic validation
        if not name or not category or not quantity or not threshold or not expiration_date:
            flash("All fields are required to add a medicine.", "danger")
            return redirect(url_for('add_medicine'))
        
        # Generate unique medicine ID
        medicine_id = str(uuid.uuid4())
        
        # Store medicine in DynamoDB
        medicines_table.put_item(
            Item={
                'medicine_id': medicine_id,
                'user_id': session['user_id'],
                'name': name,
                'category': category,
                'quantity': int(quantity),
                'threshold': int(threshold),
                'expiry_date': expiration_date,
                'created_at': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
        )
        
        # Check if stock is low immediately after adding
        if int(quantity) <= int(threshold):
            send_low_stock_alert(name, int(quantity), int(threshold), session.get('email'))
        
        flash(f"Medicine '{name}' added successfully!", "success")
        return redirect(url_for('medicines'))
        
    return render_template('add_medicine.html', is_logged_in=is_logged_in())

# Edit Medicine Page
@app.route('/medicines/edit/<medicine_id>', methods=['GET', 'POST'])
@login_required
def update_medicine(medicine_id):
    # Get medicine details from DynamoDB
    response = medicines_table.get_item(Key={'medicine_id': medicine_id})
    medicine = response.get('Item')
    
    if not medicine:
        flash("Medicine not found!", "danger")
        return redirect(url_for('medicines'))
    
    if request.method == 'POST':
        name = request.form['name']
        category = request.form['category']
        quantity = request.form['quantity']
        threshold = request.form['threshold']
        expiration_date = request.form['expiration_date']
        
        new_quantity = int(quantity)
        new_threshold = int(threshold)
        
        try:
            # Update medicine in DynamoDB
            medicines_table.update_item(
                Key={'medicine_id': medicine_id},
                UpdateExpression="SET #name = :name, category = :cat, quantity = :qty, threshold = :thr, expiry_date = :exp, updated_at = :upd",
                ConditionExpression='attribute_exists(medicine_id)',
                ExpressionAttributeNames={'#name': 'name'},
                ExpressionAttributeValues={
                    ':name': name,
                    ':cat': category,
                    ':qty': new_quantity,
                    ':thr': new_threshold,
                    ':exp': expiration_date,
                    ':upd': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                }
            )

            # Check if stock is low after update
            if new_quantity <= new_threshold:
                send_low_stock_alert(name, new_quantity, new_threshold, session.get('email'))

            flash(f"Medicine '{name}' updated successfully!", "success")
            
        except medicines_table.meta.client.exceptions.ConditionalCheckFailedException:
            flash('Medicine not found. Update failed.', 'danger')
        except Exception as e:
            flash(f"Error updating medicine: {str(e)}", "danger")
        
        return redirect(url_for('medicines'))
        
    return render_template('edit_medicine.html', 
                          medicine=medicine, 
                          is_logged_in=is_logged_in())

# Delete Medicine Route
@app.route('/medicines/delete/<medicine_id>', methods=['POST'])
@login_required
def delete_medicine(medicine_id):
    # Get medicine details before deletion
    response = medicines_table.get_item(Key={'medicine_id': medicine_id})
    medicine = response.get('Item')
    
    if not medicine:
        flash("Medicine not found.", "danger")
        return redirect(url_for('medicines'))
    
    # Delete medicine from DynamoDB
    medicines_table.delete_item(Key={'medicine_id': medicine_id})
    
    flash(f"Medicine '{medicine['name']}' deleted successfully.", "success")
    return redirect(url_for('medicines'))

# User Profile Page
@app.route('/profile')
@login_required
def profile():
    # Get user details from DynamoDB
    response = users_table.get_item(Key={'user_id': session['user_id']})
    user = response.get('Item', {})
    
    # Get user's medicines count
    response = medicines_table.scan(
        FilterExpression=Attr('user_id').eq(session['user_id'])
    )
    medicines_count = len(response.get('Items', []))
    
    return render_template('profile.html', 
                          user=user, 
                          medicines_count=medicines_count,
                          is_logged_in=is_logged_in())

# Update Profile Route
@app.route('/update-profile', methods=['POST'])
@login_required
def update_profile():
    try:
        username = request.form.get('username')
        email = request.form.get('email')

        # Update user info in DynamoDB
        users_table.update_item(
            Key={'user_id': session['user_id']},
            UpdateExpression="SET username = :name, email = :email",
            ExpressionAttributeValues={
                ':name': username,
                ':email': email
            }
        )

        # Update session
        session['username'] = username
        session['email'] = email
        
        flash("Profile updated successfully!", "success")
        return redirect(url_for('profile'))

    except Exception as e:
        app.logger.error(f"Error updating profile: {str(e)}")
        flash("An error occurred while updating your profile.", "danger")
        return redirect(url_for('profile'))

# Change Password Route
@app.route('/change-password', methods=['POST'])
@login_required
def change_password():
    current_password = request.form.get('current_password')
    new_password = request.form.get('new_password')
    confirm_password = request.form.get('confirm_password')
    
    if not current_password or not new_password or not confirm_password:
        flash("All password fields are required.", "danger")
        return redirect(url_for('profile'))
    
    if new_password != confirm_password:
        flash("New passwords do not match.", "danger")
        return redirect(url_for('profile'))
    
    # Get user from database
    response = users_table.get_item(Key={'user_id': session['user_id']})
    user = response.get('Item')
    
    # Verify current password
    if not check_password_hash(user['password'], current_password):
        flash("Current password is incorrect.", "danger")
        return redirect(url_for('profile'))
    
    # Update password
    hashed_password = generate_password_hash(new_password)
    users_table.update_item(
        Key={'user_id': session['user_id']},
        UpdateExpression="SET password = :pwd",
        ExpressionAttributeValues={':pwd': hashed_password}
    )
    
    flash("Password changed successfully!", "success")
    return redirect(url_for('profile'))

# Test SNS Route (for debugging)
@app.route('/test-sns')
@login_required
def test_sns():
    send_low_stock_alert("TEST MEDICINE", 2, 10, session.get('email'))
    flash("Test SNS alert sent! Check your email.", "info")
    return redirect(url_for('dashboard'))

# Error handlers
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html', is_logged_in=is_logged_in()), 404

@app.errorhandler(500)
def server_error(e):
    return render_template('500.html', is_logged_in=is_logged_in()), 500

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, debug=True)
