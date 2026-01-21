from flask import Flask, request, session, redirect, url_for, render_template, flash
import boto3
from boto3.dynamodb.conditions import Attr
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import logging
import os
import uuid
from dotenv import load_dotenv
from functools import wraps

# Load environment variables
load_dotenv()

# ---------------------------------------
# Flask App Initialization
# ---------------------------------------
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'temporary_key_for_development')

# Add context processor for datetime
@app.context_processor
def inject_now():
    return {'now': datetime.now()}

# ---------------------------------------
# App Configuration
# ---------------------------------------
AWS_REGION_NAME = os.environ.get('AWS_REGION_NAME', 'ap-south-1')

# Email Configuration
SMTP_SERVER = os.environ.get('SMTP_SERVER', 'smtp.gmail.com')
SMTP_PORT = int(os.environ.get('SMTP_PORT', 587))
SENDER_EMAIL = os.environ.get('SENDER_EMAIL')
SENDER_PASSWORD = os.environ.get('SENDER_PASSWORD')
ENABLE_EMAIL = os.environ.get('ENABLE_EMAIL', 'False').lower() == 'true'

# Table Names from .env
MEDICINES_TABLE_NAME = os.environ.get('MEDICINES_TABLE_NAME', 'MediStock_Medicines')
USERS_TABLE_NAME = os.environ.get('USERS_TABLE_NAME', 'MediStock_Users')

# SNS Configuration
SNS_TOPIC_ARN = os.environ.get('SNS_TOPIC_ARN')
ENABLE_SNS = os.environ.get('ENABLE_SNS', 'False').lower() == 'true'

# ---------------------------------------
# AWS Resources
# ---------------------------------------
dynamodb = boto3.resource('dynamodb', region_name=AWS_REGION_NAME)
sns_client = boto3.client('sns', region_name=AWS_REGION_NAME)

# DynamoDB Tables
medicines_table = dynamodb.Table(MEDICINES_TABLE_NAME)
users_table = dynamodb.Table(USERS_TABLE_NAME)

# ---------------------------------------
# Logging
# ---------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("medistock.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# ---------------------------------------
# Helper Functions
# ---------------------------------------
def is_logged_in():
    """Check if user is logged in"""
    return 'user_id' in session

def login_required(f):
    """Decorator for login required routes"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not is_logged_in():
            flash('Please log in to access this page.', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def send_email(to_email, subject, body):
    """Send email via SMTP"""
    if not ENABLE_EMAIL:
        logger.info(f"[Email Skipped] Subject: {subject} to {to_email}")
        return False

    try:
        msg = MIMEMultipart()
        msg['From'] = SENDER_EMAIL
        msg['To'] = to_email
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'plain'))

        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(SENDER_EMAIL, SENDER_PASSWORD)
        server.sendmail(SENDER_EMAIL, to_email, msg.as_string())
        server.quit()

        logger.info(f"Email sent to {to_email}")
        return True
    except Exception as e:
        logger.error(f"Email sending failed: {e}")
        return False

def publish_to_sns(message, subject="MediStock Notification"):
    """Publish message to SNS topic"""
    if not ENABLE_SNS:
        logger.info(f"[SNS Skipped] Message: {message}")
        return False

    try:
        response = sns_client.publish(
            TopicArn=SNS_TOPIC_ARN,
            Message=message,
            Subject=subject
        )
        logger.info(f"SNS published: {response['MessageId']}")
        return True
    except Exception as e:
        logger.error(f"SNS publish failed: {e}")
        return False

def send_low_stock_alert(medicine_name, current_stock, threshold, user_email=None):
    """Send low stock alert via SNS and email"""
    message = f"""
LOW STOCK ALERT

Medicine: {medicine_name}
Current Stock: {current_stock}
Threshold: {threshold}
Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

Action Required: Please restock {medicine_name} as soon as possible.
"""
    
    # Send to SNS topic (all subscribers)
    publish_to_sns(message, f"LOW STOCK ALERT: {medicine_name}")
    
    # Send direct email if user email provided
    if user_email and ENABLE_EMAIL:
        send_email(user_email, f"LOW STOCK ALERT: {medicine_name}", message)

def send_expiry_alert(medicine_name, expiry_date, days_remaining, user_email=None):
    """Send expiry alert notification via SNS and email"""
    message = f"""
EXPIRY ALERT

Medicine: {medicine_name}
Expiry Date: {expiry_date}
Days Remaining: {days_remaining}
Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

Action Required: Remove or use {medicine_name} before expiration.
"""
    
    # Send to SNS topic
    publish_to_sns(message, f"EXPIRY ALERT: {medicine_name}")
    
    # Send direct email
    if user_email and ENABLE_EMAIL:
        send_email(user_email, f"EXPIRY WARNING: {medicine_name}", message)

def send_welcome_notification(email, username):
    """Send welcome email to new user"""
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
    
    if ENABLE_EMAIL:
        send_email(email, "Welcome to MediStock", message)
        logger.info(f"Welcome email sent to {email}")

def subscribe_user_to_alerts(email):
    """Subscribe user email to SNS topic for alerts"""
    if not ENABLE_SNS:
        logger.info(f"[SNS Skipped] Subscription for {email}")
        return None
        
    try:
        response = sns_client.subscribe(
            TopicArn=SNS_TOPIC_ARN,
            Protocol='email',
            Endpoint=email,
            ReturnSubscriptionArn=True
        )
        subscription_arn = response.get('SubscriptionArn', 'pending confirmation')
        logger.info(f"User {email} subscribed. ARN: {subscription_arn}")
        return subscription_arn
    except Exception as e:
        logger.error(f"Subscription error: {e}")
        return None

def unsubscribe_user_from_alerts(subscription_arn):
    """Unsubscribe user from SNS topic"""
    if not ENABLE_SNS or not subscription_arn or subscription_arn == 'pending confirmation':
        return False
        
    try:
        sns_client.unsubscribe(SubscriptionArn=subscription_arn)
        logger.info(f"Unsubscribed: {subscription_arn}")
        return True
    except Exception as e:
        logger.error(f"Unsubscribe error: {e}")
        return False

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
                    logger.warning(f"Invalid expiry date format for medicine: {med.get('name')}")
        
        return alert_sent
    except Exception as e:
        logger.error(f"Expiry check error: {e}")
        return False

# ---------------------------------------
# Routes
# ---------------------------------------

# Home Page
@app.route('/')
def index():
    if is_logged_in():
        return redirect(url_for('dashboard'))
    return render_template('index.html', is_logged_in=is_logged_in())

# Registration Page
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if is_logged_in():
        return redirect(url_for('dashboard'))
        
    if request.method == 'POST':
        # Form validation
        required_fields = ['username', 'email', 'password']
        for field in required_fields:
            if field not in request.form or not request.form[field]:
                flash(f'Please fill in the {field} field', 'danger')
                return render_template('signup.html', is_logged_in=is_logged_in())
        
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form.get('confirm_password', '')
        
        # Check if passwords match
        if confirm_password and password != confirm_password:
            flash('Passwords do not match', 'danger')
            return render_template('signup.html', is_logged_in=is_logged_in())

        # Check if user already exists
        try:
            response = users_table.scan(FilterExpression=Attr('email').eq(email))
            if response.get('Items'):
                flash('Email already registered. Please log in.', 'danger')
                return redirect(url_for('login'))
        except Exception as e:
            logger.error(f"Error checking existing user: {e}")
            flash('An error occurred. Please try again.', 'danger')
            return render_template('signup.html', is_logged_in=is_logged_in())

        # Hash the password
        hashed_password = generate_password_hash(password)
        
        # Generate unique user ID
        user_id = str(uuid.uuid4())

        # Store user in DynamoDB
        try:
            users_table.put_item(
                Item={
                    'user_id': user_id,
                    'username': username,
                    'email': email,
                    'password': hashed_password,
                    'created_at': datetime.now().isoformat(),
                    'subscription_arn': '',
                    'login_count': 0
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
            
            flash('Registration successful! You can now log in.', 'success')
            return redirect(url_for('login'))
            
        except Exception as e:
            logger.error(f"Registration error: {e}")
            flash('An error occurred during registration. Please try again.', 'danger')
            return render_template('signup.html', is_logged_in=is_logged_in())
        
    return render_template('signup.html', is_logged_in=is_logged_in())

# Login Page
@app.route('/login', methods=['GET', 'POST'])
def login():
    if is_logged_in():
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        # Basic Validation
        if not request.form.get('email') or not request.form.get('password'):
            flash('Please enter both email and password.', 'danger')
            return render_template('login.html', is_logged_in=is_logged_in())

        email = request.form['email']
        password = request.form['password']

        try:
            # Fetch user data from DynamoDB
            response = users_table.scan(FilterExpression=Attr('email').eq(email))
            users = response.get('Items', [])

            if not users:
                flash('Email not found.', 'danger')
                return render_template('login.html', is_logged_in=is_logged_in())

            user = users[0]
            
            # Verify password
            if not check_password_hash(user['password'], password):
                flash('Invalid password.', 'danger')
                return render_template('login.html', is_logged_in=is_logged_in())

            # Store user info in session
            session['user_id'] = user['user_id']
            session['username'] = user['username']
            session['email'] = user['email']
            
            # Update login count
            try:
                users_table.update_item(
                    Key={'user_id': user['user_id']},
                    UpdateExpression='SET login_count = if_not_exists(login_count, :zero) + :inc',
                    ExpressionAttributeValues={':inc': 1, ':zero': 0}
                )
            except Exception as e:
                logger.error(f"Failed to update login count: {e}")
            
            flash(f'Welcome back, {user["username"]}!', 'success')
            return redirect(url_for('dashboard'))
            
        except Exception as e:
            logger.error(f"Login error: {e}")
            flash('An error occurred. Please try again.', 'danger')
            return render_template('login.html', is_logged_in=is_logged_in())
        
    return render_template('login.html', is_logged_in=is_logged_in())

# Logout route
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('username', None)
    session.pop('email', None)
    flash('You have been logged out successfully.', 'success')
    return redirect(url_for('index'))

# Dashboard Page
@app.route('/dashboard')
@login_required
def dashboard():
    try:
        # Get user's medicines
        response = medicines_table.scan(
            FilterExpression=Attr('user_id').eq(session['user_id'])
        )
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
    except Exception as e:
        logger.error(f"Dashboard error: {e}")
        flash('An error occurred loading the dashboard.', 'danger')
        return render_template('dashboard.html', 
                              medicines=[], 
                              stats={},
                              is_logged_in=is_logged_in())

# Medicines List Page
@app.route('/medicines')
@login_required
def medicines():
    try:
        # Get user's medicines from DynamoDB
        response = medicines_table.scan(
            FilterExpression=Attr('user_id').eq(session['user_id'])
        )
        medicines_list = response.get('Items', [])
        
        # Sort medicines by name
        medicines_list.sort(key=lambda x: x.get('name', ''))
        
        return render_template('medicines.html', 
                              medicines=medicines_list, 
                              is_logged_in=is_logged_in())
    except Exception as e:
        logger.error(f"Error fetching medicines: {e}")
        flash('An error occurred loading medicines.', 'danger')
        return render_template('medicines.html', 
                              medicines=[], 
                              is_logged_in=is_logged_in())

# Add Medicine Page
@app.route('/medicines/add', methods=['GET', 'POST'])
@login_required
def add_medicine():
    if request.method == 'POST':
        # Form validation
        required_fields = ['name', 'category', 'quantity', 'threshold', 'expiration_date']
        for field in required_fields:
            if field not in request.form or not request.form[field]:
                flash(f'Please fill in the {field} field', 'danger')
                return render_template('add_medicine.html', is_logged_in=is_logged_in())
        
        name = request.form['name']
        category = request.form['category']
        quantity = request.form['quantity']
        threshold = request.form['threshold']
        expiration_date = request.form['expiration_date']
        
        try:
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
                    'created_at': datetime.now().isoformat()
                }
            )
            
            # Check if stock is low immediately after adding
            if int(quantity) <= int(threshold):
                send_low_stock_alert(name, int(quantity), int(threshold), session.get('email'))
            
            flash(f"Medicine '{name}' added successfully!", 'success')
            return redirect(url_for('medicines'))
            
        except Exception as e:
            logger.error(f"Error adding medicine: {e}")
            flash('An error occurred while adding the medicine. Please try again.', 'danger')
            return render_template('add_medicine.html', is_logged_in=is_logged_in())
        
    return render_template('add_medicine.html', is_logged_in=is_logged_in())

# Edit Medicine Page
@app.route('/medicines/edit/<medicine_id>', methods=['GET', 'POST'])
@login_required
def update_medicine(medicine_id):
    try:
        # Get medicine details from DynamoDB
        response = medicines_table.get_item(Key={'medicine_id': medicine_id})
        medicine = response.get('Item')
        
        if not medicine:
            flash('Medicine not found!', 'danger')
            return redirect(url_for('medicines'))
        
        # Security check - verify the logged-in user owns this medicine
        if medicine.get('user_id') != session['user_id']:
            flash('You are not authorized to edit this medicine.', 'danger')
            return redirect(url_for('medicines'))
        
        if request.method == 'POST':
            # Form validation
            required_fields = ['name', 'category', 'quantity', 'threshold', 'expiration_date']
            for field in required_fields:
                if field not in request.form or not request.form[field]:
                    flash(f'Please fill in the {field} field', 'danger')
                    return render_template('edit_medicine.html', 
                                          medicine=medicine, 
                                          is_logged_in=is_logged_in())
            
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
                        ':upd': datetime.now().isoformat()
                    }
                )

                # Check if stock is low after update
                if new_quantity <= new_threshold:
                    send_low_stock_alert(name, new_quantity, new_threshold, session.get('email'))

                flash(f"Medicine '{name}' updated successfully!", 'success')
                
            except medicines_table.meta.client.exceptions.ConditionalCheckFailedException:
                flash('Medicine not found. Update failed.', 'danger')
            except Exception as e:
                logger.error(f"Error updating medicine: {e}")
                flash(f"Error updating medicine: {str(e)}", 'danger')
            
            return redirect(url_for('medicines'))
            
        return render_template('edit_medicine.html', 
                              medicine=medicine, 
                              is_logged_in=is_logged_in())
    except Exception as e:
        logger.error(f"Error in update_medicine: {e}")
        flash('An error occurred. Please try again.', 'danger')
        return redirect(url_for('medicines'))

# Delete Medicine Route
@app.route('/medicines/delete/<medicine_id>', methods=['POST'])
@login_required
def delete_medicine(medicine_id):
    try:
        # Get medicine details before deletion
        response = medicines_table.get_item(Key={'medicine_id': medicine_id})
        medicine = response.get('Item')
        
        if not medicine:
            flash('Medicine not found.', 'danger')
            return redirect(url_for('medicines'))
        
        # Security check - verify the logged-in user owns this medicine
        if medicine.get('user_id') != session['user_id']:
            flash('You are not authorized to delete this medicine.', 'danger')
            return redirect(url_for('medicines'))
        
        # Delete medicine from DynamoDB
        medicines_table.delete_item(Key={'medicine_id': medicine_id})
        
        flash(f"Medicine '{medicine['name']}' deleted successfully.", 'success')
    except Exception as e:
        logger.error(f"Error deleting medicine: {e}")
        flash('An error occurred while deleting the medicine.', 'danger')
    
    return redirect(url_for('medicines'))

# User Profile Page
@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    try:
        # Get user details from DynamoDB
        response = users_table.get_item(Key={'user_id': session['user_id']})
        user = response.get('Item', {})
        
        if request.method == 'POST':
            # Update user profile
            username = request.form.get('username')
            email = request.form.get('email')
            
            if not username or not email:
                flash('All fields are required.', 'danger')
                return render_template('profile.html', 
                                      user=user,
                                      is_logged_in=is_logged_in())
            
            try:
                # Update user info in DynamoDB
                users_table.update_item(
                    Key={'user_id': session['user_id']},
                    UpdateExpression="SET username = :name, email = :email, updated_at = :upd",
                    ExpressionAttributeValues={
                        ':name': username,
                        ':email': email,
                        ':upd': datetime.now().isoformat()
                    }
                )

                # Update session
                session['username'] = username
                session['email'] = email
                
                flash('Profile updated successfully!', 'success')
                return redirect(url_for('profile'))

            except Exception as e:
                logger.error(f"Error updating profile: {e}")
                flash('An error occurred while updating your profile.', 'danger')
        
        # Get user's medicines count
        medicines_response = medicines_table.scan(
            FilterExpression=Attr('user_id').eq(session['user_id'])
        )
        medicines_count = len(medicines_response.get('Items', []))
        
        return render_template('profile.html', 
                              user=user, 
                              medicines_count=medicines_count,
                              is_logged_in=is_logged_in())
    except Exception as e:
        logger.error(f"Profile error: {e}")
        flash('An error occurred. Please try again.', 'danger')
        return redirect(url_for('dashboard'))

# Change Password Route
@app.route('/change-password', methods=['POST'])
@login_required
def change_password():
    current_password = request.form.get('current_password')
    new_password = request.form.get('new_password')
    confirm_password = request.form.get('confirm_password')
    
    # Validation
    if not current_password or not new_password or not confirm_password:
        flash('All password fields are required.', 'danger')
        return redirect(url_for('profile'))
    
    if new_password != confirm_password:
        flash('New passwords do not match.', 'danger')
        return redirect(url_for('profile'))
    
    try:
        # Get user from database
        response = users_table.get_item(Key={'user_id': session['user_id']})
        user = response.get('Item')
        
        if not user:
            flash('User not found.', 'danger')
            return redirect(url_for('profile'))
        
        # Verify current password
        if not check_password_hash(user['password'], current_password):
            flash('Current password is incorrect.', 'danger')
            return redirect(url_for('profile'))
        
        # Update password
        hashed_password = generate_password_hash(new_password)
        users_table.update_item(
            Key={'user_id': session['user_id']},
            UpdateExpression="SET password = :pwd, updated_at = :upd",
            ExpressionAttributeValues={
                ':pwd': hashed_password,
                ':upd': datetime.now().isoformat()
            }
        )
        
        flash('Password changed successfully!', 'success')
    except Exception as e:
        logger.error(f"Password change error: {e}")
        flash('An error occurred while changing your password.', 'danger')
    
    return redirect(url_for('profile'))

# Search functionality for medicines
@app.route('/search_medicines', methods=['GET', 'POST'])
@login_required
def search_medicines():
    if request.method == 'POST':
        search_term = request.form.get('search_term', '').strip()
        
        if not search_term:
            flash('Please enter a search term.', 'info')
            return redirect(url_for('medicines'))
        
        try:
            # Search medicines by name or category
            response = medicines_table.scan(
                FilterExpression=Attr('user_id').eq(session['user_id']) & (
                    Attr('name').contains(search_term) | 
                    Attr('category').contains(search_term)
                )
            )
            
            medicines_list = response.get('Items', [])
            medicines_list.sort(key=lambda x: x.get('name', ''))
            
            return render_template('medicines.html', 
                                  medicines=medicines_list, 
                                  search_term=search_term,
                                  is_logged_in=is_logged_in())
        except Exception as e:
            logger.error(f"Search failed: {e}")
            flash('Search failed. Please try again.', 'danger')
    
    return redirect(url_for('medicines'))

@app.route('/alerts')
@login_required
def alerts():
    response = medicines_table.scan(
        FilterExpression=Attr('user_id').eq(session['user_id'])
    )
    medicines = response.get('Items', [])

    low_stock = [
        m for m in medicines
        if int(m.get('quantity', 0)) <= int(m.get('threshold', 0))
    ]

    expiring_soon = []
    today = datetime.now()

    for m in medicines:
        if 'expiry_date' in m:
            try:
                expiry = datetime.strptime(m['expiry_date'], '%Y-%m-%d')
                if 0 <= (expiry - today).days <= 30:
                    expiring_soon.append(m)
            except:
                pass

    return render_template(
        'alerts.html',
        low_stock=low_stock,
        expiring_soon=expiring_soon,
        is_logged_in=is_logged_in()
    )

# Test SNS Route (for debugging - remove in production)
@app.route('/test-sns')
@login_required
def test_sns():
    send_low_stock_alert("TEST MEDICINE", 2, 10, session.get('email'))
    flash('Test alert sent! Check your email and SNS subscriptions.', 'info')
    return redirect(url_for('dashboard'))

# Health check endpoint for AWS load balancers
@app.route('/health')
def health():
    return {'status': 'healthy', 'timestamp': datetime.now().isoformat()}, 200

# Error handlers
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html', is_logged_in=is_logged_in()), 404

@app.errorhandler(500)
def server_error(e):
    logger.error(f"Server error: {e}")
    return render_template('500.html', is_logged_in=is_logged_in()), 500

# ---------------------------------------
# Run the Flask app
# ---------------------------------------
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    debug_mode = os.environ.get('FLASK_ENV') == 'development'
    app.run(host='0.0.0.0', port=port, debug=debug_mode)

