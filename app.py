from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
import boto3
from boto3.dynamodb.conditions import Key, Attr
from decimal import Decimal
from datetime import datetime, timedelta
import os
from functools import wraps
import uuid

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'your-secret-key-change-in-production')

# AWS Configuration
AWS_REGION = os.environ.get('AWS_REGION', 'ap-south-1')
DYNAMODB_TABLE_MEDICINES = os.environ.get('DYNAMODB_TABLE_MEDICINES', 'MediStock_Medicines')
DYNAMODB_TABLE_USERS = os.environ.get('DYNAMODB_TABLE_USERS', 'MediStock_Users')
SNS_TOPIC_ARN = os.environ.get('SNS_TOPIC_ARN', '')

# Initialize AWS clients
dynamodb = boto3.resource('dynamodb', region_name=AWS_REGION)
sns_client = boto3.client('sns', region_name=AWS_REGION)

# DynamoDB tables
medicines_table = dynamodb.Table(DYNAMODB_TABLE_MEDICINES)
users_table = dynamodb.Table(DYNAMODB_TABLE_USERS)

# Helper function to convert float to Decimal for DynamoDB
def float_to_decimal(obj):
    if isinstance(obj, float):
        return Decimal(str(obj))
    elif isinstance(obj, dict):
        return {k: float_to_decimal(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [float_to_decimal(i) for i in obj]
    return obj

# Decorator for login required
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Route: Home/Landing Page
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

# Route: Signup
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        role = request.form.get('role', 'staff')  # admin or staff
        
        # Validation
        if not all([username, email, password, confirm_password]):
            flash('All fields are required!', 'danger')
            return redirect(url_for('signup'))
        
        if password != confirm_password:
            flash('Passwords do not match!', 'danger')
            return redirect(url_for('signup'))
        
        if len(password) < 6:
            flash('Password must be at least 6 characters long!', 'danger')
            return redirect(url_for('signup'))
        
        try:
            # Check if user already exists
            response = users_table.query(
                IndexName='email-index',
                KeyConditionExpression=Key('email').eq(email)
            )
            
            if response['Items']:
                flash('Email already registered!', 'danger')
                return redirect(url_for('signup'))
            
            # Create new user
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
            
            flash('Account created successfully! Please log in.', 'success')
            return redirect(url_for('login'))
            
        except Exception as e:
            flash(f'Error creating account: {str(e)}', 'danger')
            return redirect(url_for('signup'))
    
    return render_template('signup.html')

# Route: Login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        if not email or not password:
            flash('Email and password are required!', 'danger')
            return redirect(url_for('login'))
        
        try:
            # Find user by email
            response = users_table.query(
                IndexName='email-index',
                KeyConditionExpression=Key('email').eq(email)
            )
            
            if not response['Items']:
                flash('Invalid email or password!', 'danger')
                return redirect(url_for('login'))
            
            user = response['Items'][0]
            
            # Verify password
            if check_password_hash(user['password'], password):
                session['user_id'] = user['user_id']
                session['username'] = user['username']
                session['role'] = user['role']
                flash(f'Welcome back, {user["username"]}!', 'success')
                return redirect(url_for('dashboard'))
            else:
                flash('Invalid email or password!', 'danger')
                return redirect(url_for('login'))
                
        except Exception as e:
            flash(f'Login error: {str(e)}', 'danger')
            return redirect(url_for('login'))
    
    return render_template('login.html')

# Route: Logout
@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out successfully.', 'info')
    return redirect(url_for('index'))

# Route: Dashboard
@app.route('/dashboard')
@login_required
def dashboard():
    try:
        # Get all medicines
        response = medicines_table.scan()
        medicines = response['Items']
        
        # Calculate statistics
        total_medicines = len(medicines)
        low_stock_count = sum(1 for m in medicines if int(m.get('quantity', 0)) <= int(m.get('threshold', 0)))
        expired_count = sum(1 for m in medicines if datetime.fromisoformat(m.get('expiration_date', '9999-12-31')) < datetime.now())
        total_value = sum(float(m.get('quantity', 0)) * float(m.get('unit_price', 0)) for m in medicines)
        
        stats = {
            'total_medicines': total_medicines,
            'low_stock': low_stock_count,
            'expired': expired_count,
            'total_value': round(total_value, 2)
        }
        
        # Get recent low stock items
        low_stock_items = [m for m in medicines if int(m.get('quantity', 0)) <= int(m.get('threshold', 0))][:5]
        
        return render_template('dashboard.html', stats=stats, low_stock_items=low_stock_items)
    except Exception as e:
        flash(f'Error loading dashboard: {str(e)}', 'danger')
        return render_template('dashboard.html', stats={}, low_stock_items=[])

# Route: View All Medicines
@app.route('/medicines')
@login_required
def medicines():
    try:
        response = medicines_table.scan()
        medicines_list = response['Items']
        
        # Sort by name
        medicines_list.sort(key=lambda x: x.get('name', ''))
        
        return render_template('medicines.html', medicines=medicines_list)
    except Exception as e:
        flash(f'Error loading medicines: {str(e)}', 'danger')
        return render_template('medicines.html', medicines=[])

# Route: Add Medicine
@app.route('/medicines/add', methods=['GET', 'POST'])
@login_required
def add_medicine():
    if request.method == 'POST':
        try:
            medicine_id = str(uuid.uuid4())
            
            medicine_data = {
                'medicine_id': medicine_id,
                'name': request.form.get('name'),
                'category': request.form.get('category'),
                'quantity': int(request.form.get('quantity')),
                'unit': request.form.get('unit'),
                'threshold': int(request.form.get('threshold')),
                'batch_number': request.form.get('batch_number'),
                'expiration_date': request.form.get('expiration_date'),
                'unit_price': float_to_decimal(float(request.form.get('unit_price', 0))),
                'manufacturer': request.form.get('manufacturer'),
                'description': request.form.get('description', ''),
                'added_by': session['username'],
                'created_at': datetime.now().isoformat(),
                'updated_at': datetime.now().isoformat()
            }
            
            medicines_table.put_item(Item=medicine_data)
            
            flash(f'Medicine "{medicine_data["name"]}" added successfully!', 'success')
            return redirect(url_for('medicines'))
            
        except Exception as e:
            flash(f'Error adding medicine: {str(e)}', 'danger')
            return redirect(url_for('add_medicine'))
    
    return render_template('add_medicine.html')

# Route: Edit Medicine
@app.route('/medicines/edit/<medicine_id>', methods=['GET', 'POST'])
@login_required
def edit_medicine(medicine_id):
    if request.method == 'POST':
        try:
            old_quantity = int(request.form.get('old_quantity', 0))
            new_quantity = int(request.form.get('quantity'))
            threshold = int(request.form.get('threshold'))
            
            medicines_table.update_item(
                Key={'medicine_id': medicine_id},
                UpdateExpression='SET #name=:name, category=:category, quantity=:quantity, unit=:unit, threshold=:threshold, batch_number=:batch, expiration_date=:exp, unit_price=:price, manufacturer=:mfr, description=:desc, updated_at=:updated',
                ExpressionAttributeNames={'#name': 'name'},
                ExpressionAttributeValues={
                    ':name': request.form.get('name'),
                    ':category': request.form.get('category'),
                    ':quantity': new_quantity,
                    ':unit': request.form.get('unit'),
                    ':threshold': threshold,
                    ':batch': request.form.get('batch_number'),
                    ':exp': request.form.get('expiration_date'),
                    ':price': float_to_decimal(float(request.form.get('unit_price', 0))),
                    ':mfr': request.form.get('manufacturer'),
                    ':desc': request.form.get('description', ''),
                    ':updated': datetime.now().isoformat()
                }
            )
            
            # Check if stock falls below threshold
            if new_quantity <= threshold and old_quantity > threshold:
                send_low_stock_alert(request.form.get('name'), new_quantity, threshold)
            
            flash('Medicine updated successfully!', 'success')
            return redirect(url_for('medicines'))
            
        except Exception as e:
            flash(f'Error updating medicine: {str(e)}', 'danger')
            return redirect(url_for('edit_medicine', medicine_id=medicine_id))
    
    try:
        response = medicines_table.get_item(Key={'medicine_id': medicine_id})
        medicine = response.get('Item')
        
        if not medicine:
            flash('Medicine not found!', 'danger')
            return redirect(url_for('medicines'))
        
        return render_template('edit_medicine.html', medicine=medicine)
    except Exception as e:
        flash(f'Error loading medicine: {str(e)}', 'danger')
        return redirect(url_for('medicines'))

# Route: Delete Medicine
@app.route('/medicines/delete/<medicine_id>', methods=['POST'])
@login_required
def delete_medicine(medicine_id):
    try:
        response = medicines_table.get_item(Key={'medicine_id': medicine_id})
        medicine = response.get('Item')
        
        if medicine:
            medicines_table.delete_item(Key={'medicine_id': medicine_id})
            flash(f'Medicine "{medicine["name"]}" deleted successfully!', 'success')
        else:
            flash('Medicine not found!', 'danger')
            
    except Exception as e:
        flash(f'Error deleting medicine: {str(e)}', 'danger')
    
    return redirect(url_for('medicines'))

# Route: Low Stock Alert Page
@app.route('/alerts')
@login_required
def alerts():
    try:
        response = medicines_table.scan()
        all_medicines = response['Items']
        
        # Filter low stock items
        low_stock_medicines = [
            m for m in all_medicines 
            if int(m.get('quantity', 0)) <= int(m.get('threshold', 0))
        ]
        
        # Filter expiring soon (within 30 days)
        expiring_soon = [
            m for m in all_medicines
            if datetime.fromisoformat(m.get('expiration_date', '9999-12-31')) < datetime.now() + timedelta(days=30)
            and datetime.fromisoformat(m.get('expiration_date', '9999-12-31')) >= datetime.now()
        ]
        
        return render_template('alerts.html', 
                             low_stock=low_stock_medicines,
                             expiring_soon=expiring_soon)
    except Exception as e:
        flash(f'Error loading alerts: {str(e)}', 'danger')
        return render_template('alerts.html', low_stock=[], expiring_soon=[])

# Route: Update Stock (Quick Update)
@app.route('/medicines/update-stock/<medicine_id>', methods=['POST'])
@login_required
def update_stock(medicine_id):
    try:
        quantity_change = int(request.form.get('quantity_change', 0))
        action = request.form.get('action')  # 'add' or 'remove'
        
        # Get current medicine data
        response = medicines_table.get_item(Key={'medicine_id': medicine_id})
        medicine = response.get('Item')
        
        if not medicine:
            return jsonify({'success': False, 'message': 'Medicine not found'})
        
        current_quantity = int(medicine['quantity'])
        threshold = int(medicine['threshold'])
        
        # Calculate new quantity
        if action == 'add':
            new_quantity = current_quantity + quantity_change
        else:
            new_quantity = max(0, current_quantity - quantity_change)
        
        # Update quantity
        medicines_table.update_item(
            Key={'medicine_id': medicine_id},
            UpdateExpression='SET quantity=:quantity, updated_at=:updated',
            ExpressionAttributeValues={
                ':quantity': new_quantity,
                ':updated': datetime.now().isoformat()
            }
        )
        
        # Send alert if stock falls below threshold
        if new_quantity <= threshold and current_quantity > threshold:
            send_low_stock_alert(medicine['name'], new_quantity, threshold)
        
        return jsonify({
            'success': True, 
            'message': 'Stock updated successfully',
            'new_quantity': new_quantity
        })
        
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

# Function to send low stock alert via SNS
def send_low_stock_alert(medicine_name, current_stock, threshold):
    try:
        if SNS_TOPIC_ARN:
            message = f"""
MEDISTOCK ALERT: Low Stock Warning

Medicine: {medicine_name}
Current Stock: {current_stock}
Threshold: {threshold}
Status: CRITICAL - Immediate restocking required

Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

Please take immediate action to replenish this medicine.
            """
            
            sns_client.publish(
                TopicArn=SNS_TOPIC_ARN,
                Subject=f'MediStock Alert: Low Stock - {medicine_name}',
                Message=message
            )
    except Exception as e:
        print(f'Error sending SNS alert: {str(e)}')

# Route: Reports
@app.route('/reports')
@login_required
def reports():
    try:
        response = medicines_table.scan()
        medicines = response['Items']
        
        # Category-wise distribution
        category_stats = {}
        for med in medicines:
            cat = med.get('category', 'Uncategorized')
            if cat not in category_stats:
                category_stats[cat] = {'count': 0, 'total_value': 0}
            category_stats[cat]['count'] += 1
            category_stats[cat]['total_value'] += float(med.get('quantity', 0)) * float(med.get('unit_price', 0))
        
        return render_template('reports.html', 
                             medicines=medicines,
                             category_stats=category_stats)
    except Exception as e:
        flash(f'Error generating reports: {str(e)}', 'danger')
        return render_template('reports.html', medicines=[], category_stats={})

# Error handlers
@app.errorhandler(404)
def not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def server_error(e):
    return render_template('500.html'), 500

if __name__ == '__main__':

    app.run(host='0.0.0.0', port=5000, debug=True)
