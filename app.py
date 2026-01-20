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
print("AWS_REGION =", AWS_REGION)
print("USERS TABLE =", DYNAMODB_TABLE_USERS)

SNS_TOPIC_ARN = "arn:aws:sns:ap-south-1:120121146931:MediStockAlertsNew"
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
# Route: Edit Medicine
from decimal import Decimal

@app.route('/medicines/edit/<medicine_id>', methods=['GET', 'POST'])
@login_required
def edit_medicine(medicine_id):
    if request.method == 'POST':
        try:
            response = medicines_table.get_item(Key={'medicine_id': medicine_id})
            medicine = response.get('Item')

            if not medicine:
                flash('Medicine not found!', 'danger')
                return redirect(url_for('medicines'))

            old_quantity = int(medicine.get('quantity', 0))
            new_quantity = int(request.form.get('quantity'))
            threshold = int(request.form.get('threshold'))

            medicines_table.update_item(
                Key={'medicine_id': medicine_id},
                UpdateExpression="""
                    SET #n=:n, #c=:c, #q=:q, #t=:t, #ua=:ua
                """,
                ExpressionAttributeNames={
                    '#n': 'name',
                    '#c': 'category',
                    '#q': 'quantity',
                    '#t': 'threshold',
                    '#ua': 'updated_at'
                },
                ExpressionAttributeValues={
                    ':n': request.form.get('name'),
                    ':c': request.form.get('category'),
                    ':q': new_quantity,
                    ':t': threshold,
                    ':ua': datetime.now().isoformat()
                }
            )

            # 🔔 Low stock alert
            if new_quantity <= threshold:
                send_low_stock_alert(
                    request.form.get('name'),
                    new_quantity,
                    threshold
                )

            flash('Medicine updated successfully!', 'success')
            return redirect(url_for('medicines'))

        except Exception as e:
            flash(f'Error updating medicine: {str(e)}', 'danger')
            return redirect(url_for('edit_medicine', medicine_id=medicine_id))

    # GET request
    response = medicines_table.get_item(Key={'medicine_id': medicine_id})
    medicine = response.get('Item')

    if not medicine:
        flash('Medicine not found!', 'danger')
        return redirect(url_for('medicines'))

    return render_template('edit_medicine.html', medicine=medicine)
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
        return jsonify({
            'success': True, 
            'message': 'Stock updated successfully',
            'new_quantity': new_quantity
        })
        
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

# Function to send low stock alert via SNS
def send_low_stock_alert(medicine_name, current_stock, threshold):
    if not SNS_TOPIC_ARN:
        print("SNS_TOPIC_ARN is missing")
        return

    try:
        response = sns_client.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject=f'MediStock Alert: Low Stock - {medicine_name}',
            Message=f"""
LOW STOCK ALERT

Medicine: {medicine_name}
Current Stock: {current_stock}
Threshold: {threshold}
Time: {datetime.now()}
"""
        )
        print("SNS publish success:", response)

    except Exception as e:
        print("SNS publish FAILED:", str(e))


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

@app.route('/test-sns')
def test_sns():
    send_low_stock_alert("Paracetamol Test", 2, 10)
    return "SNS test sent"

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)






















