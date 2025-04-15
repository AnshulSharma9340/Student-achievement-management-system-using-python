import os
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime
import re


# Create Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your_secret_key')  # Change this in production

# Database configuration
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///achievements.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Configure upload folder
UPLOAD_FOLDER = os.path.join('static', 'uploads')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
ALLOWED_EXTENSIONS = {'pdf', 'png', 'jpg', 'jpeg'}

# Create uploads directory if it doesn't exist
os.makedirs(os.path.join(app.root_path, UPLOAD_FOLDER), exist_ok=True)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    roll_no = db.Column(db.String(20), unique=True, nullable=False)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    certificates = db.relationship('Certificate', backref='user', lazy=True)

class Certificate(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=True)
    filename = db.Column(db.String(100), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        roll_no = request.form['roll_no']
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']

         # ✅ Email format validation using regex
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(email_pattern, email):
            flash('Invalid email format. Please enter a valid email.')
            return redirect(url_for('register'))
        
        # Check if user already exists
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Email already exists!')
            return redirect(url_for('register'))

        existing_roll = User.query.filter_by(roll_no=roll_no).first()
        if existing_roll:
            flash('Roll number already exists!')
            return redirect(url_for('register'))

        # Create new user
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(roll_no=roll_no, name=name, email=email, password=hashed_password)

        try:
            db.session.add(new_user)
            db.session.commit()
            flash('Registration successful! Please login.')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            flash('An error occurred during registration.')
            return redirect(url_for('register'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        # Check if user exists
        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['user_name'] = user.name
            session['is_admin'] = user.is_admin

            if user.is_admin:
                return redirect(url_for('admin_dashboard'))
            else:
                return redirect(url_for('dashboard'))
        else:
            flash('Login unsuccessful. Please check email and password.')

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    user = User.query.get(user_id)
    certificates = Certificate.query.filter_by(user_id=user_id).all()

    return render_template('dashboard.html', user=user, certificates=certificates)

@app.route('/upload_certificate', methods=['GET', 'POST'])
def upload_certificate():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        file = request.files['certificate']

        if file and allowed_file(file.filename):
            # Secure and save the file
            filename = secure_filename(file.filename)
            # Add timestamp to filename to prevent duplicates
            timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
            filename = f"{timestamp}_{filename}"
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)

            # Ensure directory exists
            os.makedirs(os.path.dirname(file_path), exist_ok=True)

            # Save the file
            file.save(os.path.join(app.root_path, file_path))

            # Create certificate record
            new_certificate = Certificate(
                title=title,
                description=description,
                filename=filename,
                user_id=session['user_id']
            )

            try:
                db.session.add(new_certificate)
                db.session.commit()
                flash('Certificate uploaded successfully!')
                return redirect(url_for('dashboard'))
            except Exception as e:
                db.session.rollback()
                flash('An error occurred during upload.')
                return redirect(url_for('upload_certificate'))
        else:
            flash('Invalid file format. Allowed formats are PDF, PNG, JPG, JPEG.')

    return render_template('upload_certificate.html')

@app.route('/admin_dashboard')
def admin_dashboard():
    if 'user_id' not in session or not session.get('is_admin', False):
        return redirect(url_for('login'))

    users = User.query.filter_by(is_admin=False).all()
    certificates = Certificate.query.all()

    return render_template('admin_dashboard.html', users=users, certificates=certificates)

@app.route('/admin/certificates/<int:user_id>')
def admin_view_user_certificates(user_id):
    if 'user_id' not in session or not session.get('is_admin', False):
        return redirect(url_for('login'))

    user = User.query.get_or_404(user_id)
    certificates = Certificate.query.filter_by(user_id=user_id).all()

    return render_template('admin_user_certificates.html', user=user, certificates=certificates)

@app.route('/view_certificate/<int:certificate_id>')
def view_certificate(certificate_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    certificate = Certificate.query.get_or_404(certificate_id)
    # Ensure that only admins or the certificate owner can view it
    if not session.get('is_admin', False) and certificate.user_id != session['user_id']:
        flash('You do not have permission to view this certificate.')
        return redirect(url_for('dashboard'))

    return render_template('view_certificate.html', certificate=certificate)

@app.route('/create_admin', methods=['GET', 'POST'])
def create_admin():
    # Check if there's already an admin
    admin_exists = User.query.filter_by(is_admin=True).first()

    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']

        # Check if user already exists
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Email already exists!')
            return redirect(url_for('create_admin'))

        # Create new admin user
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_admin = User(
            roll_no='ADMIN',
            name=name,
            email=email,
            password=hashed_password,
            is_admin=True
        )

        try:
            db.session.add(new_admin)
            db.session.commit()
            flash('Admin created successfully! Please login.')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            flash('An error occurred during admin creation.')
            return redirect(url_for('create_admin'))

    return render_template('create_admin.html', admin_exists=admin_exists)

# Create database tables if they don't exist
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
