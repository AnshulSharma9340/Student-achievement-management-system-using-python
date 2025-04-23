# Student Achievements Management System

A web application built with Flask that allows students to sign up, upload their certificates with their roll numbers, and provides an admin panel to access all certificates with student details.

## Features

- **Student Registration**: Students can sign up with their roll numbers and personal details
- **Certificate Management**: Students can upload and manage their certificates in PDF, PNG, JPG formats
- **Admin Panel**: Administrators can manage users and view all certificates
- **Secure Authentication**: Password hashing and session management
- **Responsive Design**: Mobile-friendly interface with Bootstrap

## Technologies Used

- **Backend**: Python 3, Flask
- **Database**: SQLite with SQLAlchemy ORM
- **Frontend**: HTML, CSS, Bootstrap 5
- **Authentication**: Werkzeug security for password hashing
- **File Handling**: Secure file uploads with Werkzeug

## Installation and Setup

1. Clone the repository
2. Navigate to the project directory
3. Create a virtual environment:
   ```
   python -m venv venv
   ```

4. Activate the virtual environment:
   - On Windows:
     ```
     venv\Scripts\activate
     ```
   - On macOS and Linux:
     ```
     source venv/bin/activate
     ```

5. Install the dependencies:
   ```
   pip install -r requirements.txt
   ```

6. Run the application:
   ```
   python app.py
   ```

7. Open a web browser and navigate to `http://localhost:5000`

## Usage

### For Students

1. Register with your roll number, name, email, and password
2. Log in with your email and password
3. Upload certificates from your dashboard
4. View and manage your uploaded certificates

### For Administrators

1. Create an admin account from the login page (there can only be one admin account)
2. Log in with your admin credentials
3. View all registered students and their certificates
4. Access student details and download certificates

## Project Structure

- `app.py`: Main Flask application with routes and database setup
- `templates/`: HTML templates
- `static/`: CSS, JavaScript, and uploaded certificates
- `instance/`: Contains the SQLite database file

## Security Considerations

- Passwords are securely hashed using Werkzeug's security functions
- File uploads are secured with proper validation and filename sanitization
- Session management to ensure authenticated access
- Certificate access permissions to protect student privacy


