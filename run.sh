#!/bin/bash

# Check if virtual environment exists, if not create it
if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv venv
fi

# Activate virtual environment
source venv/bin/activate

# Install requirements
echo "Installing dependencies..."
pip install -r requirements.txt

# Create uploads directory if it doesn't exist
mkdir -p static/uploads

# Run the Flask application
echo "Starting the application..."
python app.py

# Deactivate virtual environment on exit
deactivate
