#!/bin/bash

# Check if Python 3 is installed
if ! command -v python3 &> /dev/null; then
    echo "Error: Python 3 is required but not installed."
    exit 1
fi

# Create virtual environment
echo "Creating virtual environment..."
python3 -m venv venv

# Activate virtual environment
source venv/bin/activate

# Upgrade pip
echo "Upgrading pip..."
pip install --upgrade pip

# No external dependencies required
echo "No external Python dependencies required."

# Verify Python version
echo "Verifying Python version..."
python --version

# Deactivate virtual environment
deactivate

echo "Setup complete! To use DataSift, activate the virtual environment with:"
echo "source venv/bin/activate"
echo "Then run: python datasift.py --help"