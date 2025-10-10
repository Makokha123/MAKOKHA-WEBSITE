#!/usr/bin/env python3
"""
Setup script for Makokha Medical Centre - Local Development
"""

import os
import sys
import subprocess

def run_command(command, description):
    print(f"\n🔧 {description}...")
    try:
        subprocess.run(command, shell=True, check=True)
        print(f"✅ {description} completed successfully!")
    except subprocess.CalledProcessError as e:
        print(f"❌ {description} failed: {e}")
        sys.exit(1)

def main():
    print("🚀 Setting up Makokha Medical Centre - Local Development")
    
    # Create virtual environment
    if not os.path.exists('venv'):
        run_command('python -m venv venv', 'Creating virtual environment')
    
    # Activate virtual environment and install dependencies
    if os.name == 'nt':  # Windows
        pip_cmd = 'venv\\Scripts\\pip'
        python_cmd = 'venv\\Scripts\\python'
    else:  # Linux/Mac
        pip_cmd = 'venv/bin/pip'
        python_cmd = 'venv/bin/python'
    
    run_command(f'{pip_cmd} install -r backend/requirements.txt', 'Installing dependencies')
    
    # Initialize database
    run_command(f'{python_cmd} -m flask --app backend/run.py init-db', 'Initializing database')
    
    # Create sample data
    run_command(f'{python_cmd} -m flask --app backend/run.py create-sample-data', 'Creating sample data')
    
    print("\n🎉 Setup completed successfully!")
    print("\n📋 Next steps:")
    print("1. Activate virtual environment:")
    if os.name == 'nt':
        print("   venv\\Scripts\\activate")
    else:
        print("   source venv/bin/activate")
    print("2. Run the application:")
    print("   python backend/run.py")
    print("3. Open http://localhost:5000 in your browser")
    print("\n🔐 Default login credentials:")
    print("   Admin: admin@makokha.com / Admin123!")
    print("   Doctor: doctor@makokha.com / Doctor123!")

if __name__ == '__main__':
    main()