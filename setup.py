import os
import subprocess
import sys
from pathlib import Path

def create_virtualenv():
    try:
        print("Creating virtual environment...")
        subprocess.run([sys.executable, "-m", "venv", "env"], check=True)
        print("Virtual environment created successfully.")
    except subprocess.CalledProcessError as e:
        print(f"Error creating virtual environment: {e}")
        sys.exit(1)

def install_requirements():
    try:
        print("Installing requirements...")
        pip_path = os.path.join("env", "Scripts", "pip") if os.name == "nt" else os.path.join("env", "bin", "pip")
        requirements_file = Path("requirements.txt")
        
        if not requirements_file.exists():
            print("Error: requirements.txt not found!")
            sys.exit(1)
            
        subprocess.run([pip_path, "install", "-r", str(requirements_file)], check=True)
        print("Requirements installed successfully.")
    except subprocess.CalledProcessError as e:
        print(f"Error installing requirements: {e}")
        sys.exit(1)

def run_main():
    try:
        python_path = os.path.join("env", "Scripts", "python") if os.name == "nt" else os.path.join("env", "bin", "python")
        main_file = Path("main.py")
        
        if not main_file.exists():
            print("Error: main.py not found!")
            sys.exit(1)
            
        subprocess.run([python_path, str(main_file)], check=True)
    except subprocess.CalledProcessError as e:
        print(f"Error running main.py: {e}")
        sys.exit(1)

if __name__ == "__main__":
    try:
        if not os.path.exists("env"):
            create_virtualenv()
            install_requirements()
        else:
            print("Virtual environment already exists.")
        run_main()
    except KeyboardInterrupt:
        print("\nSetup interrupted by user.")
        sys.exit(1)
