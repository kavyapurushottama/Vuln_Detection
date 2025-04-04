# test_code/vulnerable.py

import subprocess

# Vulnerable code - Bandit will detect this
user_input = input("Enter: ")
subprocess.call(user_input, shell=True)  # B602 - High Risk
