import time
import subprocess

while True:
    subprocess.run(["python", "main.py"])
    time.sleep(600)  # 10 minutes
