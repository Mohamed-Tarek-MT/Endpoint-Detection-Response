import psutil
import requests
import time
import socket

EDR_SERVER = "http://10.0.0.8:5000"  # Ubuntu Manager
hostname = socket.gethostname()
ip = socket.gethostbyname(hostname)

while True:
    try:
        data = {
            "cpu": psutil.cpu_percent(interval=1),
            "memory": psutil.virtual_memory().percent,
	    "source_ip": ip,
            "reason": "Agent metrics update"
        }
        requests.post(EDR_SERVER + "/agent", json=data)
    except Exception as e:
        print("Connection failed:", e)
    time.sleep(30)
