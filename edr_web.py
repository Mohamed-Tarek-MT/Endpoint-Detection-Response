from flask import Flask, jsonify, request, render_template
import json, os
from datetime import datetime

app = Flask(__name__)
ALERT_FILE = "alerts.json"
AGENT_METRICS_FILE = "metrics.json"

@app.route('/')
def dashboard():
    return render_template("dashboard.html")

@app.route('/alerts')
def get_alerts():
    try:
        if os.path.exists(ALERT_FILE):
            with open(ALERT_FILE, "r") as f:
                data = json.load(f)
        else:
            data = []
    except json.JSONDecodeError:
        data = [{"time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                 "message": "ERROR: Could not parse alerts.json",
                 "ip": "N/A"}]
    return jsonify(data[-100:])

@app.route('/agent', methods=['POST'])
def receive_agent_data():
    content = request.json
    content["time"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Save to metrics.json
    try:
        if os.path.exists(AGENT_METRICS_FILE):
            with open(AGENT_METRICS_FILE, "r") as f:
                metrics_data = json.load(f)
        else:
            metrics_data = []
    except json.JSONDecodeError:
        metrics_data = []

    metrics_data.append(content)
    with open(AGENT_METRICS_FILE, "w") as f:
        json.dump(metrics_data[-1000:], f, indent=4)

    # Save to alerts.json (for dashboard)
    alert_entry = {
        "message": content.get("reason", "Unknown"),
        "ip": content.get("source_ip", "N/A"),
        "time": content["time"]
    }

    try:
        if os.path.exists(ALERT_FILE):
            with open(ALERT_FILE, "r") as f:
                alerts_data = json.load(f)
        else:
            alerts_data = []
    except json.JSONDecodeError:
        alerts_data = []

    alerts_data.append(alert_entry)
    with open(ALERT_FILE, "w") as f:
        json.dump(alerts_data[-100:], f, indent=4)

    return jsonify({"status": "ok"})


if __name__ == '__main__':
    print("Starting Flask EDR Dashboard...")
    app.run(host="10.0.0.8", port=5000)

