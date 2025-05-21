# 🛡️ ICMP Flood Detection and Endpoint Monitoring System
This repository implements a basic **EDR (Endpoint Detection and Response)** prototype in a simulated cybersecurity lab environment. 
It detects **ICMP flood attacks** from malicious nodes (e.g., Kali Linux) and monitors system metrics from endpoints (e.g., Windows 10). The system uses:

* 🐍 Python + Flask (for backend monitoring and alert dashboard)
* 📡 Scapy (for ICMP sniffing)
* 🔒 iptables (for blocking attackers)
* 🖥️ psutil (for Windows system monitoring)
* 🌐 A simple web UI for displaying alerts

---

## 📁 Directory Structure

```text
edr_project/
├── alerts.json            # Logs of triggered alerts
├── dashboard.html         # Web dashboard for alert viewing
├── edr_monitor.py         # Main ICMP monitoring and blocking engine
├── edr_web.py             # Flask app for the EDR web interface
├── metrics.json           # Endpoint performance metrics (CPU, RAM)
├── windows_edr_agent.py   # Agent script to monitor Windows metrics
├── EDR-Steps.txt          # Setup commands and procedures used
```

---

## 🧪 Lab Architecture

* **Ubuntu VM (10.0.0.8)** — Acts as the EDR manager, dashboard host, and packet sniffer.
* **Windows 10 VM (192.168.100.10)** — Simulated endpoint, monitored by the agent.
* **Kali Linux VM (10.0.0.13)** — Attacker performing ICMP flood attacks.
* All VMs are on a **bridged network**. Ubuntu bridges traffic between networks using two NICs: `ens33` (external) and `ens37` (host-only).

---

## 🚨 Features

✅ Detect high-rate ICMP traffic (≥ 40 pps)
✅ Log alerts and attacker IPs
✅ Block attacker IPs using `iptables`
✅ Track and store endpoint performance metrics
✅ Display alerts on a web dashboard
✅ Auto-refresh dashboard every 10 seconds

---

## 🚀 Setup Instructions

### 🔧 Ubuntu EDR Manager

1. **Clone or copy all files into a directory**:

```bash
git clone https://github.com/Mohamed-Tarek-MT/Endpoint-Detection-Response.git
cd edr_project
```

2. **Install dependencies (inside a virtual environment)**:

```bash
python3 -m venv edr_env
source edr_env/bin/activate
pip install flask scapy requests
```

3. **Enable IP forwarding and set routing rules**:

```bash
echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward
sudo iptables -t nat -A POSTROUTING -o ens33 -j MASQUERADE
sudo iptables -A FORWARD -i ens33 -o ens37 -m state --state RELATED,ESTABLISHED -j ACCEPT
sudo iptables -A FORWARD -i ens37 -o ens33 -j ACCEPT
```

4. **Run the Flask dashboard**:

```bash
python edr_web.py
```

Visit [http://10.0.0.8:5000](http://10.0.0.8:5000)

5. **Start the traffic monitor**:

```bash
sudo env "PATH=$PATH" "VIRTUAL_ENV=$VIRTUAL_ENV" python edr_monitor.py
```

---

### 💻 Windows Victim Agent

1. **Install Python and `psutil`**.
2. Save and run `windows_edr_agent.py` using:

```bash
pip install psutil requests
python windows_edr_agent.py
```

This sends periodic CPU and memory stats to the EDR dashboard every 30 seconds.

---

### ⚔️ Simulating ICMP Attack (Kali)

1. Confirm route via Ubuntu:

```bash
sudo ip route add 192.168.100.0/24 via 10.0.0.8
```

2. Launch an ICMP flood from Kali:

```bash
sudo nping --icmp -c 200 --rate 50 192.168.100.10
```

You should see alerts and blocking actions logged by the monitor and appear on the dashboard.

---

## ✅ Whitelisting Endpoints

To prevent false blocking of legitimate endpoints like the Windows victim:

In `edr_monitor.py`, add this global variable:

```python
WHITELIST = {"192.168.100.10"}
```

Then modify the IP check in the loop:

```python
if ip in WHITELIST or ip in blocked_ips:
    continue
```

---

## 🔁 Resetting IP Blocks

If an IP was mistakenly blocked and you want to remove it:

```bash
sudo iptables -D INPUT -s <IP> -j DROP
sudo iptables -D FORWARD -s <IP> -j DROP
sudo iptables -D OUTPUT -d <IP> -j DROP
```

Do NOT use `iptables -F` unless you want to flush all firewall rules.

---

## 📊 Sample Alert (alerts.json)

```json
{
  "message": "High ICMP rate: 49 pps",
  "ip": "10.0.0.13",
  "time": "2025-05-21 01:32:39"
}
```

## 📡 Sample Agent Metric (metrics.json)

```json
{
  "cpu": 12.1,
  "memory": 42.6,
  "source_ip": "192.168.100.10",
  "reason": "Agent metrics update",
  "time": "2025-05-21 01:31:23"
}
```

---

## 📌 Notes

* Alerts are limited to last 100 entries.
* Metrics are limited to last 1000 entries.
* Dashboard auto-refreshes every 10 seconds.

---
