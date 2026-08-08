# AegisFlow WAF & Threat Intelligence Dashboard 🛡️

AegisFlow is a robust, real-time Web Application Firewall (WAF) and Threat Intelligence Dashboard. It acts as an active reverse-proxy shield that sits in front of vulnerable applications, inspecting incoming payloads for malicious content, enforcing rate limits, and securing a hash-chained audit log of all traffic.

## 🏗️ Architecture

AegisFlow utilizes a dual-engine architecture, combining fast deterministic RegEx heuristics with a Python-based Machine Learning inference model (trained on the CSIC-2010 Web Application Attacks dataset).

1. **WAF Gateway (Port 3000)**: 
   - Intercepts all traffic. 
   - Analyzes payloads (URL parameters, headers, JSON bodies).
   - Blocks malicious requests (returns `403 Forbidden`).
   - Rate limits excessive traffic (returns `429 Too Many Requests`).
   - Proxies clean traffic to the target application.
2. **Target Application (Port 4000)**: 
   - A vulnerable test application (`VaultStore`) running completely exposed.
   - AegisFlow sits in front of it to provide the necessary security layer.
3. **Dashboard UI**:
   - Served on `http://localhost:3000/store` (and `/aegisflow/dashboard`).
   - Provides real-time geospatial telemetry, threat categorization, live feeds, and data-leak monitoring.
4. **Immutable Audit Logger**:
   - Maintains an in-memory hash chain of every request. 
   - If a log entry is tampered with or deleted, the dashboard's Verify Log Integrity tool will pinpoint the exact `Log ID` where the chain broke.

## 🚀 Getting Started

To run the entire simulated environment, you need three separate terminal windows.

### 1. Start the Target Application (VaultStore)
This runs the vulnerable e-commerce store on **Port 4000**.
```bash
cd aegisflow
npm run store
```

### 2. Start the AegisFlow WAF Gateway & Dashboard
This runs the main WAF middleware on **Port 3000** and proxies clean traffic to Port 4000.
```bash
cd aegisflow
npm start
```
*Wait for the server to spin up, then open `http://localhost:3000/store` in your browser to view the Dashboard.*

### 3. Run the Continuous Threat Simulator
This will simulate high-volume, globally-distributed traffic containing various cyber attacks to test the WAF.
```bash
cd aegisflow/attack-sim
python modern_infinite_attacker.py
```

## ⚔️ Threat Detection Capabilities

AegisFlow is currently capable of detecting and blocking:
- **SQL Injection (SQLi)**
- **Cross-Site Scripting (XSS)**
- **Path Traversal**
- **Command / OS Injection**
- **CRLF Injection**
- **XPath Injection**
- **LDAP Injection & JNDI (Log4Shell)**
- **Server-Side Request Forgery (SSRF)**
- **Prompt Injection (AI LLM bypasses)**
- **Credential Stuffing**
- **Parameter Tampering / NoSQL Injection**
- **Buffer Overflows**
- **DDoS / Rate Flood Attempts**

## 🔧 Managing the WAF
From the UI dashboard, you can:
- **Toggle Protection**: Turn the WAF shield off to see attacks successfully breach the target application in real-time.
- **Verify Log Integrity**: Audit the hash chain to ensure no internal actor has tampered with the security logs.
- **Reset Chain**: Clear the immutable buffer and start fresh.
- **Monitor Leaks**: Watch the live exfiltration feed to see exactly what data attackers are extracting when the WAF is disabled.
