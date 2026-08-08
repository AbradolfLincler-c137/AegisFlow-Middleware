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

## 🌍 Zero-Code Deployment Architecture ("The 3 Warrior Methods")

To deploy AegisFlow without touching a single line of customer application code, position the product at the **network perimeter or infrastructure layer**.

### Strategy Comparison Matrix

| **Deployment Method**            | **Setup Time** | **Code Changes** | **Platform Compatibility**          | **Execution Level**  |
| -------------------------------- | -------------- | ---------------- | ----------------------------------- | -------------------- |
| **1. CNAME / DNS Reverse Proxy** | **< 5 Mins**   | **0 Lines**      | 100% (AWS, Wix, Shopify, WordPress) | Network / DNS Level  |
| **2. NGINX / Container Sidecar** | **< 10 Mins**  | **0 Lines**      | Docker, K8s, Bare-Metal EC2         | Infrastructure Level |
| **3. CDN Edge Worker**           | **< 5 Mins**   | **0 Lines**      | Cloudflare, AWS CloudFront          | CDN / Edge Level     |

### Detailed Breakdown of the 3 Methods

#### Method 1: CNAME / DNS Reverse Proxy (The Perimeter Shield)
- **Mechanism**: Customer updates their domain's DNS `A` or `CNAME` record to route traffic through AegisFlow before reaching their web host.
- **Flow**:
    1. User requests `https://customer-app.com`.
    2. DNS routes request to `proxy.aegisflow.io`.
    3. AegisFlow Node.js middleware + Python ML engine inspects the request in sub-10ms.
    4. Malicious requests are dropped instantly (`403 Forbidden`).
    5. Clean requests are forwarded to the real origin server IP (AWS EC2, Wix, Shopify, GCP).
- **Pitch to Judges**: *"Zero developer time required. Swap DNS records, and AegisFlow shields any website on any platform."*

#### Method 2: NGINX / Container Sidecar (The Infrastructure Shield)
- **Mechanism**: AegisFlow runs inside a Docker container sitting directly in front of the application container on the customer's server or Kubernetes cluster.
- **Flow**:
    1. NGINX or Docker receives incoming traffic on port `80/443`.
    2. Passes incoming payloads to the AegisFlow container on port `3000`.
    3. AegisFlow inspects the traffic and proxies valid calls to the internal app port (e.g., `localhost:8080`).
- **Pitch to Judges**: *"For enterprise clients hosting on AWS or Kubernetes, AegisFlow drops in as a Docker sidecar container with zero backend refactoring."*

#### Method 3: CDN Edge Worker Interceptor (The Cloud Shield)
- **Mechanism**: Deployed as a lightweight script on Cloudflare Workers or AWS Lambda@Edge.
- **Flow**:
    1. Requests hit the CDN edge node closest to the end user.
    2. The Worker forwards request metadata to the AegisFlow ML endpoint.
    3. If blocked (`threat_score > 0.7`), the edge node halts execution immediately before traffic reaches the customer's origin datacenter.
- **Pitch to Judges**: *"Edge-level threat neutralization stops DDoS and injection vectors before they consume origin bandwidth or compute costs."*

### Zero-Code Reverse Proxy Roadmap

```text
                                [ END USER / ATTACKER ]
                                           │
                                           ▼
                            [ 1. DNS / CNAME Routing ]
                                           │
                                           ▼
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                          AEGISFLOW SECURITY GATEWAY                                    │
│                                                                                        │
│   ┌───────────────────────────────────┐    Telemetry    ┌──────────────────────────┐   │
│   │ Node.js Reverse Proxy Middleware  │ ──────────────> │ Python ML Threat Engine  │   │
│   │ (http-proxy-middleware)           │ <────────────── │ (Scikit-Learn Model)     │   │
│   └─────────────────┬─────────────────┘   Threat Score  └──────────────────────────┘   │
│                     │                                                                  │
└─────────────────────┼──────────────────────────────────────────────────────────────────┘
                      │
        ┌─────────────┴─────────────┐
        │                           │
  (Threat Score > 0.7)        (Threat Score <= 0.7)
        │                           │
        ▼                           ▼
[ 403 Forbidden Block ]    [ Forward Clean Request ]
                            ├── AWS EC2 / S3
                            ├── Wix / Shopify
                            └── Custom Backend API
```
