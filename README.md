# 🛡️ Dynamic Shield WAF for PHP

A lightweight, self-contained, behavior-driven **Web Application Firewall (WAF)** designed to protect PHP applications from common web threats like **SQL Injection (SQLi)** and **Cross-Site Scripting (XSS)**.

Unlike simple signature-based firewalls, Dynamic Shield uses a **multi-layered defense strategy** that includes **risk scoring** and **behavioral analysis** to detect and block sophisticated, automated attacks.

---

## 💡 Core Philosophy
The primary goal of this WAF is not only to block known malicious patterns, but also to **identify malicious intent** by analyzing client behavior over time.  
It’s built to stop the **“low and slow” attacks** that simple firewalls often miss.

---

## ✨ Key Features
- 🛡️ **Multi-Layered Defense**: Immediate blocking of high-risk requests + behavioral analysis for suspicious activities.  
- 💯 **Risk-Scoring Engine**: Assigns risk scores to requests based on customizable attack patterns.  
- 🤖 **Behavioral Analysis & Temp-Banning**: Tracks suspicious requests per session and blocks bot-like activity (e.g., dictionary attacks).  
- 🎭 **Input Normalization**: Defeats evasion techniques like URL encoding & comment obfuscation.  
- 🔌 **Easy to Integrate**: A single PHP file, drop it in with one line of code.  
- 🔧 **Configurable**: Adjust thresholds, ban duration, and attack patterns to fit your needs.  

---

## ⚙️ How It Works

### Layer 1: ⚡ Immediate Threat Blocking
1. **Normalization**: All `$_REQUEST` inputs (`$_GET`, `$_POST`, `$_COOKIE`) are normalized (URL decoded, comments removed).  
2. **Risk Scoring**: Inputs are checked against regex attack patterns → scores are assigned.  
3. **Decision**: If `total_risk_score >= RISK_THRESHOLD` → the request is **blocked instantly**.  

### Layer 2: 📈 Behavioral Analysis (Suspicion Tracking)
1. If a request is risky but not critical → it's marked as **suspicious**.  
2. A **Suspicion Counter** increments per session for each suspicious request.  
3. A **Time Window** (e.g., `60s`) tracks repeated suspicious behavior.  
4. **Temp-Ban**: If the counter ≥ `SUSPICION_THRESHOLD`, the client is **blocked** for the `BLOCK_DURATION` (e.g., 5 mins).  

✅ This is **highly effective against tools like sqlmap**, which send many slightly varied requests.  

---

## 🚀 Installation & Usage

1. **Download** the `firewall.php` file.  
2. Place it in your PHP project’s root (or any desired directory).  
3. Add this line at the very top of your application's entry point (`index.php`, `router.php`, etc.):  

```php
<?php
// Include and execute the firewall before any other code runs.
require_once 'firewall.php';
```
That's it! Your application is now protected. 🎉

## 🛠️ Configuration
You can customize the firewall's behavior by editing the constants at the top of firewall.php:

**RISK_THRESHOLD**: The score at which a single request is immediately blocked.

**SUSPICION_THRESHOLD**: The number of suspicious requests before a client is temporarily banned.

**TIME_WINDOW**: The time window in seconds for tracking suspicious requests.

**BLOCK_DURATION**: The duration in seconds for which a client is blocked.

## ⚠️ Important Security Notice
A WAF is an essential layer of security, but it is NOT a substitute for secure coding practices. It acts as a shield, not a fix for underlying vulnerabilities.
You should always continue to use:

**Prepared Statements to prevent SQL Injection**
**Proper Output Escaping (e.g., htmlspecialchars) to prevent XSS**

## 📜 License
This project is licensed under the **MIT License**.
