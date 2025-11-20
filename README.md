# 🛡️ Dynamic Shield WAF (v2.0)

A **robust**, class-based, persistence-driven **Web Application Firewall (WAF)** designed to protect PHP applications from advanced threats such as **SQL Injection (SQLi)**, **XSS**, **RCE**, and automated scanners.

Unlike simple signature-based firewalls that rely on PHP Sessions (and can be bypassed by clearing cookies), **Dynamic Shield** uses **IP-based file storage**, **Deep Request Scanning**, and **behavioral analysis** to track, score, and block attackers with high accuracy.

## 💡 Core Philosophy

Dynamic Shield focuses on **identifying malicious intent**, not just keywords.  
It uses a **Deep Scan Engine** that flattens nested arrays and JSON inputs to detect hidden payloads buried inside complex request structures. **No input goes unchecked.**

It's built to stop **"low and slow" attacks** that simple firewalls often miss.

## ✨ Key Features

| Feature                        | Description                                                                                     |
|--------------------------------|-------------------------------------------------------------------------------------------------|
| 🛡️ **IP-Based Persistence**     | Stores attacker data in `waf_storage` JSON files instead of PHP sessions                        |
|                                    | ✔ Survives cookie clearing<br>✔ Blocks curl/python CLI attackers<br>✔ Works across browser restarts |
| 🔍 **Deep Scan Engine**         | Recursively flattens nested arrays and JSON objects to reveal payloads hidden in:              |
|                                    | `comment[body][text]`, `filters[user][input][raw]`, etc.                                        |
| 🧠 **Context-Aware Rules**      | Understands logic breaks and polyglot payloads, including:<br>• `';`<br>• `<details>` HTML5 polyglots<br>• Backticks like: `alertx` |
| 🔐 **Self-Protecting Architecture** | Auto-generates `.htaccess` and dummy `index.php` inside storage folders to prevent public access |
| 🤖 **Behavioral Analysis**      | Tracks suspicious payloads over time. Low-risk anomalies accumulate → temporary ban            |
| 🌐 **Modern API Support**       | Automatically scans `php://input` for JSON payloads (React, Vue, mobile apps, REST APIs)       |
| 🏳️ **Smart Whitelisting**       | Built-in admin whitelist to prevent accidental self-blocking                                   |

## ⚙️ How It Works

### Layer 1 — 📥 Input Normalization & Flattening
- Collects: `$_GET`, `$_POST`, `$_COOKIE`, `php://input`, User-Agent
- Recursively flattens arrays
- Normalizes (lowercase + urldecode)
- Prevents bypasses using array nesting and encoding tricks

### Layer 2 — ⚡ Immediate Threat Blocking (Score-Based)

| Type              | Examples                          | Score | Result          |
|-------------------|-----------------------------------|-------|-----------------|
| Critical Attack   | `UNION SELECT`, `<script>`, `/etc/passwd` | 20+   | Instant Block   |
| High Risk Syntax  | `';`, `onmouseover=`              | 15+   | Instant Block   |

### Layer 3 — 📈 Behavioral Analysis
If risk score is below 15 → increments IP's **Suspicion Counter**.  
Too much "noise" in a short time (e.g., SQLmap fingerprinting) → **temporary ban**.

## 🚀 Installation & Usage

### 1. Create Directory Structure
```php
/public_html/
├── index.php
└── security/
    └── Firewall.php
```
### 2. Integrate the Firewall
Add this at the **very top** of your `index.php` (or any main entry file for protection like post.php):

```php
<?php
// 1. Define the Security Key (Prevents direct access to the firewall file)
define('PREVENT_DIRECT_ACCESS', true);

// 2. Load the Firewall
require_once __DIR__ . '/security/Firewall.php';

// Your application code starts here...
```

### 🛠️ Configuration
Tune behavior via constants in `Firewall.php`:

| Constant              | Default | Description                                             |
|-----------------------|---------|---------------------------------------------------------|
| `RISK_THRESHOLD`      | 15      | Score needed for immediate block                        |
| `SUSPICION_THRESHOLD` | 20      | Cumulative suspicion score for behavioral block         |
| `TIME_WINDOW`         | 60      | Seconds logs/suspicion persist during active monitoring|
| `BLOCK_DURATION`      | 300     | Ban duration in seconds (5 minutes default)            |

### 📂 Logs & Storage

The firewall automatically creates the `waf_storage/` directory inside `/security/`:

| File                  | Purpose                                                  |
|-----------------------|----------------------------------------------------------|
| `blocked_ips.json`    | Stores currently banned IPs with ban expiry time        |
| `suspicion_log.json`  | Tracks active suspicion scores and timestamps per IP     |
| `attacks.log`         | Human-readable log of all blocked attempts               |
| `.htaccess`           | Auto-generated to deny all public access                |
| `index.php`           | Dummy file (auto-generated) to prevent directory listing|

### ⚠️ Important Security Notice
**Dynamic Shield** provides excellent baseline protection, but **it is not a silver bullet**.

Always combine it with best security practices:

| Best Practice                          | Recommendation                                      |
|----------------------------------------|-----------------------------------------------------|
| Database Queries                       | Always use **Prepared Statements** (PDO/MySQLi)     |
| Output Encoding                        | Escape output with `htmlspecialchars()` or equivalent |
| PHP Version                            | Keep PHP **updated** to the latest stable release  |
| Input Handling                         | **Validate and sanitize** all input server-side    |

### 📜 License

This project is licensed under the **MIT License** – see the [LICENSE](LICENSE) file for details.

### 📝 Author

Created with ❤️ by **AMIRX**
