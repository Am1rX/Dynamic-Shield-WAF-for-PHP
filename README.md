🛡️ Dynamic Shield WAF for PHP
A lightweight, self-contained, behavior-driven Web Application Firewall (WAF) designed to protect PHP applications from common web threats like SQL Injection (SQLi) and Cross-Site Scripting (XSS).

Unlike simple signature-based firewalls, Dynamic Shield uses a multi-layered defense strategy that includes risk scoring and behavioral analysis to detect and block sophisticated, automated attacks.

💡 Core Philosophy
The primary goal of this WAF is not just to block known bad patterns but to identify malicious intent by analyzing the behavior of a client over time. It's built to stop the "low and slow" attacks that simple firewalls might miss.

✨ Key Features
🛡️ Multi-Layered Defense: Combines immediate blocking of high-risk requests with behavioral analysis for suspicious activities.

💯 Risk-Scoring Engine: Assigns a risk score to each request based on customizable attack patterns instead of a simple block/allow logic.

🤖 Behavioral Analysis & Temp-Banning: Tracks suspicious requests per session and temporarily blocks clients that exhibit bot-like behavior (e.g., running a dictionary attack).

🎭 Input Normalization: Defeats common evasion techniques like URL encoding and comment-based obfuscation before analysis.

🔌 Easy to Integrate: A single file that can be dropped into any PHP project with one line of code.

🔧 Configurable: Easily adjust risk thresholds, ban duration, and attack patterns to fit your application's needs.

⚙️ How It Works
Dynamic Shield operates on two layers of defense for every request:

Layer 1: ⚡ Immediate Threat Blocking
Normalization: The firewall first normalizes all $_REQUEST inputs ($_GET, $_POST, $_COOKIE) to decode URLs and strip out comments (/**/, --). This ensures that obfuscated payloads are revealed.

Risk Scoring: It then checks the normalized input against a list of attack patterns (defined using regular expressions). Each matched pattern adds a specific score to the request's total risk score.

Decision: If the total_risk_score exceeds the RISK_THRESHOLD (e.g., 15), the request is deemed highly dangerous, and the client is immediately blocked and redirected to a "Blocked" page.

Layer 2: 📈 Behavioral Analysis (Suspicion Tracking)
If a request is not dangerous enough to be blocked immediately but still has a risk score greater than zero, it's considered "suspicious."

Suspicion Counter: The firewall increments a session-based counter for each suspicious request.

Time Window: This counter is only valid for a specific time window (e.g., 60 seconds).

Temp-Ban: If the suspicion_counter reaches the SUSPICION_THRESHOLD (e.g., 20 requests) within the time window, the firewall flags the client as a potential bot. It then blocks their session for a configurable duration (e.g., 5 minutes).

This layer is incredibly effective against automated tools like sqlmap that rely on sending hundreds of slightly different requests to probe for vulnerabilities.

🚀 Installation and Usage
Integrating Dynamic Shield into your project is simple:

Download the firewall.php file.

Place it in your project's root directory (or any other directory of your choice).

Add the following line to the very top of your main entry point file (e.g., index.php, router.php):

<?php

// Include and execute the firewall before any other code runs.
require_once 'firewall.php';

// ... the rest of your application's code follows ...

?>

That's it! Your application is now protected. 🎉

🛠️ Configuration
You can customize the firewall's behavior by editing the define constants at the top of firewall.php:

Constant

Default

Description

RISK_THRESHOLD

15

The score at which a single request is immediately blocked.

SUSPICION_THRESHOLD

20

The number of suspicious requests before a client is temporarily banned.

TIME_WINDOW

60

The time window in seconds for tracking suspicious requests.

BLOCK_DURATION

300

The duration in seconds (5 minutes) for which a client is blocked.

✏️ Customizing Attack Patterns
The core of the detection engine is the $attack_patterns array. You can easily add or modify rules to better suit your needs. Each rule is an array with three keys:

'pattern': A regular expression (PCRE) to search for.

'score': The integer score to add to the request's risk if the pattern is found.

'type': A descriptive name for the attack type (used for logging).

⚠️ Important Security Notice
A Web Application Firewall is an essential layer of security, but it is not a substitute for secure coding practices. It acts as a shield, not a fix for underlying vulnerabilities.

You should always continue to use:

Prepared Statements (with parameterized queries) to prevent SQL Injection.

Proper Output Escaping (e.g., using htmlspecialchars) to prevent XSS.

This WAF is designed to be your second line of defense to block attacks before they can even reach your vulnerable code.

📜 License
This project is licensed under the MIT License. See the LICENSE.md file for details.
