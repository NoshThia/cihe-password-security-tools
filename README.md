#  CIHE ShieldX – Password Security Management System (PSMS)

##  Project Overview

CIHE ShieldX is a Flask-based Password Security Management System (PSMS) developed as a cybersecurity capstone project. The system provides password security analysis, vault protection, attack simulation, AI-assisted cybersecurity recommendations, MFA authentication, and security reporting features.

The project aims to improve user password hygiene, identify weak or compromised credentials, and demonstrate practical cybersecurity implementation using Python, Flask, and AI-assisted analysis.

---

#  Features

##  Authentication & RBAC

* Secure login system using Flask-Login
* Role-Based Access Control (RBAC)

  * Admin
  * Analyst
  * User
* Password hashing using Werkzeug Security

---

## Multi-Factor Authentication (MFA)

* TOTP-based MFA using PyOTP
* QR code generation for Google Authenticator / Microsoft Authenticator
* Secure MFA verification workflow

---

## Password Strength Checker

* Password analysis using zxcvbn
* Entropy calculation
* Crack-time estimation
* Common pattern detection
* Blacklist password detection

---

##  Password Attack Simulator

* Simulates:

  * Brute-force attacks
  * GPU cracking
  * Dictionary attacks
  * Offline cracking
* Includes:

  * Entropy analysis
  * Risk classification
  * Animated attack simulation
  * Chart.js visual analytics

---

##  AI-Assisted Security Recommendations

* Integrated with Google Gemini API
* Generates:

  * Security summaries
  * Password recommendations
  * Security posture analysis
* Uses local fallback if Gemini is unavailable

---

## Security Reporting Dashboard

* Password health analytics
* MFA adoption monitoring
* Failed login monitoring
* Breach indicator reporting
* AI-generated security reports
* Visual charts using Chart.js

---

## Secure Password Vault

* Encrypted password storage
* Secure vault item management
* Password reuse detection

---

##  Breach & Blacklist Monitoring

* Local compromised password dataset
* Blacklist matching system
* Reused password detection

---

## Security & Testing

Implemented testing and security validation using:

* PyTest
* Bandit
* pip-audit
* OWASP ZAP
* Locust

---

# Technologies Used

## Backend

* Python
* Flask
* Flask-SQLAlchemy
* Flask-Login

## Frontend

* AdminLTE 3
* Bootstrap 5
* Chart.js

## Database

* SQLite

## Security Libraries

* zxcvbn
* pyotp
* cryptography
* Werkzeug Security

## AI / LLM

* Google Gemini API (`google-generativeai`)

---

# Project Structure

```text
psms/
│
├── routes/
├── services/
├── templates/
├── static/
├── data/
├── tests/
│
├── app.py
├── config.py
├── models.py
├── extensions.py
├── requirements.txt
└── README.md
```

---

# Installation & Setup

## 1️ Clone Repository

```bash
git clone https://github.com/NoshThia/cihe-password-security-tools.git
cd cihe-password-security-tools
```

---

## 2️ Create Virtual Environment

```bash
python -m venv venv
```

Activate environment:

### Windows

```bash
venv\Scripts\activate
```

---

## 3️ Install Dependencies

```bash
pip install -r requirements.txt
```

---

## 4️ Configure Gemini API (Optional)

Create `.env`

```env
GEMINI_API_KEY=YOUR_GEMINI_API_KEY
```

---

## 5️ Run Application

```bash
python app.py
```

Open:

```text
http://127.0.0.1:5000
```

---

#  Default Admin Account

```text
Username: admin
Password: Admin@1234
```

---

#  Running Unit Tests

```bash
pytest
```

Coverage testing:

```bash
pytest --cov=services.attack_simulator --cov=services.vault_crypto --cov=services.password_ai
```

---

#  Security Testing

## Bandit

```bash
bandit -r . -x venv
```

## pip-audit

```bash
pip-audit
```

---

# AI & Privacy Note

Password analysis and attack simulation are processed locally using Python-based security heuristics and zxcvbn entropy analysis.

The Gemini LLM integration operates only on derived security metadata rather than raw password values.

---

#  Developed By

Noshin Tabassum Thia
Nitin Mehta
CIHE Australia
Master of Information Technology

---

# 📄 License

This project is developed for academic and educational purposes only.
