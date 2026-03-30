---
title: Phishing Email Detector
emoji: 🛡️
colorFrom: blue
colorTo: indigo
sdk: docker
pinned: false
app_port: 7860
---
# 🔐 Phishing Email Detector - OpenEnv Environment

**Author:** M Abhilash Kumar  
**Hackathon:** OpenEnv Hackathon 2026  
**Submission Date:** March 2026  

An OpenEnv-compatible environment where an AI agent detects phishing emails using rule-based analysis and domain trust verification.

---

## 📌 Overview

This project simulates a real-world email security task where an AI agent must analyze emails and determine whether they are phishing attempts.

The detector uses a scoring-based system that evaluates:

- Domain authenticity (trusted vs fake domains)
- Link safety (whether links match the sender)
- Urgency indicators (pressure tactics used in phishing)
- Security alerts (real vs fake alerts)

The environment supports multiple difficulty levels and provides automatic grading with partial rewards.

---

## ✨ Features

- 3 Difficulty Levels (Easy, Medium, Hard)
- Automated Graders (score from 0.0 to 1.0)
- Partial Rewards for correct detection
- Fake Domain Detection (google-accounts.com, paypal-verify.xyz, etc.)
- Link Domain Verification
- Legitimate Security Email Detection (GitHub, Google, etc.)
- Fully Offline – No API keys required
- Automatic score logging to `email_scores.txt`

---

## 📁 Project Structure

```
phishing-detector/
├── inference.py              # Main program
├── openenv.yaml              # OpenEnv configuration
├── requirements.txt          # Dependencies
├── Dockerfile                # Docker setup
├── README.md                 # Documentation
├── custom_emails.txt         # Custom emails (optional)
└── data/
    └── phishing_dataset.csv  # Auto-generated dataset
```

---

## 🚀 Installation

```bash
cd phishing-detector

python -m venv venv
source venv/bin/activate      # Windows: venv\Scripts\activate

pip install -r requirements.txt
```

---

## 📦 Dependencies

```
pydantic>=2.0.0
pandas>=2.0.0
numpy>=1.24.0
```

---

## ▶️ Usage

Run the detector:

```bash
python inference.py
```

Menu options:

1. Test custom emails  
2. Run full dataset (400 emails)  
3. Quick test with built-in emails  
4. View saved scores  
5. Exit  

---

## 🔧 Testing Custom Emails

Create a file named:

```
custom_emails.txt
```

Example:

```
=== EMAIL 1 ===
From: security@paypal-verify.xyz
Subject: URGENT: Your Account Is Limited

Verify now: http://paypal-verify.xyz
```

Then run:

```bash
python inference.py
```

Choose option **1**.

---

## 📊 How the Scoring Works

| Indicator | Impact |
|----------|--------|
Fake domain detected | +0.7  
Company impersonation | +0.6  
Suspicious sender domain | +0.25  
Phishing keywords (urgent, verify, suspended) | +0.08 each  
Trusted domain | −0.35  
Links match sender | −0.3  

Final rule:

```
Score ≥ 0.4 → PHISHING  
Score < 0.4 → LEGITIMATE
```

---

## 📈 Example Output

```
From: google-accounts.com
Result: 🔴 PHISHING
Confidence: 90%
Score: 0.85
Reason: Fake domain + impersonation attempt
```

---

## 🐳 Docker

Build:

```bash
docker build -t phishing-detector .
```

Run:

```bash
docker run --rm -it phishing-detector
```

---

## 📊 Accuracy

- 90%+ after domain trust verification  
- 100% on legitimate security emails  
- 70%+ on advanced phishing emails  

---

## 📄 License

This project is licensed under the [MIT License](LICENSE.md).

---

## 👨‍💻 Author

M Abhilash Kumar  
OpenEnv Hackathon 2026 Submission

---

Stay safe from phishing! 🛡️