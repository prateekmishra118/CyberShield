# CyberShield – Network Threat Detection & Protection

CyberShield is a cybersecurity analytics and threat protection platform designed to analyze network traffic, identify malicious activities, classify network attacks, and provide an interactive security dashboard for monitoring and protection.

The platform combines data preprocessing, exploratory data analysis, machine learning, database connectivity, visualization, and a security-focused dashboard to support network threat detection and protection.

---

## Project Overview

Modern networks generate large volumes of traffic that can contain normal activities as well as different types of cyber attacks. Identifying and understanding these attacks requires systematic analysis of network traffic and effective classification techniques.

CyberShield analyzes network traffic records and identifies **9 attack categories**, providing a structured view of detected threats and their protection status.

The project also provides an interactive dashboard where users can:

- Scan network traffic
- View detected threat categories
- Review threats requiring protection
- Apply protection actions
- Track handled threats
- View protection history
- Analyze security statistics and model performance

---

## Key Features

### Network Traffic Analysis
- Processes network traffic records
- Performs data preprocessing and feature engineering
- Analyzes network protocols, services, connection states, and traffic characteristics

### Threat Detection
- Identifies normal and malicious network activity
- Uses a trained detection model for attack detection
- Uses a protection-oriented detection threshold

### Attack Classification
CyberShield classifies detected attacks into 9 categories:

1. Analysis
2. Backdoor
3. DoS
4. Exploits
5. Fuzzers
6. Generic
7. Reconnaissance
8. Shellcode
9. Worms

### Protection System
- Displays detected threats requiring action
- Allows protection actions for detected threats
- Tracks handled threats
- Maintains protection history
- Updates security status after protection actions

### Interactive Dashboard
The dashboard provides:

- Home
- Network Scan
- Threat Protection
- Protection Center
- Protection History
- Security Analytics

---

## Dashboard Workflow

```text
Network Traffic
       ↓
Data Preprocessing
       ↓
Feature Engineering
       ↓
Threat Detection
       ↓
Attack Classification
       ↓
Threat Categories
       ↓
Threats Requiring Action
       ↓
Protection Action
       ↓
Protection History
       ↓
Security Analytics
