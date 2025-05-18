# DPC Sentinel X - AI Cyber Guardian

## Overview
DPC Sentinel X is an advanced AI-integrated antivirus and antimalware suite designed specifically for Don Predreick College. This security solution aims to protect systems with maximum defense capabilities, modern AI integration, and an intuitive user interface.

## Core Features

### 🔍 AI-Powered Threat Detection
- Deep Learning + XGBoost model for malware signature identification
- Real-time anomaly detection using memory and file pattern analytics
- Zero-day and polymorphic threat detection
- Behavioral sandbox for unknown file execution simulation

### 🧬 DNA-Based Malware Fingerprint Engine
- Reverse-engineers unknown files to find opcode-level similarities to known malware
- Detects mutated ransomware and trojans using internal DNA matching

### 🔊 Offline Voice-Controlled AI Assistant
- Built-in secure AI assistant for voice commands
- Offline LLM-based local chatbot integration

### 🗃️ Smart Scanning Modes
- Quick Scan – Fast daily threat sweep
- Deep Scan – Forensic-grade, memory + disk scan
- Custom Scan – Pick drives, folders, and system components
- Heuristic Scan – Detects suspicious behaviors and script modifications

### 🧼 Real-Time Protection Engine
- Auto-scan on file download, USB insertion, or application installation
- Background memory process monitoring
- Anti-keylogger, anti-rootkit, and anti-screenshot spy system

### 🔐 Immunity Vault & File Lockdown
- Auto-restore critical files if ransomware encrypts them
- Protected folders with write-protection against unauthorized apps
- Crypto-layer backup system

### 🛰️ Network & Phishing Protection
- Browser session analysis for MITM attacks, phishing pages, DNS spoofing
- Unsafe link and redirected domain warnings
- Built-in fake website and scam blocker

### 🛡️ College-Aware Protection Mode
- LMS sync to monitor file submissions
- Suspicious behavior detection during online exams
- Cheating app and suspicious Discord bot flagging

### 🎮 Auto Performance Mode
- Game Mode, Exam Mode, and Focus Mode based on system usage
- Background scan suppression during CPU-intensive tasks

### 🌍 Blockchain-Powered Threat Logging
- Immutable logging of detections with timestamp, SHA256 hash, and type
- Admin panel with full scan history for auditing

## Tech Stack
- Python for scanning engine (using yara, pyshark, volatility, pymem)
- PyQt6 for cross-platform UI
- scikit-learn, LightGBM, TensorFlow for ML malware analysis
- Frida, psutil, watchdog, osquery for low-level system integration
- Tesseract + OpenCV for screenshot spyware detection
- Pyttsx3 + Vosk for offline voice recognition
- SQLite + Blockchain.py for event storage and tamper-proof logging
- Flask/Socket.IO for internal dashboard & alerts

## Installation

```bash
# Clone the repository
git clone https://github.com/donpredreickcollege/dpc-sentinel-x.git

# Navigate to the project directory
cd dpc-sentinel-x

# Install dependencies
pip install -r requirements.txt

# Run the application
python main.py
```

## Project Structure
```
dpc-sentinel-x/
├── core/                  # Core scanning and protection engine
│   ├── scanner/           # File and memory scanning modules
│   ├── detection/         # Threat detection algorithms
│   ├── protection/        # Real-time protection components
│   └── ai/                # AI and ML models for threat analysis
├── ui/                    # User interface components
│   ├── dashboard/         # Main dashboard screens
│   ├── settings/          # Configuration screens
│   ├── reports/           # Threat reports and logs
│   └── assets/            # UI assets (icons, styles)
├── utils/                 # Utility functions and helpers
├── data/                  # Data storage and management
│   ├── signatures/        # Malware signatures database
│   ├── logs/              # Scan and threat logs
│   └── quarantine/        # Quarantined file storage
├── tests/                 # Test suites
├── docs/                  # Documentation
├── main.py                # Application entry point
└── requirements.txt       # Project dependencies
```

## License
This project is proprietary software developed for Don Predreick College.

## Vision Statement
DPC Sentinel X is more than just an antivirus — it's a guardian angel for the digital lives of every student and teacher at Don Predreick College. With its unbeatable AI brain, powerful malware engine, and a stunning futuristic interface, it sets a new global standard in digital security.