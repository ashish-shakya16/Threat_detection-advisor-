# 🛡️ Cybersecurity Threat Advisor - B.Tech Final Year Project

## 📋 Problem Statement

**Title:** Intelligent Cybersecurity Threat Advisor with Risk Classification and Human-Readable Advisory System

**Problem:** 
Traditional security tools generate technical alerts that are difficult for non-experts to understand and act upon. System administrators and end-users need an intelligent system that:
- Monitors system/network activities in real-time
- Detects potential cybersecurity threats
- Classifies threats by risk level (Low, Medium, High)
- Provides actionable, human-readable security advice
- Maintains historical logs for audit and analysis

**Solution:**
An AI-powered threat advisor that combines rule-based detection with machine learning to identify threats and generate contextual security recommendations.

---

## 🎯 Core Features

### Phase 1: Rule-Based Core System
1. **Activity Monitoring Module**
   - Monitor system processes
   - Track network connections
   - Log file access patterns
   - Monitor authentication attempts

2. **Threat Detection Engine**
   - Rule-based pattern matching
   - Signature-based detection
   - Behavioral analysis using predefined rules
   - Port scanning detection
   - Brute-force attempt detection

3. **Risk Classification System**
   - Low Risk: Informational alerts, minor policy violations
   - Medium Risk: Suspicious activity requiring attention
   - High Risk: Critical threats requiring immediate action

4. **Advisory Generation Module**
   - Convert technical alerts to human-readable advice
   - Provide step-by-step remediation guidance
   - Context-aware recommendations

5. **Logging & Storage**
   - SQLite database for threat logs
   - Historical data for trend analysis
   - Event correlation storage

### Phase 2: ML-Enhanced System
1. **Anomaly Detection**
   - Isolation Forest for outlier detection
   - Statistical anomaly detection
   - Unsupervised learning for unknown threats

2. **Behavioral Profiling**
   - User behavior analytics
   - Network traffic pattern learning
   - Adaptive threshold adjustment

3. **Predictive Analysis**
   - Threat prediction based on historical patterns
   - Risk score calculation using ML

---

## 🏗️ System Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    USER INTERFACE LAYER                      │
│  (Dashboard, CLI, Alerts Display, Report Generation)         │
└──────────────────┬──────────────────────────────────────────┘
                   │
┌──────────────────▼──────────────────────────────────────────┐
│                   ADVISOR LAYER                              │
│  (Advisory Generator, Risk Scorer, Explainability Module)   │
└──────────────────┬──────────────────────────────────────────┘
                   │
┌──────────────────▼──────────────────────────────────────────┐
│              THREAT DETECTION LAYER                          │
│  Rule Engine │ ML Anomaly Detector │ Correlation Engine     │
└──────────────────┬──────────────────────────────────────────┘
                   │
┌──────────────────▼──────────────────────────────────────────┐
│              MONITORING LAYER                                │
│  System Monitor │ Network Monitor │ Log Parser              │
└──────────────────┬──────────────────────────────────────────┘
                   │
┌──────────────────▼──────────────────────────────────────────┐
│              DATA LAYER                                      │
│  SQLite Database │ Log Files │ Configuration                │
└─────────────────────────────────────────────────────────────┘
```

---

## 🗂️ Module Breakdown

### 1. **Monitoring Module** (`monitors/`)
- **Purpose:** Collect system and network activity data
- **Components:**
  - System process monitor
  - Network connection tracker
  - File system watcher
  - Authentication log parser
- **Output:** Structured activity events

### 2. **Detection Module** (`detection/`)
- **Purpose:** Identify threats from monitored activities
- **Components:**
  - Rule-based detector (signatures, patterns)
  - Anomaly detector (ML-based)
  - Correlation engine (multi-event analysis)
- **Output:** Threat alerts with metadata

### 3. **Risk Assessment Module** (`risk_assessment/`)
- **Purpose:** Calculate and classify threat severity
- **Components:**
  - Risk scoring algorithm
  - Threat classifier (Low/Medium/High)
  - Impact calculator
- **Output:** Risk level and score

### 4. **Advisory Module** (`advisory/`)
- **Purpose:** Generate human-readable advice
- **Components:**
  - Advisory template engine
  - Remediation guide generator
  - Context-aware recommender
- **Output:** Plain-language security advice

### 5. **Database Module** (`database/`)
- **Purpose:** Store and retrieve threat data
- **Components:**
  - SQLite handler
  - Log manager
  - Query interface
- **Output:** Persistent storage

### 6. **Dashboard Module** (`dashboard/`)
- **Purpose:** Visualize threats and system status
- **Components:**
  - Web dashboard (Flask)
  - CLI interface
  - Report generator
- **Output:** User interface

---

## 🛠️ Technology Stack

### Core Technologies
- **Language:** Python 3.8+
- **Database:** SQLite3
- **Web Framework:** Flask (for dashboard)
- **Frontend:** HTML, CSS, JavaScript (Bootstrap)

### Python Libraries
```
Core:
- psutil (system monitoring)
- scapy (network monitoring)
- watchdog (file monitoring)

ML/Analytics:
- scikit-learn (anomaly detection)
- pandas (data analysis)
- numpy (numerical operations)

Database:
- sqlite3 (built-in)

Dashboard:
- Flask (web framework)
- plotly/matplotlib (visualization)

Logging:
- logging (built-in)
- python-json-logger
```

---

## 📊 Dataset Strategy

### Option 1: Simulated Data (Recommended for Start)
- Generate synthetic system logs
- Simulate network traffic patterns
- Create benign and malicious event sequences
- **Advantage:** Controlled, reproducible, safe

### Option 2: Public Datasets
- **KDD Cup 99 / NSL-KDD:** Network intrusion detection
- **CICIDS2017:** Realistic network traffic with attacks
- **ADFA-IDS:** System call-based intrusion detection
- **Advantage:** Real-world patterns

### Option 3: Live Monitoring (Advanced)
- Monitor actual system activity (own machine)
- Capture real network traffic (own network)
- **Advantage:** Real data, but needs careful filtering
- **Caution:** Privacy and legal considerations

---

## 📁 Folder Structure (Created Next)

```
cybersecurity-threat-advisor/
├── config/                  # Configuration files
├── src/                     # Source code
│   ├── monitors/           # Activity monitoring
│   ├── detection/          # Threat detection
│   ├── risk_assessment/    # Risk scoring
│   ├── advisory/           # Advisory generation
│   ├── database/           # Database operations
│   ├── ml_models/          # ML models
│   └── dashboard/          # Web interface
├── data/                   # Data storage
│   ├── logs/              # Application logs
│   ├── datasets/          # Training datasets
│   └── db/                # SQLite database
├── tests/                  # Unit tests
├── docs/                   # Documentation
├── notebooks/              # Jupyter notebooks for analysis
├── requirements.txt        # Dependencies
└── main.py                # Entry point
```

---

## 🎓 Key Points for Viva/Report

### Assumptions
1. Running in controlled environment (student machine)
2. Simulated threats for demonstration
3. Single-machine deployment initially
4. Focus on detection accuracy over performance
5. Supervised learning requires labeled data

### Limitations
1. Cannot detect zero-day exploits (no signatures yet)
2. ML models need training data and time
3. Resource-intensive for real-time monitoring
4. False positives in anomaly detection
5. Not suitable for enterprise deployment as-is

### Scope of Work
✅ **Included:**
- Core threat detection (common attacks)
- Risk classification
- Advisory system
- Database logging
- Basic ML anomaly detection
- Web dashboard

❌ **Not Included (Future Scope):**
- Multi-machine distributed monitoring
- Advanced persistent threat (APT) detection
- Integration with enterprise SIEM
- Real-time packet deep inspection
- Automated threat response/blocking

### Innovation/Novelty
1. **Human-readable advisories** instead of just alerts
2. **Hybrid approach** (rules + ML)
3. **Educational focus** with explainability
4. **Context-aware recommendations**
5. **Low barrier to entry** (no paid tools)

---

## 📅 Implementation Timeline (Student-Friendly)

### Week 1-2: Foundation
- Set up project structure
- Implement monitoring modules
- Create simulated data

### Week 3-4: Core Detection
- Rule-based detection engine
- Risk classification system
- Database integration

### Week 5-6: Advisory System
- Advisory templates
- Recommendation engine
- CLI interface

### Week 7-8: ML Enhancement
- Feature engineering
- Train anomaly detection models
- Integrate ML pipeline

### Week 9-10: Dashboard & Testing
- Build web dashboard
- Unit testing
- Integration testing

### Week 11-12: Documentation & Polish
- Report writing
- Presentation preparation
- Code documentation

---

## 🎯 Learning Outcomes

By completing this project, you will learn:
1. **Cybersecurity:** Threat types, detection methods, risk assessment
2. **System Programming:** Process monitoring, network analysis
3. **Machine Learning:** Anomaly detection, classification
4. **Software Engineering:** Modular design, testing, documentation
5. **Data Engineering:** Database design, logging, data pipelines
6. **Full-Stack Development:** Backend APIs, web dashboards

---

**Next Steps:** Let's create the folder structure and start implementing modules!
