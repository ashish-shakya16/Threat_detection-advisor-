# 🚀 Getting Started Guide

## Welcome to Cybersecurity Threat Advisor!

This guide will help you set up and run the project step by step.

---

## 📋 Prerequisites

Before starting, ensure you have:

1. **Python 3.8 or higher**
   - Check: `python --version`
   - Download: https://www.python.org/downloads/

2. **pip (Python package manager)**
   - Usually comes with Python
   - Check: `pip --version`

3. **Text editor or IDE**
   - VS Code, PyCharm, or any editor

4. **Windows/Linux/Mac**
   - Works on all platforms

---

## ⚙️ Setup Instructions

### Step 1: Navigate to Project Directory

```bash
cd a:\codes\pbl
```

### Step 2: Create Virtual Environment (Recommended)

**Windows:**
```powershell
python -m venv venv
venv\Scripts\activate
```

**Linux/Mac:**
```bash
python3 -m venv venv
source venv/bin/activate
```

You should see `(venv)` in your terminal prompt.

### Step 3: Install Dependencies

```bash
pip install -r requirements.txt
```

This installs:
- psutil (system monitoring)
- scikit-learn (ML)
- Flask (web dashboard)
- pandas, numpy (data processing)
- etc.

**Note:** If you get permission errors with scapy (network packet analysis), you can comment it out in requirements.txt. The system will still work without deep packet inspection.

### Step 4: Initialize the System

```bash
python main.py --init
```

This creates:
- Database directory and SQLite database
- Log directory
- Ensures config files are in place

---

## 🎮 Running the System

### Option 1: Single Scan (Quick Test)

Run one scan cycle and exit:

```bash
python main.py --scan
```

This will:
1. Monitor system processes
2. Check network connections
3. Detect any threats
4. Display advisories
5. Exit

**Perfect for testing!**

### Option 2: Continuous Monitoring (Production Mode)

Run continuous monitoring with 5-second intervals:

```bash
python main.py --monitor --interval 5
```

This will:
1. Scan every 5 seconds
2. Detect threats in real-time
3. Display alerts as they occur
4. Keep running until you press Ctrl+C

**Press Ctrl+C to stop**

### Option 3: View Past Threats

List threats detected in the last 24 hours:

```bash
python main.py --list-threats --hours 24
```

### Option 4: View Statistics

Show threat statistics:

```bash
python main.py --stats --hours 24
```

---

## 🧪 Testing the System

Since you're in a safe environment, you won't see many real threats. Let's test with simulated activities:

### Test 1: High CPU Usage

Open Task Manager or a heavy application (browser with many tabs) to trigger high CPU alert.

### Test 2: Many Network Connections

Open multiple websites simultaneously to test network monitoring.

### Test 3: Custom Testing Script

Run the test data generator (we'll create this next):

```bash
python tests/test_system.py
```

---

## 📊 Understanding the Output

When a threat is detected, you'll see:

```
======================================================================
🚨 Suspicious Program Detected
Risk Level: High (Score: 0.85)
======================================================================

What happened:
A potentially harmful program was found running on your system.

What you should do:
  1. Immediately close the suspicious program
  2. Run a full system antivirus scan
  3. Check if this program was intentionally installed
  4. If unsure, disconnect from the network and seek IT support

Technical Remediation:
  Terminate the process and remove the executable file from the system.

Technical Details:
  Threat Type: Malware
  Severity: high
  Confidence: 90%
  Process: mimikatz.exe
  Process ID: 1234
  Detected by: system_monitor

References:
  - MITRE ATT&CK: T1059
======================================================================
```

### Understanding Risk Levels:

- **Low (0.0-0.3):** Informational, minimal risk
- **Medium (0.3-0.6):** Investigate, moderate concern
- **High (0.6-0.85):** Urgent, requires action
- **Critical (0.85-1.0):** Immediate threat, act now

---

## 🗂️ Project Structure Overview

```
a:\codes\pbl\
├── config/
│   ├── config.yaml          # Main configuration
│   └── rules.json           # Detection rules
├── src/
│   ├── monitors/            # System/network monitoring
│   ├── detection/           # Threat detection
│   ├── risk_assessment/     # Risk scoring
│   ├── advisory/            # Advisory generation
│   └── database/            # Database operations
├── data/
│   ├── db/                  # SQLite database
│   └── logs/                # Application logs
├── main.py                  # Entry point
├── requirements.txt         # Dependencies
└── README.md                # Documentation
```

---

## 🔧 Configuration

Edit `config/config.yaml` to customize:

### Monitoring Intervals
```yaml
monitoring:
  system_check_interval: 5    # seconds between scans
  network_check_interval: 10
```

### Thresholds
```yaml
monitoring:
  system:
    cpu_threshold: 90          # Alert if CPU > 90%
    memory_threshold: 85       # Alert if memory > 85%
```

### Detection Rules

Edit `config/rules.json` to:
- Add new threat patterns
- Modify severity levels
- Customize advisory messages

---

## 🐛 Troubleshooting

### "Module not found" Error

**Solution:**
```bash
pip install -r requirements.txt
```

### "Access Denied" for Network Monitoring

**Cause:** Some network operations require admin privileges.

**Solution:**
- Run terminal as Administrator (Windows)
- Use `sudo` on Linux/Mac
- Or disable network monitoring in config.yaml:
  ```yaml
  monitoring:
    network:
      enabled: false
  ```

### Database Locked Error

**Cause:** Another instance is running.

**Solution:** Stop other instances or delete `data/db/threats.db` and reinitialize.

### No Threats Detected

**This is normal!** If you're on a clean system, you won't see many threats. To test:
1. Run the test script (we'll create next)
2. Simulate suspicious activity
3. Lower thresholds in config.yaml

---

## 📈 Next Steps

1. ✅ **Run the system** - Get familiar with basic operation
2. ✅ **Understand the code** - Read module comments
3. ✅ **Test detection** - Run test scenarios
4. 🔜 **Add ML enhancement** - Phase 2 (coming next)
5. 🔜 **Build dashboard** - Web interface
6. 🔜 **Write report** - Document your work

---

## 💡 Tips for Viva/Presentation

### Be Ready to Explain:

1. **Architecture:** Why modular design?
2. **Detection:** Rule-based vs ML-based differences
3. **Risk Scoring:** Why weighted scoring?
4. **Advisory:** How templates work
5. **Database:** Why SQLite? When to use what?
6. **Limitations:** What can't it detect?

### Demo Flow:

1. Show configuration files
2. Run single scan
3. Explain output
4. Show database queries
5. Demonstrate threat detection
6. Show advisory generation

---

## 📚 Additional Resources

- **MITRE ATT&CK:** https://attack.mitre.org/
- **OWASP:** https://owasp.org/
- **Cybersecurity Datasets:** 
  - NSL-KDD: https://www.unb.ca/cic/datasets/nsl.html
  - CICIDS2017: https://www.unb.ca/cic/datasets/ids-2017.html

---

## 🆘 Need Help?

1. Check logs: `data/logs/app.log`
2. Review configuration: `config/config.yaml`
3. Read code comments - they explain everything!
4. Test individual modules (each has `if __name__ == "__main__"` test code)

---

**Ready to start? Run:**

```bash
python main.py --scan
```

**Good luck with your project! 🎓🛡️**
