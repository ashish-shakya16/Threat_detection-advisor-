# 🤖 Phase 2: ML Enhancement Guide

## Adding Machine Learning-Based Anomaly Detection

This guide explains how to implement the ML enhancement layer.

---

## 📋 Overview

**Goal:** Add unsupervised anomaly detection to catch unknown threats that rule-based detection misses.

**Approach:** Isolation Forest algorithm

**Why Isolation Forest?**
- Unsupervised (no labeled data needed)
- Fast training and prediction
- Good for rare event detection
- Works well with high-dimensional data
- Low memory footprint

---

## 🏗️ Architecture Integration

```
Current: Monitor → Rules → Risk → Advisory → DB

Enhanced: Monitor → Rules ⎤
                        ⎥→ Combiner → Risk → Advisory → DB
                  ML ⎦
```

**Both detection methods run in parallel, results are combined.**

---

## 📊 Step 1: Data Collection & Preparation

### 1.1 Collect Baseline Data

Run the system in "learning mode" to collect normal activity:

```python
# In main.py, add data collection mode
python main.py --collect-data --duration 24  # Collect for 24 hours
```

**What to collect:**
- All events (even non-threatening)
- Label as "benign"
- Store in CSV for training

### 1.2 Feature Engineering

**For System Events:**
```python
features = [
    'cpu_percent',           # 0-100
    'memory_percent',        # 0-100
    'num_threads',           # Count
    'num_connections',       # Count
    'process_age_seconds',   # Time since start
    'hour_of_day',          # 0-23
    'day_of_week',          # 0-6
    'connections_per_min',   # Rate
]
```

**For Network Events:**
```python
features = [
    'remote_port',           # Port number
    'bytes_sent',            # Volume
    'bytes_received',        # Volume
    'connection_duration',   # Seconds
    'connections_count',     # Per process
    'unique_ips_count',      # Distinct IPs
]
```

### 1.3 Data Preprocessing

```python
from sklearn.preprocessing import StandardScaler

# Normalize features to 0-1 range
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

# Save scaler for future use
import joblib
joblib.dump(scaler, 'src/ml_models/saved_models/scaler.pkl')
```

---

## 🧠 Step 2: Train Anomaly Detector

### 2.1 Create AnomalyDetector Class

```python
# src/ml_models/anomaly_detector.py

from sklearn.ensemble import IsolationForest
import joblib
import numpy as np
import logging

class AnomalyDetector:
    """
    ML-based anomaly detection using Isolation Forest.
    
    How it works:
    1. Train on normal (benign) data
    2. Learn what "normal" looks like
    3. Anything unusual = anomaly = potential threat
    """
    
    def __init__(self, contamination=0.1):
        """
        Initialize detector.
        
        Args:
            contamination: Expected % of anomalies (0.1 = 10%)
        """
        self.model = IsolationForest(
            contamination=contamination,
            n_estimators=100,
            max_samples='auto',
            random_state=42
        )
        self.scaler = None
        self.is_trained = False
        self.logger = logging.getLogger('CyberAdvisor.AnomalyDetector')
    
    def train(self, X_train, scaler=None):
        """
        Train the anomaly detector.
        
        Args:
            X_train: Training data (numpy array)
            scaler: Optional fitted scaler
        """
        self.logger.info(f"Training on {len(X_train)} samples...")
        
        if scaler:
            self.scaler = scaler
            X_train = scaler.transform(X_train)
        
        self.model.fit(X_train)
        self.is_trained = True
        
        self.logger.info("Training complete")
    
    def predict(self, X):
        """
        Predict if samples are anomalies.
        
        Args:
            X: Feature matrix
        
        Returns:
            Array: 1 for normal, -1 for anomaly
        """
        if not self.is_trained:
            raise ValueError("Model not trained yet!")
        
        if self.scaler:
            X = self.scaler.transform(X)
        
        predictions = self.model.predict(X)
        return predictions
    
    def score_samples(self, X):
        """
        Get anomaly scores (lower = more anomalous).
        
        Args:
            X: Feature matrix
        
        Returns:
            Array of anomaly scores
        """
        if self.scaler:
            X = self.scaler.transform(X)
        
        scores = self.model.score_samples(X)
        return scores
    
    def save_model(self, path='src/ml_models/saved_models/anomaly_detector.pkl'):
        """Save trained model."""
        joblib.dump({
            'model': self.model,
            'scaler': self.scaler,
            'is_trained': self.is_trained
        }, path)
        self.logger.info(f"Model saved to {path}")
    
    def load_model(self, path='src/ml_models/saved_models/anomaly_detector.pkl'):
        """Load trained model."""
        data = joblib.load(path)
        self.model = data['model']
        self.scaler = data['scaler']
        self.is_trained = data['is_trained']
        self.logger.info(f"Model loaded from {path}")
```

### 2.2 Training Script

```python
# train_ml_model.py

import pandas as pd
from sklearn.preprocessing import StandardScaler
from src.ml_models.anomaly_detector import AnomalyDetector

# Load collected data
print("Loading training data...")
df = pd.read_csv('data/training_data.csv')

# Filter benign samples only
benign_data = df[df['label'] == 'benign']

# Extract features
feature_cols = [
    'cpu_percent', 'memory_percent', 'num_threads',
    'num_connections', 'process_age_seconds'
]
X = benign_data[feature_cols].values

# Scale features
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

# Train model
detector = AnomalyDetector(contamination=0.1)
detector.train(X_scaled, scaler)

# Save model
detector.save_model()

print("Model trained and saved!")
```

---

## 🔌 Step 3: Integration with Main System

### 3.1 Update Main Application

```python
# In main.py, add ML detector

class ThreatAdvisor:
    def __init__(self, config_path="config/config.yaml"):
        # ... existing code ...
        
        # Initialize ML detector (if enabled)
        if self.config.get('detection.ml_based.enabled', False):
            self.logger.info("Loading ML anomaly detector...")
            self.ml_detector = AnomalyDetector()
            model_path = self.config.get('detection.ml_based.model_path')
            try:
                self.ml_detector.load_model(model_path)
                self.logger.info("✓ ML detector loaded")
            except FileNotFoundError:
                self.logger.warning("ML model not found. Run training first.")
                self.ml_detector = None
        else:
            self.ml_detector = None
    
    def scan_once(self):
        # ... existing monitoring code ...
        
        all_threats = []
        
        # 1. Rule-based detection (existing)
        rule_threats = self.rule_engine.check_events(all_events)
        all_threats.extend(rule_threats)
        
        # 2. ML-based detection (NEW)
        if self.ml_detector:
            ml_threats = self._detect_ml_anomalies(all_events)
            all_threats.extend(ml_threats)
        
        # 3. Combine and deduplicate
        all_threats = self._merge_threats(all_threats)
        
        # ... rest of pipeline ...
    
    def _detect_ml_anomalies(self, events):
        """Detect anomalies using ML."""
        ml_threats = []
        
        for event in events:
            # Extract features
            features = self._extract_features(event)
            
            if features is None:
                continue
            
            # Predict
            prediction = self.ml_detector.predict([features])[0]
            score = self.ml_detector.score_samples([features])[0]
            
            # If anomaly
            if prediction == -1:
                threat = {
                    'timestamp': event.get('timestamp'),
                    'threat_id': 'ML_ANOMALY',
                    'threat_name': 'Anomalous Behavior Detected',
                    'description': 'ML model detected unusual activity',
                    'category': 'Anomaly',
                    'severity': 'medium',
                    'confidence': self._score_to_confidence(score),
                    'impact': 'unknown',
                    'source': 'ml_detector',
                    'event_data': event.get('data', {}),
                    'anomaly_score': score
                }
                ml_threats.append(threat)
        
        return ml_threats
    
    def _extract_features(self, event):
        """Extract ML features from event."""
        data = event.get('data', {})
        
        # System event features
        if 'cpu_percent' in data:
            return [
                data.get('cpu_percent', 0),
                data.get('memory_percent', 0),
                data.get('num_threads', 1),
                data.get('num_connections', 0),
                data.get('process_age_seconds', 0)
            ]
        
        # Network event features
        elif 'remote_port' in data:
            return [
                data.get('remote_port', 0),
                data.get('bytes_sent', 0),
                data.get('bytes_received', 0),
                data.get('connection_duration', 0),
                data.get('connections_count', 1)
            ]
        
        return None
    
    def _score_to_confidence(self, score):
        """Convert anomaly score to confidence."""
        # Score ranges typically from -0.5 to 0.5
        # More negative = more anomalous
        confidence = max(0, min(1, 0.5 - score))
        return confidence
    
    def _merge_threats(self, threats):
        """Deduplicate threats from multiple detectors."""
        # If same event detected by both rule and ML,
        # keep the one with higher confidence
        
        seen = {}
        for threat in threats:
            key = (threat.get('timestamp'), 
                   threat.get('event_data', {}).get('pid'))
            
            if key not in seen:
                seen[key] = threat
            else:
                # Keep higher confidence
                if threat.get('confidence', 0) > seen[key].get('confidence', 0):
                    seen[key] = threat
        
        return list(seen.values())
```

---

## 📈 Step 4: Evaluation & Tuning

### 4.1 Evaluation Metrics

```python
def evaluate_detector(detector, X_test, y_test):
    """
    Evaluate anomaly detector.
    
    Args:
        detector: Trained AnomalyDetector
        X_test: Test features
        y_test: True labels (1=normal, -1=anomaly)
    """
    predictions = detector.predict(X_test)
    
    # Calculate metrics
    from sklearn.metrics import confusion_matrix, classification_report
    
    cm = confusion_matrix(y_test, predictions)
    print("Confusion Matrix:")
    print(cm)
    
    print("\nClassification Report:")
    print(classification_report(y_test, predictions, 
                                target_names=['Anomaly', 'Normal']))
    
    # Calculate custom metrics
    tn, fp, fn, tp = cm.ravel()
    
    detection_rate = tp / (tp + fn)  # Recall
    false_positive_rate = fp / (fp + tn)
    precision = tp / (tp + fp)
    
    print(f"\nDetection Rate: {detection_rate:.2%}")
    print(f"False Positive Rate: {false_positive_rate:.2%}")
    print(f"Precision: {precision:.2%}")
```

### 4.2 Hyperparameter Tuning

```python
# Try different contamination values
contaminations = [0.05, 0.1, 0.15, 0.2]

best_score = 0
best_contamination = 0.1

for cont in contaminations:
    detector = AnomalyDetector(contamination=cont)
    detector.train(X_train, scaler)
    
    predictions = detector.predict(X_test)
    f1 = f1_score(y_test, predictions)
    
    print(f"Contamination {cont}: F1={f1:.3f}")
    
    if f1 > best_score:
        best_score = f1
        best_contamination = cont

print(f"\nBest contamination: {best_contamination}")
```

---

## 🧪 Step 5: Testing

### 5.1 Test with Known Anomalies

```python
# tests/test_ml_detector.py

def test_ml_detector():
    detector = AnomalyDetector()
    detector.load_model()
    
    # Normal event
    normal_event = [50, 30, 10, 5, 100]  # Normal CPU, memory, etc.
    pred = detector.predict([normal_event])
    assert pred[0] == 1, "Should be normal"
    
    # Anomalous event
    anomaly_event = [98, 95, 200, 500, 10]  # High CPU, memory, many threads
    pred = detector.predict([anomaly_event])
    assert pred[0] == -1, "Should be anomaly"
    
    print("✓ ML detector tests passed")

if __name__ == "__main__":
    test_ml_detector()
```

---

## 📊 Step 6: Performance Monitoring

### 6.1 Track ML Performance

```python
# Add to database schema
cursor.execute('''
    CREATE TABLE IF NOT EXISTS ml_detections (
        id INTEGER PRIMARY KEY,
        timestamp TEXT,
        anomaly_score REAL,
        prediction INTEGER,
        features TEXT,
        was_threat BOOLEAN,
        false_positive BOOLEAN
    )
''')
```

### 6.2 Monitor and Retrain

```python
def check_model_drift(detector, recent_data):
    """
    Check if model performance is degrading.
    """
    predictions = detector.predict(recent_data)
    anomaly_rate = (predictions == -1).mean()
    
    # If anomaly rate drifts too far from expected
    expected_rate = 0.1  # 10% contamination
    
    if abs(anomaly_rate - expected_rate) > 0.05:
        print("⚠️ Model drift detected! Consider retraining.")
        return True
    
    return False
```

---

## 🎯 Expected Results

### Performance Targets:

**On Known Threats:**
- Detection Rate: >90%
- False Positive Rate: <5%
- Precision: >85%

**On Unknown Threats:**
- Detection Rate: >70% (ML helps here)
- False Positive Rate: <10%

### Comparison:

| Method | Known Threats | Unknown Threats | FP Rate |
|--------|--------------|-----------------|---------|
| Rules Only | 95% | 20% | 2% |
| ML Only | 75% | 70% | 8% |
| **Hybrid** | **97%** | **75%** | **4%** |

**Hybrid gives best of both worlds!**

---

## 🔍 Explainability

### Why ML Made This Decision:

```python
def explain_ml_detection(detector, event, features):
    """
    Explain why ML flagged this as anomaly.
    """
    score = detector.score_samples([features])[0]
    
    explanation = f"Anomaly Score: {score:.3f}\n"
    explanation += "(More negative = more anomalous)\n\n"
    
    # Compare to normal ranges
    normal_ranges = {
        'cpu_percent': (0, 80),
        'memory_percent': (0, 70),
        'num_connections': (0, 20)
    }
    
    for i, (key, normal_range) in enumerate(normal_ranges.items()):
        value = features[i]
        if value < normal_range[0] or value > normal_range[1]:
            explanation += f"⚠️ {key}={value} (normal: {normal_range})\n"
    
    return explanation
```

---

## 📚 Resources for Learning

### Isolation Forest:
- Original Paper: https://cs.nju.edu.cn/zhouzh/zhouzh.files/publication/icdm08b.pdf
- Sklearn Docs: https://scikit-learn.org/stable/modules/generated/sklearn.ensemble.IsolationForest.html

### Anomaly Detection:
- "Outlier Analysis" by Charu Aggarwal
- Coursera: Anomaly Detection course

### Datasets:
- NSL-KDD: https://www.unb.ca/cic/datasets/nsl.html
- CICIDS2017: https://www.unb.ca/cic/datasets/ids-2017.html

---

## ✅ Implementation Checklist

- [ ] Collect baseline data (24+ hours)
- [ ] Engineer features
- [ ] Train Isolation Forest model
- [ ] Evaluate on test set
- [ ] Integrate with main system
- [ ] Test with known anomalies
- [ ] Compare hybrid vs rule-only performance
- [ ] Document results in report
- [ ] Prepare viva demo

---

## 🎓 For Viva: ML Questions

**Be ready to explain:**

1. Why Isolation Forest? (Unsupervised, fast, good for anomalies)
2. What features did you use? (CPU, memory, connections, etc.)
3. How did you train? (Only on benign data)
4. How do you handle false positives? (Combine with rules, human review)
5. What's the detection accuracy? (Show evaluation results)
6. How does it complement rules? (Catches unknowns, rules catch knowns)

---

**This completes Phase 2! Your system now has both rule-based AND ML-based detection! 🎉**
