# AI-Based Spam & Scam Call Detection System (CallShield Forensics)

**Course:** CSCR2600 - Project-Based Learning (PBL) - 1  
**Institution:** Department of Computer Science & Engineering, Sharda School of Computing Science and Engineering, Sharda University, Greater Noida  
**Session:** 2025 – 2026 | **Section:** MG2  
**Submitted By:**
- **Silvia Noatia** (`2026279652`) — Designer and Developer
- **Fatima Iqbal** (`2026187337`) — Design and Tester

**Submitted To:** Prof. Dharmendra Kumar

---

## System Architecture & Modules

| Module | File | Description |
| :--- | :--- | :--- |
| **Data Preprocessing** | `data_preprocessing.py` | Generates the reproducible 6,000-row synthetic dataset (`data/calls.csv`), safely normalizes E.164 phone numbers starting with `+`, cleans duplicates, and builds a leak-free `ColumnTransformer` fit strictly on the 80% training split. |
| **Model Training** | `model_training.py` | Performs an 80/20 stratified split, trains 5 classifiers (**Random Forest**, **Gradient Boosting**, **SVM**, **Logistic Regression**, **Decision Tree**), selects **Random Forest** as the best model (`94.75%` Accuracy, `0.9400` Macro-F1), and saves `.pkl` artifacts with `joblib`. |
| **Prediction Engine** | `prediction.py` | Loads the fitted preprocessing pipeline and trained model to output class probabilities (`Safe`, `Spam`, `Scam`), a `0–100` ML risk score, and plain-language forensic reasons. |
| **Risk Engine** | `risk_engine.py` | Blends the **ML risk score (60%)**, **Community report score (25%)**, and **Historical reputation score (15%)** into one final, transparent `0–100` risk score. |
| **Database Module** | `database.py` | SQLite-backed storage (`data/call_detection.db`) for `community_reports`, `number_reputation`, and `call_logs`. |
| **Transcript Analyzer** | `transcript_analyzer.py` | Scans pasted call transcripts against **10 regex-based scam-indicator categories** (OTP harvesting, Digital Arrest threats, payment demands, AnyDesk remote access, KYC suspension, urgency, etc.) with inline phrase highlighting. |
| **Verification Suite** | `test_suite.py` | Automated unit and edge-case test suite (10 checks) + formal development defect log. |

---

## Live Hosted Demo (No Local Setup Required)

- **GitHub Pages Live App (8-Page Forensic UI):** [https://samarthvarshney.github.io/spam-scam-call-detection/](https://samarthvarshney.github.io/spam-scam-call-detection/)
- **GitHub Repository:** [https://github.com/SamarthVarshney/spam-scam-call-detection](https://github.com/SamarthVarshney/spam-scam-call-detection)

---

## Running the Web Application Locally

This project includes **both** a bespoke Full-Stack Web Application (FastAPI + Custom HTML/CSS/JS UI) and the 8-Page Streamlit Web Application (`app.py`), both connected to the same backend modules, `.pkl` models, and SQLite database:

### Option 1: Full-Stack Web Application (FastAPI + Custom Forensic UI)
```bash
python server.py
```
Then open **http://127.0.0.1:8000** in your browser.

### Option 2: Streamlit Web Application (8 Functional Pages)
```bash
streamlit run app.py
```

### Run Automated Unit & Edge-Case Verification Suite
```bash
python test_suite.py
```
