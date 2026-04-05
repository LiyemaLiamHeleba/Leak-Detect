# Data Leak Detection & Insider Threat Analytics

A production-like cybersecurity portfolio project combining file scanning,
data pipelines, risk scoring, insider threat detection, and ML anomaly detection.

---

## Quick start

```bash
# 1. Unzip and enter the project
unzip leak-detect-project.zip && cd leak-detect

# 2. Create and activate a virtual environment
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate

# 3. Install all dependencies
pip install -r requirements.txt

# 4. (Optional but recommended) Download spaCy model for NLP scanning
python -m spacy download en_core_web_lg

# 5. Copy env file
cp .env.example .env

# 6. Run the end-to-end demo
python run_demo.py

# 7. Train the ML anomaly model
python -m ml.train

# 8. Launch the dashboard
streamlit run dashboard/app.py
```

---

## Project structure

```
leak-detect/
├── scanner/
│   ├── patterns.py          # 10 regex patterns + redaction logic
│   ├── nlp_scanner.py       # Presidio NLP scanner (graceful fallback)
│   └── file_scanner.py      # .txt .csv .eml .json .log support
│
├── pipeline/
│   ├── enrichment.py        # severity classification + risk scoring
│   ├── db_writer.py         # writes scan results to DB
│   ├── flow.py              # Prefect orchestration flow
│   └── schedule.py          # cron-scheduled auto-scan + auto-retrain
│
├── db/
│   ├── models.py            # 4 SQLAlchemy tables
│   ├── session.py           # session factory
│   └── init_db.py           # creates tables (run once)
│
├── security/
│   ├── insider_threat.py    # 4 DLP rules engine
│   └── user_manager.py      # create/list/assign users (CLI + API)
│
├── ml/
│   ├── anomaly_detector.py  # Isolation Forest (train/predict/save/load)
│   └── train.py             # training script, writes results to DB
│
├── dashboard/
│   └── app.py               # Streamlit: 5 tabs, 10+ charts
│
├── data/
│   ├── generate_samples.py  # generates realistic fake PII files
│   └── sample_files/        # pre-generated test data
│
├── tests/
│   ├── test_scanner.py      # 9 regex scanner tests
│   ├── test_enrichment.py   # 5 enrichment/scoring tests
│   └── test_nlp_scanner.py  # 6 NLP scanner tests (graceful fallback)
│
├── run_demo.py              # one-command end-to-end demo
├── install.sh               # automated setup script
├── requirements.txt
└── .env.example
```

---

## What gets detected

| Pattern       | Severity  | Example                          |
|---------------|-----------|----------------------------------|
| Credit card   | CRITICAL  | `4111111111111111`               |
| SSN           | CRITICAL  | `123-45-6789`                    |
| AWS key       | CRITICAL  | `AKIAIOSFODNN7EXAMPLE`           |
| Private key   | CRITICAL  | `-----BEGIN RSA PRIVATE KEY----` |
| API key       | HIGH      | `api_key=sk_live_abc123...`      |
| Password      | HIGH      | `password=S3cr3t!`               |
| JWT token     | HIGH      | `eyJhbGci...`                    |
| Phone number  | MEDIUM    | `+1 (555) 123-4567`              |
| Email address | LOW       | `user@example.com`               |
| IP address    | LOW       | `192.168.1.100`                  |

---

## User management (insider threat)

```bash
# Create users
python -m security.user_manager add --username alice --department Engineering
python -m security.user_manager add --username bob   --department Finance

# Assign files to a user (enables insider threat tracking)
python -m security.user_manager assign --username alice --directory ./data/sample_files

# View all users and risk scores
python -m security.user_manager list

# Reset a user's risk score
python -m security.user_manager reset --username alice
```

## Insider threat rules

| Rule                | Trigger                               | Score delta |
|---------------------|---------------------------------------|-------------|
| `repeated_leak`     | >3 alerts from same user in 24 h      | +15         |
| `off_hours_activity`| Alert file scanned between 10pm–6am   | +10         |
| `bulk_exfiltration` | >10 files scanned in 1 h by same user | +20         |
| `critical_detection`| Any CRITICAL severity file            | +25         |

---

## ML anomaly detection

```bash
# Train (after running demo to populate DB)
python -m ml.train

# With custom contamination rate (default 5%)
python -m ml.train --contamination 0.10
```

The Isolation Forest trains on 7 features: `risk_score`, `size_bytes`,
`file_type`, `hour_of_day`, `is_weekend`, `is_alert`, `detection_count`.
Results are stored in the `anomaly_results` DB table and shown in the dashboard.

---

## Scheduled pipeline (Prefect)

```bash
# Run once manually
python -m pipeline.flow --directory ./data/sample_files

# Start the cron scheduler (default: every 30 minutes)
python -m pipeline.schedule

# Custom schedule
SCAN_CRON="0 2 * * *" python -m pipeline.schedule   # nightly at 2am
```

---

## Switch to PostgreSQL

Edit `.env`:
```
DATABASE_URL=postgresql://user:password@localhost:5432/leakdetect
```
Then uncomment `psycopg2-binary` in `requirements.txt` and reinstall.
All SQLAlchemy models are database-agnostic.

---

## Run tests

```bash
pytest tests/ -v
# 20 tests: 9 scanner · 5 enrichment · 6 NLP scanner
```

---

## Dashboard tabs

| Tab                  | Contents                                          |
|----------------------|---------------------------------------------------|
| 📊 Overview          | KPIs, trend chart, severity pie, risk histogram   |
| 🔍 Detections        | Filterable table, detections by file type         |
| 👤 Users             | Risk bar chart, files-per-user table              |
| 🤖 Anomaly Detection | Scatter plot, flagged files, train button         |
| 🚨 Threat Events     | Event type breakdown, timeline, raw event table   |


## License

MIT License

Copyright (c) 2025 Liyema Heleba

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

## Languages & Tools

| Category | Technologies |
|---|---|
| **Language** | Python 3.12 |
| **Database** | SQLite (dev) · PostgreSQL (production) |
| **ORM** | SQLAlchemy 2.0 |
| **Scanning** | Regex · Microsoft Presidio · spaCy |
| **Pipeline** | Prefect 2.x · Pandas |
| **Machine Learning** | Scikit-learn · Isolation Forest · NumPy |
| **Dashboard** | Streamlit · Plotly Express |
| **Testing** | pytest · pytest-cov |
| **Data Generation** | Faker |
| **Version Control** | Git · GitHub |