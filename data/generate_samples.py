"""
Generates realistic synthetic test files in data/sample_files/.
Run once before testing:   python data/generate_samples.py
"""

import os, csv, json, random
from pathlib import Path
from faker import Faker

fake = Faker()
OUT  = Path(__file__).parent / "sample_files"
OUT.mkdir(exist_ok=True)


def rand_credit_card():
    # Visa-format fake CC
    return "4" + "".join([str(random.randint(0,9)) for _ in range(15)])


def rand_api_key():
    import string
    chars = string.ascii_letters + string.digits
    return "sk_live_" + "".join(random.choices(chars, k=32))


# 1. Plain text files
for i in range(5):
    lines = [
        f"From: {fake.email()}",
        f"Subject: Quarterly Report - {fake.bs()}",
        "",
        fake.paragraph(),
        f"Confidential contact: {fake.name()} | {fake.phone_number()}",
    ]
    if i % 2 == 0:
        lines += [
            f"Payment card: {rand_credit_card()}",
            f"password={fake.password()}",
        ]
    (OUT / f"email_{i+1}.txt").write_text("\n".join(lines))

# 2. CSV files
for i in range(3):
    rows = [["name","email","phone","ssn","amount"]]
    for _ in range(20):
        rows.append([
            fake.name(),
            fake.email(),
            fake.phone_number(),
            fake.ssn(),
            str(round(random.uniform(10, 5000), 2)),
        ])
    with open(OUT / f"customers_{i+1}.csv", "w", newline="") as f:
        csv.writer(f).writerows(rows)

# 3. Config / log files with secrets
configs = [
    f'DATABASE_URL="postgresql://admin:{fake.password()}@db.internal:5432/prod"',
    f'api_key = "{rand_api_key()}"',
    f'AWS_ACCESS_KEY_ID = "AKIA{"".join([str(random.randint(0,9)) if random.random()>0.5 else chr(random.randint(65,90)) for _ in range(16)])}"',
    f"# Server IP: {fake.ipv4()}",
    '-----BEGIN RSA PRIVATE KEY-----',
    'MIIEowIBAAKCAQEA0Z3VS5JJcds3xHn/ygWep4PAtEsHAWGS...',
    '-----END RSA PRIVATE KEY-----',
]
(OUT / "config.txt").write_text("\n".join(configs))

# 4. JSON log file
log_entries = []
for _ in range(15):
    log_entries.append({
        "timestamp": fake.iso8601(),
        "user":      fake.user_name(),
        "action":    random.choice(["LOGIN","DOWNLOAD","UPLOAD","DELETE"]),
        "file":      fake.file_name(),
        "ip":        fake.ipv4(),
    })
(OUT / "access_log.json").write_text(json.dumps(log_entries, indent=2))

# 5. A clean file (no secrets)
(OUT / "readme.txt").write_text(
    "This project tracks internal file usage.\n"
    "Contact the IT department for access requests.\n"
    + fake.paragraph()
)

print(f"[DataGen] Sample files written to {OUT}")
print(f"          Files: {[f.name for f in OUT.iterdir()]}")
