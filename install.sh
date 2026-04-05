#!/bin/bash
# ── Leak Detect — One-command setup ──────────────────────────────────────────
set -e

echo "── Creating virtual environment ─────────────────────────────────────────"
python -m venv venv

echo "── Activating venv ──────────────────────────────────────────────────────"
source venv/bin/activate

echo "── Installing dependencies ───────────────────────────────────────────────"
pip install --upgrade pip
pip install -r requirements.txt

echo "── Downloading spaCy language model (for NLP scanning) ──────────────────"
python -m spacy download en_core_web_lg

echo "── Setting up .env ──────────────────────────────────────────────────────"
cp .env.example .env

echo ""
echo "✅  Setup complete!"
echo ""
echo "Run the system:"
echo "  source venv/bin/activate"
echo "  python run_demo.py"
echo "  python -m streamlit run dashboard/app.py"
echo ""
echo "Run tests:"
echo "  pytest tests/ -v"
