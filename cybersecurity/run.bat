@echo off
chcp 65001 >nul
setlocal

echo.
echo ============================================================
echo   cybersecurity - AI-Native Security Operations Platform
echo ============================================================
echo.

:: Set working directory to script location
cd /d "%~dp0"

:: Set encoding for emoji/unicode support
set PYTHONIOENCODING=utf-8

:: ── Step 1: Install dependencies ─────────────────────────────────────────────
echo [1/5] Installing dependencies...
pip install -r requirements.txt -q
if %ERRORLEVEL% neq 0 (
    echo [ERROR] pip install failed. Make sure Python is installed.
    pause & exit /b 1
)
echo [OK] Dependencies ready.
echo.

:: ── Step 2: Ingest threat intel into ChromaDB ─────────────────────────────────
echo [2/5] Ingesting threat intel into ChromaDB...
python scripts/ingest_threat_intel.py
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Threat intel ingestion failed.
    pause & exit /b 1
)
echo.

:: ── Step 3: Build evaluation dataset ─────────────────────────────────────────
echo [3/5] Building synthetic alert dataset (100 alerts)...
python -m eval.dataset_builder
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Dataset generation failed.
    pause & exit /b 1
)
echo.

:: ── Step 4: Run unit tests ────────────────────────────────────────────────────
echo [4/5] Running unit tests (no API key needed)...
python -m pytest tests/test_agent.py -v --tb=short
if %ERRORLEVEL% neq 0 (
    echo [WARN] Some tests failed. Check output above.
)
echo.

:: ── Step 5: Run evaluation for both models ────────────────────────────────────
echo [5/5] Running model evaluation (gpt-4o-mini, 15 alerts)...
python -m eval.runner --model gpt-4o-mini --limit 15
echo.
echo Running evaluation (gpt-4o, 10 alerts)...
python -m eval.runner --model gpt-4o --limit 10
echo.

:: ── Launch dashboard ──────────────────────────────────────────────────────────
echo ============================================================
echo   Launching cybersecurity Dashboard...
echo   Open your browser at: http://localhost:8501
echo ============================================================
echo.
echo Press Ctrl+C to stop the dashboard.
echo.

streamlit run eval/dashboard.py --server.port 8501 --server.headless true

pause
