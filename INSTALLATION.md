# SENTINAL Installation Guide

This guide provides detailed instructions for installing and configuring the SENTINAL security scanner.

## System Requirements

- Python 3.9 or higher
- pip (Python package manager)
- Git (for cloning the repository)
- 4GB RAM minimum (8GB recommended)
- Internet connection for downloading dependencies and accessing external APIs
- Optional/feature-based tools:
  - nmap (for the primary network scanner; an alternative is auto-used if unavailable)
  - sslyze (for SSL scanning; optional)
  - Google Chrome + ChromeDriver/Selenium (only for authenticated or browser-driven modules; optional)

## 1. Clone the Repository

```bash
git clone https://github.com/Prashithshetty/SENTINAL.git
cd SENTINAL
```

## 2. Create and Activate a Virtual Environment (recommended)

- Windows (CMD/PowerShell):
```bash
python -m venv .venv
.venv\Scripts\activate
```

- macOS/Linux:
```bash
python3 -m venv .venv
source .venv/bin/activate
```

## 3. Install Dependencies

This repository may not include a requirements.txt. Use either option below:

- Option A: If requirements.txt exists
```bash
pip install -r requirements.txt
```

- Option B: Install core dependencies explicitly
```bash
pip install \
  rich \
  python-dotenv \
  httpx \
  requests \
  fastapi \
  uvicorn \
  pydantic \
  pydantic-settings \
  SQLAlchemy \
  beautifulsoup4 \
  dnspython \
  shodan
```

Optional dependencies (enable extra features if you plan to use those modules):
```bash
# SSL/TLS scanner backend (optional)
pip install sslyze

# Selenium for browser-based or authenticated scanning (optional)
pip install selenium webdriver-manager

# NVD/CVE mapping (optional)
pip install nvdlib
```

Notes:
- If nmap is not installed, the project will fall back to an alternative network scanner implementation automatically if available.
- Some modules are gated behind feature flags and will be skipped if dependencies are missing.

## 4. Configure Environment Variables

Create a `.env` file in the project root (same folder as cli.py) with any values you plan to use:

```
# API Keys for External Services (optional features)
SHODAN_API_KEY=your_shodan_api_key_here
HUGGINGFACE_API_KEY=your_huggingface_api_key_here

# LLM Configuration for PoC Generation (optional)
USE_LM_STUDIO=true
LM_STUDIO_API_URL=http://localhost:1234/v1
CUSTOM_MODEL_NAME=DeepSeek-R1-Distill-Qwen-7B-Uncensored

# Scanner Configuration (defaults exist in backend/core/config.py)
MAX_CONCURRENT_SCANS=3
SCAN_TIMEOUT_SECONDS=3600
RATE_LIMIT_REQUESTS_PER_MINUTE=60
MAX_SCAN_DEPTH=3
REQUIRE_CONSENT=true
```

The application also reads many defaults from `backend/core/config.py`.

## 5. Verify Installation

Run the professional CLI:
```bash
python cli.py
```

You should see the SENTINAL banner and main menu.

Alternatively, run the simple CLI:
```bash
python sentinal.py
```

## 6. Run the API (optional)

A FastAPI service is included. Start it with:
```bash
python run_api.py
```

- API Docs: http://localhost:8001/docs

## Advanced Configuration

### Scanner Module Configuration

Some modules read additional configuration from YAML files in the `config/` directory, e.g.:
```bash
# Edit the SSL scanner configuration (example present)
# Use an editor of your choice
# Windows (PowerShell):
notepad config\ssl_scanner.yaml

# macOS/Linux:
nano config/ssl_scanner.yaml
```

### LM Studio Setup (Optional)

1. Download and install LM Studio: https://lmstudio.ai/
2. Launch LM Studio and load a compatible model
3. Start the local API server in LM Studio
4. Ensure your `.env` has `USE_LM_STUDIO=true` and `LM_STUDIO_API_URL` set

### Shodan Integration (Optional)

1. Sign up for a Shodan account: https://account.shodan.io/register
2. Obtain your API key
3. Add it to `.env` as `SHODAN_API_KEY`

## Docker (Alternative)

If you want to containerize, create a simple Dockerfile that installs the required dependencies (not provided by default) and then:

```bash
docker build -t sentinal .
docker run -it --rm ^
  -v "%cd%/reports:/app/reports" ^
  -v "%cd%/scan_results:/app/scan_results" ^
  -v "%cd%/.env:/app/.env" ^
  sentinal
```

On macOS/Linux replace line continuations with backslashes:
```bash
docker run -it --rm \
  -v "$(pwd)/reports:/app/reports" \
  -v "$(pwd)/scan_results:/app/scan_results" \
  -v "$(pwd)/.env:/app/.env" \
  sentinal
```

## Troubleshooting

1. Missing Dependencies
```bash
pip install --upgrade pip
# Then install using Option B above to ensure all direct deps are present
```

2. Permission Errors (mostly on Unix-like systems)
```bash
chmod +x *.py
# Or run with elevated permissions only if necessary
```

3. API Key Issues
- Verify your `.env` is in the project root and variables are correctly named
- Ensure the services (e.g. Shodan) are reachable from your network

4. Module Import Errors
- Ensure you run commands from the project root
- Verify optional dependencies for the module you use are installed
- Verify your Python interpreter uses the virtual environment

5. Windows specific
- Use `python` instead of `python3`
- Use `notepad` or VS Code to edit files
- Ensure your terminal encoding supports ASCII/Unicode art (PowerShell usually works fine)

## Getting Help

- Issues: https://github.com/Prashithshetty/SENTINAL/issues
- Include system info, command used, and stack traces when reporting issues
