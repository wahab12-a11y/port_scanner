# W4R-LOCK Port Scanner (Professional Starter)

**W4R-LOCK** — a professional, ethical-port-scanner starter kit focused on defensive use, automation, and easy integration into security workflows.

**Features**
- Threaded TCP connect scanning
- Optional banner grabbing and simple service detection
- JSON and CSV output
- Optional `nmap` integration for service/version detection (if installed)
- Small Flask-based web dashboard to view last results (optional)
- Clear documentation, MIT license, and production-ready .gitignore

> ⚠️ Only use this scanner on systems you own or have explicit permission to test.

## Quick start (CLI)

```bash
# Clone this repo
git clone https://github.com/<yourname>/W4R-LOCK.git
cd W4R-LOCK

# (optional) create venv
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies (for dashboard / extras)
pip install -r requirements.txt

# Run a quick scan
python3 port_scanner.py --target 127.0.0.1

# Save results to CSV and JSON, grab banners
python3 port_scanner.py --target 192.168.100.208 --ports 1-1024 --threads 200 --grab --output results.json --csv results.csv

# Run web dashboard (optional)
export FLASK_APP=dashboard.app
flask run --host=0.0.0.0 --port=5000
# visit http://127.0.0.1:5000 to view last results
```

## Files of interest
- `port_scanner.py` — main CLI scanner (threaded, banner grabbing, CSV/JSON output)
- `dashboard/app.py` — minimal Flask web UI for quick visualization of `results.json`
- `README.md` — this file
- `LICENSE` — MIT license
- `.gitignore` — ignores common Python artifacts
- `requirements.txt` — Flask (optional) and other deps

## Usage notes & ethics
- Always get permission before scanning third-party hosts.
- Lower thread counts and higher timeouts when scanning fragile or remote systems.
- Consider rate-limiting and obey robots/network policies when running large scans.

---
Made with ❤️ by **W4R-LOCK**
