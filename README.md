# SPAT CLI — Security Posture Analysis Tool

Command-line security scanner by **Antibody Cyber Technology, LLC**  
Mirrors the SPAT web tool at https://spatcyber.com

---

## Quick Start

### 1. Install dependencies

From `C:\tmp\` in Git Bash:

```bash
/c/Users/wayne/AppData/Local/Programs/Python/Python312/python.exe -m pip install -r spat_cli/requirements.txt
```

> Installs `rich` for enhanced colour output. The tool works without it.

### 2. Launch the GUI dashboard

```bash
/c/Users/wayne/AppData/Local/Programs/Python/Python312/python.exe spat_gui.py
```

### 3. Or run the CLI directly

```bash
/c/Users/wayne/AppData/Local/Programs/Python/Python312/python.exe spat_cli/spat_cli.py urlcybersecurity.com
```

---

## GUI Dashboard — How To Use

### Window Layout

```
┌─────────────────────────────────────────────────────────┐
│  [SPAT logo banner]        by Antibody Cyber Tech, LLC  │  ← Header
├─────────────────────────────────────────────────────────┤
│  Target hostname          │  Scan profile               │
│  [ urlcybersecurity.com ] │  [ Full Scan (web + SSH) ▼] │  ← Row 1
├─────────────────────────────────────────────────────────┤
│  SSH port │  JSON output    […] │  HTML output      […] │  ← Row 2
│  [ 22   ] │  [ report.json    ] │  [ report.html      ] │
├─────────────────────────────────────────────────────────┤
│  Command: python.exe spat_cli.py urlcybersecurity.com   │  ← Preview
├─────────────────────────────────────────────────────────┤
│  [▶ Run Scan]  [■ Stop]  [Clear output]  [Open HTML →] │  ← Buttons
├─────────────────────────────────────────────────────────┤
│                                                         │
│   Output terminal (colour-coded, scrollable)            │  ← Output
│                                                         │
├─────────────────────────────────────────────────────────┤
│  Ready                                                  │  ← Status bar
└─────────────────────────────────────────────────────────┘
```

---

### Step-by-Step: Running a Scan

**Step 1 — Enter your target**  
Click the **Target hostname** field, clear `example.com`, and type the domain you want to scan (e.g. `urlcybersecurity.com`). Do not include `https://` — just the bare hostname.

**Step 2 — Choose a scan profile**  
Click the **Scan profile** dropdown and select one of the preset modes:

| Profile | What it runs |
|---------|-------------|
| Full Scan (web + SSH) | All checks — DNS, TLS, HTTP headers, ports, robots.txt, SSH |
| Web Only (--skip-ssh) | Everything except SSH checks |
| SSH Only (--ssh-only) | SSH checks only (banner, algorithms, auth methods) |
| Quiet (warnings & failures only) | Full scan, hides passed checks |
| Full Scan + JSON report | Saves results to `report.json` |
| Full Scan + HTML report | Saves results to `report.html` |
| Full Scan + JSON + HTML reports | Saves both report files |
| Quiet + JSON + HTML reports | Quiet mode with both report files saved |

**Step 3 — (Optional) Override settings**  
- **SSH port** — change from `22` if the target uses a non-standard SSH port (e.g. `2222`)
- **JSON output** — type a filename or click `…` to choose a save location
- **HTML output** — type a filename or click `…` to choose a save location

> Any filename you enter here overrides the profile's default filename.

**Step 4 — Check the Command preview**  
The **Command** line updates live as you type, showing the exact command that will be run. Verify it looks correct before proceeding.

**Step 5 — Click ▶ Run Scan**  
The scan starts immediately. Output streams line-by-line in the terminal pane, colour-coded:

| Colour | Meaning |
|--------|---------|
| 🟢 Green | Check passed |
| 🟡 Yellow | Warning — review recommended |
| 🔴 Red | Failure — action required |
| 🔵 Blue | Informational |
| Grey | Progress / section headers |

**Step 6 — Read the results**  
Each finding shows:
- Status icon (✔ / ⚠ / ✘ / ℹ)
- Finding name and category
- Description of what was found
- Evidence (raw data)
- Fix recommendation (for warnings and failures)

A **Security Score (0–100)** and **Grade (A–F)** are shown at the end.

**Step 7 — Open the HTML report**  
If you selected an HTML output profile, click **Open report.html** (top-right button) to open the report in your browser. The report contains the full findings table with colour-coded severity.

**Step 8 — Stop or clear**  
- **■ Stop** — terminates the scan mid-run
- **Clear output** — clears the terminal pane for the next scan

---

## CLI Usage Reference

All commands run from `C:\tmp\`:

```bash
# Full scan (web + SSH checks)
/c/Users/wayne/AppData/Local/Programs/Python/Python312/python.exe spat_cli/spat_cli.py urlcybersecurity.com

# Custom SSH port
/c/Users/wayne/AppData/Local/Programs/Python/Python312/python.exe spat_cli/spat_cli.py example.com --ssh-port 2222

# SSH checks only
/c/Users/wayne/AppData/Local/Programs/Python/Python312/python.exe spat_cli/spat_cli.py example.com --ssh-only

# Skip SSH, web checks only
/c/Users/wayne/AppData/Local/Programs/Python/Python312/python.exe spat_cli/spat_cli.py example.com --skip-ssh

# Save reports
/c/Users/wayne/AppData/Local/Programs/Python/Python312/python.exe spat_cli/spat_cli.py example.com --json report.json --html report.html

# Quiet mode (failures and warnings only)
/c/Users/wayne/AppData/Local/Programs/Python/Python312/python.exe spat_cli/spat_cli.py example.com --quiet
```

> **Tip:** To use `python` directly in Git Bash, add Python to PATH:
> ```bash
> export PATH="/c/Users/wayne/AppData/Local/Programs/Python/Python312:$PATH"
> ```
> Add that line to `~/.bashrc` to make it permanent.

---

## Checks Performed

### Web Checks
| Check | Description |
|-------|-------------|
| DNS Resolution | Resolves hostname, detects failures |
| TLS/SSL Certificate | Expiry, validity, issuer |
| TLS Protocols | Detects SSLv2/3, TLSv1.0, TLSv1.1 |
| HTTP Security Headers | HSTS, CSP, X-Frame-Options, etc. |
| HTTP→HTTPS Redirect | Checks for forced HTTPS redirect |
| Port Scan | 20 common ports, flags risky ones |
| robots.txt | Presence check |

### SSH Checks
| Check | Description |
|-------|-------------|
| SSH Protocol Version | Detects SSHv1 (broken) |
| SSH Banner | Version disclosure, outdated OpenSSH |
| Key Exchange Algorithms | Flags weak KEX (e.g. group1-sha1) |
| Encryption Ciphers | Flags 3DES, CBC, arcfour, etc. |
| MAC Algorithms | Flags MD5/SHA1-based MACs |
| Host Key Types | Flags DSA host keys |
| Password Authentication | Warns if password auth enabled |

---

## Understanding the Score

| Score | Grade | Meaning |
|-------|-------|---------|
| 80–100 | A | Strong security posture |
| 65–79 | B | Good, minor improvements needed |
| 50–64 | C | Moderate risks present |
| 0–49 | F | Significant vulnerabilities found |

Each failed check deducts points. Fix the highlighted issues and re-scan to improve your score.

---

## Exit Codes
- `0` — No failures found
- `1` — One or more failures detected

## Requirements
- Python 3.8+
- `curl` (for HTTP checks)
- `ssh` (for auth method probing)
- `rich` (optional, for coloured output — install via requirements.txt)
- `Pillow` (optional, for GUI banner image — install via requirements.txt)
