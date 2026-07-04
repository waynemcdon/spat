#!/usr/bin/env python3
"""
SPAT GUI — Security Posture Analysis Tool Dashboard
by Antibody Cyber Technology, LLC
"""

import os
import sys
import shutil
import subprocess
import threading
import time
import webbrowser
import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
from datetime import datetime

# ── Paths ──────────────────────────────────────────────────────────────────
if getattr(sys, "frozen", False):
    # Running as a PyInstaller .exe — sys.executable is the exe itself, not python.exe
    HERE   = os.path.dirname(sys.executable)               # folder containing the .exe
    SCRIPT = os.path.join(sys._MEIPASS, "spat_cli", "spat_cli.py")
    # Find the real Python interpreter on the system
    _py = shutil.which("python") or shutil.which("python3")
    if not _py:
        # Fallback: common Windows user install location
        _py = os.path.expandvars(
            r"%LOCALAPPDATA%\Programs\Python\Python312\python.exe")
    PYTHON = _py if (os.path.isfile(_py or "")) else "python"
else:
    HERE   = os.path.dirname(os.path.abspath(__file__))    # C:\tmp (dev)
    SCRIPT = os.path.join(HERE, "spat_cli", "spat_cli.py")
    PYTHON = sys.executable

# ── .env loader ───────────────────────────────────────────────────────────
_ENV_KEYS = ("VIRUSTOTAL_API_KEY", "URLHAUS_AUTH_KEY")

def _load_dotenv() -> dict:
    """Return a copy of os.environ augmented with keys from the .env file.

    Search order for the .env file (first match wins for each key):
      1. Environment already set (no override needed).
      2. Next to spat_gui.exe  — dist\\spat_gui\\.env  (frozen)
      3. _internal\\spat_cli\\.env inside the bundle  (frozen, bundled copy)
      4. Next to spat_gui.py  — C:\\tmp\\.env          (dev)
      5. Next to spat_cli.py  — C:\\tmp\\spat_cli\\.env (dev)
    """
    env = os.environ.copy()

    # Build candidate .env paths
    candidates = []
    if getattr(sys, "frozen", False):
        candidates.append(os.path.join(HERE, ".env"))                         # next to exe
        candidates.append(os.path.join(sys._MEIPASS, "spat_cli", ".env"))    # bundled copy
    # dev / fallback paths (harmless when frozen too)
    candidates.append(os.path.join(HERE, ".env"))
    candidates.append(os.path.join(os.path.dirname(SCRIPT), ".env"))

    for env_path in dict.fromkeys(candidates):   # deduplicate, preserve order
        if not os.path.isfile(env_path):
            continue
        try:
            with open(env_path, encoding="utf-8") as fh:
                for raw in fh:
                    line = raw.strip()
                    if not line or line.startswith("#") or "=" not in line:
                        continue
                    key, _, val = line.partition("=")
                    key = key.strip()
                    if key not in _ENV_KEYS:
                        continue
                    # Only inject if not already set in the real environment
                    if key not in os.environ:
                        env[key] = val.strip().strip('"').strip("'")
        except OSError:
            pass

    return env


# ── Colour palette (dark theme) ────────────────────────────────────────────
BG        = "#0d1117"
BG2       = "#161b22"
BG3       = "#21262d"
ACCENT    = "#e94560"
ACCENT2   = "#58a6ff"
FG        = "#e6edf3"
FG_DIM    = "#8b949e"
GREEN     = "#2ea043"
YELLOW    = "#d29922"
RED       = "#f85149"
FONT_MONO = ("Consolas", 10)
FONT_UI   = ("Segoe UI", 10)
FONT_HEAD = ("Segoe UI", 12, "bold")

# ── Scan profiles ──────────────────────────────────────────────────────────
# Each profile maps to a list of CLI args passed to spat_cli.py.
# Profiles differ in WHAT is scanned, not just output format.
PROFILES = {
    # ── Standard tiers (vary scan depth) ──────────────────────────────────
    "Full Scan  (web + SSH + threat intel)":    [],
    "Standard  (web + SSH, no threat intel)":   ["--skip-vt"],
    "Web Only  (no SSH, no threat intel)":       ["--skip-ssh", "--skip-vt"],
    "Web + Threat Intel  (no SSH)":              ["--skip-ssh"],
    "SSH Only":                                  ["--ssh-only"],
    # ── Output variants ───────────────────────────────────────────────────
    "Full Scan + JSON report":                   ["--json", "report.json"],
    "Standard + JSON report":                    ["--skip-vt",
                                                  "--json", "report.json"],
}

# ── ANSI stripping ─────────────────────────────────────────────────────────
import re as _re
_ANSI = _re.compile(r"\x1b\[[0-9;]*[mK]")

def strip_ansi(text: str) -> str:
    return _ANSI.sub("", text)


class SpatGUI:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.process = None
        self._last_html_path = ""   # set when a report is actually written
        self._scan_ts = ""            # timestamp injected into report filenames
        self._build_ui()

    # ── UI construction ────────────────────────────────────────────────────

    def _build_ui(self):
        r = self.root
        r.title("SPAT — Security Posture Analysis Tool")
        r.configure(bg=BG)
        r.resizable(True, True)
        r.minsize(820, 620)

        # ── Window icon ──────────────────────────────────────────────────
        here = os.path.dirname(os.path.abspath(__file__))
        ico  = os.path.join(here, "anticon.ico")
        png  = os.path.join(here, "anticon.png")
        try:
            if os.path.exists(ico):
                r.iconbitmap(ico)
            elif os.path.exists(png):
                from PIL import Image, ImageTk
                _icon = ImageTk.PhotoImage(Image.open(png))
                r.iconphoto(True, _icon)
                self._icon_img = _icon          # prevent GC
        except Exception:
            pass

        # ── Header ──────────────────────────────────────────────────────
        hdr = tk.Frame(r, bg=BG, pady=0)
        hdr.pack(fill="x")
        self._banner_img = self._load_banner()
        if self._banner_img:
            tk.Label(hdr, image=self._banner_img, bg=BG, bd=0
                     ).pack(side="left", padx=0)
            tk.Label(hdr,
                     text="by Antibody Cyber Technology, LLC",
                     bg=BG, fg=FG_DIM, font=FONT_UI
                     ).pack(side="right", padx=12)
        else:
            tk.Label(hdr, text="  SPAT CLI", bg=ACCENT, fg="white",
                     font=("Consolas", 16, "bold")).pack(side="left", padx=8)
            tk.Label(hdr,
                     text="Security Posture Analysis Tool  •  Antibody Cyber Technology, LLC",
                     bg=ACCENT, fg="white", font=FONT_UI).pack(side="left")

        # ── Controls panel ──────────────────────────────────────────────
        ctrl = tk.Frame(r, bg=BG2, padx=14, pady=12)
        ctrl.pack(fill="x")

        # Row 1 — hostname + scan profile
        row1 = tk.Frame(ctrl, bg=BG2)
        row1.pack(fill="x", pady=(0, 8))

        tk.Label(row1, text="TARGET HOSTNAME", bg=BG2, fg=FG_DIM,
                 font=FONT_UI).grid(row=0, column=0, sticky="w")
        tk.Label(row1, text="Scan profile", bg=BG2, fg=FG_DIM,
                 font=FONT_UI).grid(row=0, column=2, sticky="w", padx=(20, 0))

        self.hostname_var = tk.StringVar(value="example.com")
        hostname_entry = tk.Entry(row1, textvariable=self.hostname_var,
                                  bg=BG3, fg=FG, insertbackground=FG,
                                  font=FONT_UI, width=30, relief="flat",
                                  highlightthickness=1,
                                  highlightcolor=ACCENT2,
                                  highlightbackground=BG3)
        hostname_entry.grid(row=1, column=0, sticky="ew", ipady=5)
        hostname_entry.bind("<KeyRelease>", lambda e: self._refresh_cmd())

        self.profile_var = tk.StringVar(value=list(PROFILES.keys())[0])
        self.profile_var.trace_add("write", lambda *_: self._refresh_open_btn())
        profile_cb = ttk.Combobox(row1, textvariable=self.profile_var,
                                  values=list(PROFILES.keys()),
                                  state="readonly", width=38,
                                  font=FONT_UI)
        profile_cb.grid(row=1, column=2, sticky="ew", ipady=3, padx=(20, 0))
        profile_cb.bind("<<ComboboxSelected>>", lambda e: self._refresh_cmd())

        row1.columnconfigure(0, weight=2)
        row1.columnconfigure(2, weight=3)

        # Row 2 — SSH port + optional overrides
        row2 = tk.Frame(ctrl, bg=BG2)
        row2.pack(fill="x", pady=(0, 8))

        tk.Label(row2, text="SSH port", bg=BG2, fg=FG_DIM,
                 font=FONT_UI).grid(row=0, column=0, sticky="w")
        tk.Label(row2, text="JSON output", bg=BG2, fg=FG_DIM,
                 font=FONT_UI).grid(row=0, column=2, sticky="w", padx=(20, 0))
        tk.Label(row2, text="HTML output", bg=BG2, fg=FG_DIM,
                 font=FONT_UI).grid(row=0, column=4, sticky="w", padx=(20, 0))

        self.port_var = tk.StringVar(value="22")
        tk.Entry(row2, textvariable=self.port_var, bg=BG3, fg=FG,
                 insertbackground=FG, font=FONT_UI, width=6, relief="flat",
                 highlightthickness=1, highlightcolor=ACCENT2,
                 highlightbackground=BG3
                 ).grid(row=1, column=0, sticky="w", ipady=5)
        self.port_var.trace_add("write", lambda *_: self._refresh_cmd())

        self.json_var = tk.StringVar(value="")
        json_entry = tk.Entry(row2, textvariable=self.json_var,
                              bg=BG3, fg=FG, insertbackground=FG,
                              font=FONT_UI, width=22, relief="flat",
                              highlightthickness=1, highlightcolor=ACCENT2,
                              highlightbackground=BG3)
        json_entry.grid(row=1, column=2, sticky="ew", ipady=5, padx=(20, 4))
        self.json_var.trace_add("write", lambda *_: self._refresh_cmd())
        tk.Button(row2, text="…", bg=BG3, fg=FG, font=FONT_UI,
                  relief="flat", cursor="hand2",
                  command=lambda: self._browse(self.json_var, "json")
                  ).grid(row=1, column=3)

        self.html_var = tk.StringVar(value="")
        html_entry = tk.Entry(row2, textvariable=self.html_var,
                              bg=BG3, fg=FG, insertbackground=FG,
                              font=FONT_UI, width=22, relief="flat",
                              highlightthickness=1, highlightcolor=ACCENT2,
                              highlightbackground=BG3)
        html_entry.grid(row=1, column=4, sticky="ew", ipady=5, padx=(20, 4))
        self.html_var.trace_add("write", lambda *_: (self._refresh_cmd(), self._refresh_open_btn()))
        tk.Button(row2, text="…", bg=BG3, fg=FG, font=FONT_UI,
                  relief="flat", cursor="hand2",
                  command=lambda: self._browse(self.html_var, "html")
                  ).grid(row=1, column=5)

        row2.columnconfigure(2, weight=1)
        row2.columnconfigure(4, weight=1)

        # Row 3 — command preview
        row3 = tk.Frame(ctrl, bg=BG2)
        row3.pack(fill="x", pady=(0, 4))
        tk.Label(row3, text="Command", bg=BG2, fg=FG_DIM,
                 font=FONT_UI).pack(side="left")
        self.cmd_label = tk.Label(row3, text="", bg=BG2, fg=ACCENT2,
                                  font=FONT_MONO, anchor="w")
        self.cmd_label.pack(side="left", padx=(8, 0))

        # Row 4 — buttons
        row4 = tk.Frame(ctrl, bg=BG2)
        row4.pack(fill="x")

        self.run_btn = tk.Button(
            row4, text="▶  Run Scan", bg=ACCENT, fg="white",
            font=("Segoe UI", 10, "bold"), relief="flat",
            cursor="hand2", padx=18, pady=6,
            activebackground="#c73652", activeforeground="white",
            command=self._run)
        self.run_btn.pack(side="left")

        self.stop_btn = tk.Button(
            row4, text="■  Stop", bg=BG3, fg=RED,
            font=FONT_UI, relief="flat", cursor="hand2",
            padx=12, pady=6, state="disabled",
            command=self._stop)
        self.stop_btn.pack(side="left", padx=(8, 0))

        tk.Button(row4, text="Clear output", bg=BG3, fg=FG_DIM,
                  font=FONT_UI, relief="flat", cursor="hand2",
                  padx=12, pady=6,
                  command=self._clear).pack(side="left", padx=(8, 0))

        self.open_btn = tk.Button(row4, text="Open report.html", bg=BG3, fg=ACCENT2,
                  font=FONT_UI, relief="flat", cursor="hand2",
                  padx=12, pady=6,
                  command=self._open_html)
        self.open_btn.pack(side="right")
        self._refresh_open_btn()

        wp_lbl = tk.Label(row4, text="Whitepaper ↗", bg=BG2, fg=FG_DIM,
                          font=FONT_UI, cursor="hand2")
        wp_lbl.pack(side="right", padx=(0, 8))
        wp_lbl.bind("<Button-1>", lambda e: webbrowser.open(
            "https://spatcyber.com/static/SPAT_Whitepaper.pdf"))

        # ── Status bar ───────────────────────────────────────────────────
        self.status_var = tk.StringVar(value="Ready")
        status_bar = tk.Label(r, textvariable=self.status_var,
                               bg=BG3, fg=FG_DIM, font=FONT_UI,
                               anchor="w", padx=10, pady=4)
        status_bar.pack(side="bottom", fill="x")

        # ── Output terminal ──────────────────────────────────────────────
        out_frame = tk.Frame(r, bg=BG)
        out_frame.pack(fill="both", expand=True, padx=10, pady=(6, 0))

        tk.Label(out_frame, text="Output", bg=BG, fg=FG_DIM,
                 font=FONT_UI).pack(anchor="w")

        self.output = scrolledtext.ScrolledText(
            out_frame, bg=BG, fg=FG, font=FONT_MONO,
            insertbackground=FG, relief="flat",
            state="disabled", wrap="word",
            highlightthickness=1, highlightbackground=BG3)
        self.output.pack(fill="both", expand=True)

        # colour tags
        self.output.tag_config("pass",   foreground=GREEN)
        self.output.tag_config("fail",   foreground=RED)
        self.output.tag_config("warn",   foreground=YELLOW)
        self.output.tag_config("info",   foreground=ACCENT2)
        self.output.tag_config("header", foreground=ACCENT2,
                               font=("Consolas", 10, "bold"))
        self.output.tag_config("score",  foreground=ACCENT,
                               font=("Consolas", 11, "bold"))
        self.output.tag_config("dim",    foreground=FG_DIM)

        # Style combobox
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("TCombobox",
                        fieldbackground=BG3, background=BG3,
                        foreground=FG, selectbackground=BG3,
                        selectforeground=FG, arrowcolor=FG_DIM)
        style.map("TCombobox", fieldbackground=[("readonly", BG3)],
                  foreground=[("readonly", FG)])

        self._refresh_cmd()

    # ── Helpers ────────────────────────────────────────────────────────────

    def _build_args(self) -> list[str]:
        hostname = self.hostname_var.get().strip()
        profile_args = list(PROFILES[self.profile_var.get()])

        # Merge per-field overrides (override profile's json/html if set).
        # All relative filenames get the per-scan timestamp so every scan writes
        # a unique file and the browser always opens a fresh tab.
        # Only absolute paths (e.g. C:\scans\custom.html) are left unchanged.
        json_override = self.json_var.get().strip()
        if json_override:
            # Ensure .json extension
            if not os.path.splitext(json_override)[1]:
                json_override += ".json"
            resolved = self._resolve_report(json_override)
            try:
                idx = profile_args.index("--json")
                profile_args[idx + 1] = resolved
            except ValueError:
                profile_args += ["--json", resolved]
        else:
            try:
                idx = profile_args.index("--json")
                profile_args[idx + 1] = self._resolve_report(profile_args[idx + 1])
            except ValueError:
                pass

        html_override = self.html_var.get().strip()
        if html_override:
            # Ensure .html extension
            if not os.path.splitext(html_override)[1]:
                html_override += ".html"
            resolved = self._resolve_report(html_override)
            try:
                idx = profile_args.index("--html")
                profile_args[idx + 1] = resolved
            except ValueError:
                profile_args += ["--html", resolved]
        else:
            try:
                idx = profile_args.index("--html")
                profile_args[idx + 1] = self._resolve_report(profile_args[idx + 1])
            except ValueError:
                pass

        port = self.port_var.get().strip()
        if port and port != "22":
            profile_args = ["--ssh-port", port] + profile_args

        # Always ensure an HTML report is written — if neither the profile nor
        # the override field provides --html, add it now with the default name.
        if "--html" not in profile_args:
            profile_args += ["--html", self._resolve_report("report.html")]

        # Normalise to full URL so the CLI receives https://hostname and
        # the report title renders as "Scan Report: https://hostname".
        if not hostname.startswith(("https://", "http://")):
            hostname = "https://" + hostname
        return [PYTHON, SCRIPT, hostname] + profile_args

    def _resolve_report(self, filename: str) -> str:
        """Make a report filename absolute and inject the per-scan timestamp.

        e.g. "report.html"          -> "C:\\tmp\\report_20260420_175600.html"
             "C:\\scans\\out.html"  -> "C:\\scans\\out_20260420_175600.html"

        This guarantees every scan writes a unique file so the browser always
        opens a new tab instead of focusing a stale cached tab.
        """
        if not filename:
            return ""
        # Make absolute first
        if not os.path.isabs(filename):
            filename = os.path.join(HERE, filename)
        # Inject timestamp
        if self._scan_ts:
            base, ext = os.path.splitext(filename)
            if not base.endswith(self._scan_ts):
                filename = f"{base}_{self._scan_ts}{ext}"
        return filename

    def _profile_has_html(self) -> bool:
        """Return True if the current profile+override will produce an HTML file."""
        if self.html_var.get().strip():
            return True
        return "--html" in PROFILES.get(self.profile_var.get(), [])

    def _refresh_open_btn(self):
        """Open button is always enabled — every scan produces an HTML report."""
        try:
            self.open_btn.config(state="normal", fg=ACCENT2, cursor="hand2")
        except AttributeError:
            pass  # button not yet created

    def _refresh_cmd(self):
        args = self._build_args()
        # Show a short readable version
        short = " ".join(
            os.path.basename(a) if a == SCRIPT else a
            for a in args
        )
        self.cmd_label.config(text=short)

    # ── Banner ─────────────────────────────────────────────────────────────

    def _load_banner(self):
        """Load spat_logo_banner.png; generate it if missing."""
        here = os.path.dirname(os.path.abspath(__file__))
        png = os.path.join(here, "spat_logo_banner.png")
        # Always regenerate to pick up any code changes
        png = self._generate_banner(png)
        if png and os.path.exists(png):
            try:
                from PIL import Image, ImageTk
                img = Image.open(png).convert("RGBA")
                self._pil_banner = img          # prevent GC
                return ImageTk.PhotoImage(img)
            except Exception:
                pass
        return None

    @staticmethod
    def _generate_banner(out_path: str) -> str:
        """Render spat_logo_banner.png using ant_shield000.png + SPAT text."""
        try:
            from PIL import Image, ImageDraw, ImageFont

            W, H = 720, 90
            img = Image.new("RGBA", (W, H), (13, 17, 23, 255))   # #0d1117
            draw = ImageDraw.Draw(img)

            # ── Shield image ─────────────────────────────────────────────
            here = os.path.dirname(out_path)
            shield_path = os.path.join(here, "ant_shield000.png")
            text_x = 95     # fallback x if shield image not found
            if os.path.exists(shield_path):
                sh = Image.open(shield_path).convert("RGBA")
                # Remove white / near-white background
                px = sh.load()
                for y in range(sh.height):
                    for x in range(sh.width):
                        r, g, b, a = px[x, y]
                        if r > 235 and g > 235 and b > 235:
                            px[x, y] = (r, g, b, 0)
                sh_h = H - 8
                sh_w = int(sh.width * sh_h / sh.height)
                sh = sh.resize((sh_w, sh_h), Image.LANCZOS)
                img.paste(sh, (4, 4), sh)
                text_x = sh_w + 12
            else:
                # Fallback: drawn polygon
                shield = [(45,6),(79,18),(79,52),(62,72),(45,85),(28,72),(11,52),(11,18)]
                inner  = [(45,11),(74,22),(74,52),(59,67),(45,80),(31,67),(16,52),(16,22)]
                draw.polygon(shield, fill=(26,0,0,255))
                draw.line(shield + [shield[0]], fill=(204,17,0,255), width=2)
                draw.line(inner  + [inner[0]],  fill=(136,0,0,180),  width=1)

            # ── Fonts — fall back gracefully ─────────────────────────────
            def _font(path, size):
                try:
                    return ImageFont.truetype(path, size)
                except Exception:
                    try:
                        return ImageFont.load_default(size=size)
                    except TypeError:
                        return ImageFont.load_default()

            f_big = _font("C:/Windows/Fonts/ariblk.ttf", 50)
            f_sub = _font("C:/Windows/Fonts/arialbd.ttf", 22)

            draw.text((text_x,       8),  "SPAT",                              fill="#cc1100", font=f_big)
            draw.text((text_x + 140, 36), "\u2013 Security Posture Analysis Tool", fill="#cc1100", font=f_sub)

            img.save(out_path)
            return out_path
        except Exception:
            return ""

    def _browse(self, var: tk.StringVar, ext: str):
        path = filedialog.asksaveasfilename(
            defaultextension=f".{ext}",
            filetypes=[(f"{ext.upper()} files", f"*.{ext}"), ("All files", "*.*")],
            initialdir=os.path.dirname(SCRIPT),
        )
        if path:
            var.set(path)

    def _open_html(self):
        path = self._last_html_path
        if not path:
            messagebox.showinfo("Not found",
                                "No HTML report has been saved yet.\n\n"
                                "Run a scan first, then click Open report.html.")
            return

        path = os.path.normpath(path)
        if os.path.exists(path):
            try:
                os.startfile(path)
            except AttributeError:
                webbrowser.open_new_tab("file:///" + path.replace("\\", "/"))
        else:
            messagebox.showinfo("Not found",
                                f"No HTML report found at:\n{path}\n\n"
                                "Run a scan first, then click Open report.html.")

    # ── Scan execution ─────────────────────────────────────────────────────

    def _run(self):
        hostname = self.hostname_var.get().strip()
        if not hostname:
            messagebox.showwarning("No target", "Please enter a target URL (e.g. https://example.com).")
            return

        self._clear()
        self._scan_ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        self._last_html_path = ""
        args = self._build_args()
        # Pre-set the HTML path from the args we just built — this is authoritative.
        # The parse-from-output fallback in _stream is kept but this is the primary source.
        try:
            idx = args.index("--html")
            self._last_html_path = os.path.normpath(args[idx + 1])
        except (ValueError, IndexError):
            pass
        self._append(f"$ {' '.join(args)}\n", "dim")
        self._append("─" * 60 + "\n", "dim")

        self.run_btn.config(state="disabled")
        self.stop_btn.config(state="normal")
        self.status_var.set(f"Scanning {hostname}…")

        thread = threading.Thread(target=self._stream, args=(args,), daemon=True)
        thread.start()

    def _stream(self, args: list[str]):
        try:
            self.process = subprocess.Popen(
                args,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="replace",
                cwd=HERE,   # ensure relative paths resolve to C:\tmp
                env=_load_dotenv(),   # propagate API keys from .env into subprocess
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
            for line in self.process.stdout:
                clean = strip_ansi(line)
                # Capture the path whenever the CLI confirms an HTML report was saved
                if "html report saved:" in clean.lower():
                    saved = clean.split(":", 1)[-1].strip()
                    saved = os.path.normpath(saved) if saved else ""
                    if saved:
                        self._last_html_path = saved
                tag = self._classify(clean)
                self.root.after(0, self._append, clean, tag)

            self.process.wait()
            rc = self.process.returncode
        except Exception as e:
            self.root.after(0, self._append, f"\nError: {e}\n", "fail")
            rc = -1
        finally:
            self.root.after(0, self._on_done, rc)

    def _classify(self, line: str) -> str:
        """Pick a colour tag based on line content."""
        l = line.lower()
        if any(x in l for x in ("─", "═", "security score", "grade:")):
            return "score" if "score" in l or "grade" in l else "header"
        if "✔" in line or " pass" in l:
            return "pass"
        if "✘" in line or " fail" in l:
            return "fail"
        if "⚠" in line or " warn" in l:
            return "warn"
        if "ℹ" in line or "[info]" in l or "info" in l:
            return "info"
        if line.startswith("  [") or "checking" in l:
            return "dim"
        return ""

    def _on_done(self, rc: int):
        self.process = None
        self.run_btn.config(state="normal")
        self.stop_btn.config(state="disabled")
        ts = datetime.now().strftime("%H:%M:%S")
        if rc == 0:
            self.status_var.set(f"✔ Scan complete — no failures  [{ts}]")
            self._append(f"\n✔ Finished with no failures  ({ts})\n", "pass")
        elif rc == 1:
            self.status_var.set(f"⚠ Scan complete — failures detected  [{ts}]")
            self._append(f"\n⚠ Finished — one or more failures detected  ({ts})\n", "warn")
        else:
            self.status_var.set(f"✘ Scan aborted  [{ts}]")
            self._append(f"\n✘ Aborted  ({ts})\n", "fail")

    def _stop(self):
        if self.process:
            self.process.terminate()
            self.status_var.set("Stopped by user")

    def _clear(self):
        self.output.config(state="normal")
        self.output.delete("1.0", "end")
        self.output.config(state="disabled")

    def _append(self, text: str, tag: str = ""):
        self.output.config(state="normal")
        if tag:
            self.output.insert("end", text, tag)
        else:
            self.output.insert("end", text)
        self.output.see("end")
        self.output.config(state="disabled")


# ── Entry point ────────────────────────────────────────────────────────────

def main():
    root = tk.Tk()
    SpatGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
