"""Modern native desktop application (blue & white) for VirusTotal / AbuseIPDB checks."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import queue
import subprocess
import sys
import threading
import time
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import tkinter.font as tkfont
from typing import Any, Optional

import customtkinter as ctk

from vt_ioc_checker import __version__
from vt_ioc_checker.abuseipdb import (
    DEFAULT_MAX_AGE_DAYS,
    STATUS_CHECKED,
    STATUS_ERROR as ABUSE_ERROR,
    STATUS_INVALID as ABUSE_INVALID,
    STATUS_NOT_CHECKED as ABUSE_NOT_CHECKED,
    AbuseIPDBAuthError,
    AbuseIPDBClient,
    AbuseIPDBQuotaExceededError,
    AbuseIPDBRequestError,
    AbuseIPDBResult,
    write_abuseipdb_csv,
)
from vt_ioc_checker.cancel import CancelToken, OperationCancelled
from vt_ioc_checker.config import (
    ConfigError,
    get_api_settings_raw,
    load_abuseipdb_settings,
    load_settings,
    save_api_settings,
    test_abuseipdb_api_connection,
    test_vt_api_connection,
)
from vt_ioc_checker.ioc_parser import IocType, make_entry, read_raw_values
from vt_ioc_checker.report import (
    STATUS_ERROR,
    STATUS_INVALID,
    STATUS_NOT_CHECKED,
    ReportMeta,
    ReportRow,
    write_report,
)
from vt_ioc_checker.verdict import DEFAULT_VENDOR, build_verdict
from vt_ioc_checker.vt_client import (
    RateLimiter,
    VTAuthError,
    VTClient,
    VTQuotaExceededError,
    VTRequestError,
)

PROJECT_ROOT = Path(__file__).resolve().parent.parent
OUTPUT_DIR = PROJECT_ROOT / "data" / "output"
SAMPLE_INPUT = PROJECT_ROOT / "data" / "input" / "sample_iocs.txt"

# Blue & white design tokens
C = {
    "bg": "#F3F6FC",
    "card": "#FFFFFF",
    "border": "#E1E8F5",
    "sidebar": "#0B1F4B",
    "sidebar_hover": "#16316E",
    "primary": "#2563EB",
    "primary_hover": "#1D4FD8",
    "primary_soft": "#E8F0FF",
    "text": "#0F172A",
    "muted": "#64748B",
    "danger": "#DC2626",
    "danger_hover": "#B91C1C",
    "ok": "#16A34A",
    "track": "#E2E8F0",
}

# tag -> (foreground, background) for table rows
ROW_TAGS = {
    "queued": ("#64748B", "#FFFFFF"),
    "checking": ("#1D4ED8", "#E8F0FF"),
    "detected": ("#B91C1C", "#FEE2E2"),
    "clean": ("#15803D", "#DCFCE7"),
    "unknown": ("#B45309", "#FEF3C7"),
    "error": ("#7F1D1D", "#F1F5F9"),
    "invalid": ("#64748B", "#F1F5F9"),
    "notchecked": ("#64748B", "#F1F5F9"),
}


def _env_path() -> Optional[Path]:
    path = PROJECT_ROOT / ".env"
    return path if path.is_file() else None


def _key_ready(loader) -> bool:
    try:
        loader(_env_path())
        return True
    except ConfigError:
        return False


def _fmt_duration(seconds: float) -> str:
    seconds = int(max(0, seconds))
    if seconds >= 3600:
        return f"{seconds // 3600}h {seconds % 3600 // 60}m"
    if seconds >= 60:
        return f"{seconds // 60}m {seconds % 60:02d}s"
    return f"{seconds}s"


def _style_table() -> str:
    """Configures a flat, modern ttk Treeview and returns the font family."""
    style = ttk.Style()
    try:
        style.theme_use("clam")
    except tk.TclError:
        pass
    family = tkfont.nametofont("TkDefaultFont").actual("family")
    style.configure(
        "Modern.Treeview",
        background=C["card"],
        fieldbackground=C["card"],
        foreground=C["text"],
        rowheight=36,
        borderwidth=0,
        font=(family, 12),
    )
    style.configure(
        "Modern.Treeview.Heading",
        background="#F1F5FB",
        foreground=C["muted"],
        relief="flat",
        borderwidth=0,
        padding=(12, 10),
        font=(family, 11, "bold"),
    )
    style.map(
        "Modern.Treeview",
        background=[("selected", C["primary_soft"])],
        foreground=[("selected", C["text"])],
    )
    style.map("Modern.Treeview.Heading", background=[("active", "#E8EEF9")])
    style.layout("Modern.Treeview", [("Treeview.treearea", {"sticky": "nswe"})])
    style.configure(
        "Modern.Vertical.TScrollbar",
        background="#CBD5E1",
        troughcolor=C["card"],
        bordercolor=C["card"],
        arrowsize=0,
        relief="flat",
    )
    return family


class ToolPage(ctk.CTkFrame):
    """Shared layout and run-loop for one analysis tool."""

    TITLE = ""
    SUBTITLE = ""
    FILE_LABEL = "Input list"
    START_TEXT = "Start analysis"
    EXPORT_TEXT = "Export"
    COLUMNS: list[tuple[str, str, int]] = []
    STATS: list[tuple[str, str, str]] = []

    def __init__(self, master: Any, app: "WorkbenchApp") -> None:
        super().__init__(master, fg_color=C["bg"], corner_radius=0)
        self.app = app
        self.events: queue.Queue = queue.Queue()
        self.token: Optional[CancelToken] = None
        self.running = False
        self.records: list[Any] = []
        self.states: list[str] = []
        self.phase = ""
        self.wait: Optional[float] = None
        self.started_at = 0.0
        self.done_count = 0
        self.total_todo = 0

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(4, weight=1)
        self._build_header()
        self._build_input_card()
        self._build_stats()
        self._build_progress()
        self._build_table()
        self.after(60, self._pump)

    # ---------------- subclass hooks ----------------
    def build_options(self, parent: ctk.CTkFrame) -> None:
        raise NotImplementedError

    def prepare(self, path: str):
        """Return (records, states, job) or None (after showing an error)."""
        raise NotImplementedError

    def run(self, job: Any, token: CancelToken, emit) -> None:
        raise NotImplementedError

    def describe(self, record: Any, state: str) -> tuple[tuple, str]:
        raise NotImplementedError

    def category(self, record: Any, state: str) -> Optional[str]:
        raise NotImplementedError

    def do_export(self, filename: str) -> None:
        raise NotImplementedError

    export_filetypes: list[tuple[str, str]] = []
    export_ext = ""

    # ---------------- layout ----------------
    def _card(self, row: int, pady=(0, 14)) -> ctk.CTkFrame:
        card = ctk.CTkFrame(
            self,
            fg_color=C["card"],
            corner_radius=14,
            border_width=1,
            border_color=C["border"],
        )
        card.grid(row=row, column=0, sticky="nsew", padx=28, pady=pady)
        return card

    def _build_header(self) -> None:
        head = ctk.CTkFrame(self, fg_color="transparent")
        head.grid(row=0, column=0, sticky="ew", padx=28, pady=(24, 14))
        ctk.CTkLabel(
            head,
            text=self.TITLE,
            font=ctk.CTkFont(size=26, weight="bold"),
            text_color=C["text"],
        ).pack(anchor="w")
        ctk.CTkLabel(
            head,
            text=self.SUBTITLE,
            font=ctk.CTkFont(size=13),
            text_color=C["muted"],
        ).pack(anchor="w", pady=(2, 0))

    def _build_input_card(self) -> None:
        card = self._card(1)
        card.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            card,
            text=self.FILE_LABEL,
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color=C["muted"],
        ).grid(row=0, column=0, sticky="w", padx=20, pady=(16, 4))

        row = ctk.CTkFrame(card, fg_color="transparent")
        row.grid(row=1, column=0, sticky="ew", padx=20)
        row.grid_columnconfigure(0, weight=1)

        self.file_var = tk.StringVar(
            value=str(SAMPLE_INPUT) if SAMPLE_INPUT.is_file() else ""
        )
        ctk.CTkEntry(
            row,
            textvariable=self.file_var,
            height=40,
            corner_radius=10,
            border_color=C["border"],
            fg_color="#F8FAFD",
            text_color=C["text"],
            placeholder_text="Choose a .txt, .csv or .xlsx file",
        ).grid(row=0, column=0, sticky="ew", padx=(0, 10))
        ctk.CTkButton(
            row,
            text="Browse",
            width=110,
            height=40,
            corner_radius=10,
            fg_color=C["primary_soft"],
            hover_color="#D6E4FF",
            text_color=C["primary"],
            font=ctk.CTkFont(size=13, weight="bold"),
            command=self._browse,
        ).grid(row=0, column=1)

        opts = ctk.CTkFrame(card, fg_color="transparent")
        opts.grid(row=2, column=0, sticky="ew", padx=20, pady=(14, 18))
        opts.grid_columnconfigure(0, weight=1)
        left = ctk.CTkFrame(opts, fg_color="transparent")
        left.grid(row=0, column=0, sticky="w")
        self.build_options(left)

        self.start_btn = ctk.CTkButton(
            opts,
            text=self.START_TEXT,
            width=170,
            height=42,
            corner_radius=10,
            fg_color=C["primary"],
            hover_color=C["primary_hover"],
            font=ctk.CTkFont(size=14, weight="bold"),
            command=self._toggle,
        )
        self.start_btn.grid(row=0, column=1, sticky="e")

    def _build_stats(self) -> None:
        wrap = ctk.CTkFrame(self, fg_color="transparent")
        wrap.grid(row=2, column=0, sticky="ew", padx=28, pady=(0, 14))
        self.stat_labels: dict[str, ctk.CTkLabel] = {}
        for i, (key, caption, color) in enumerate(self.STATS):
            wrap.grid_columnconfigure(i, weight=1, uniform="stat")
            tile = ctk.CTkFrame(
                wrap,
                fg_color=C["card"],
                corner_radius=14,
                border_width=1,
                border_color=C["border"],
            )
            tile.grid(
                row=0, column=i, sticky="ew", padx=(0 if i == 0 else 8, 0)
            )
            value = ctk.CTkLabel(
                tile,
                text="0",
                font=ctk.CTkFont(size=28, weight="bold"),
                text_color=color,
            )
            value.pack(anchor="w", padx=18, pady=(12, 0))
            ctk.CTkLabel(
                tile,
                text=caption,
                font=ctk.CTkFont(size=12),
                text_color=C["muted"],
            ).pack(anchor="w", padx=18, pady=(0, 12))
            self.stat_labels[key] = value

    def _build_progress(self) -> None:
        card = self._card(3)
        card.grid_columnconfigure(0, weight=1)
        top = ctk.CTkFrame(card, fg_color="transparent")
        top.grid(row=0, column=0, sticky="ew", padx=20, pady=(14, 8))
        top.grid_columnconfigure(0, weight=1)
        self.status_label = ctk.CTkLabel(
            top,
            text="Ready. Choose a file and press Start.",
            font=ctk.CTkFont(size=13),
            text_color=C["text"],
            anchor="w",
        )
        self.status_label.grid(row=0, column=0, sticky="w")
        self.eta_label = ctk.CTkLabel(
            top, text="", font=ctk.CTkFont(size=12), text_color=C["muted"]
        )
        self.eta_label.grid(row=0, column=1, sticky="e")
        self.bar = ctk.CTkProgressBar(
            card,
            height=8,
            corner_radius=4,
            progress_color=C["primary"],
            fg_color=C["track"],
        )
        self.bar.set(0)
        self.bar.grid(row=1, column=0, sticky="ew", padx=20, pady=(0, 16))

    def _build_table(self) -> None:
        card = self._card(4, pady=(0, 24))
        card.grid_columnconfigure(0, weight=1)
        card.grid_rowconfigure(1, weight=1)

        bar = ctk.CTkFrame(card, fg_color="transparent")
        bar.grid(row=0, column=0, sticky="ew", padx=20, pady=(14, 10))
        self.count_label = ctk.CTkLabel(
            bar,
            text="Results",
            font=ctk.CTkFont(size=15, weight="bold"),
            text_color=C["text"],
        )
        self.count_label.pack(side="left")
        self.export_btn = ctk.CTkButton(
            bar,
            text=self.EXPORT_TEXT,
            height=34,
            corner_radius=9,
            fg_color=C["primary"],
            hover_color=C["primary_hover"],
            font=ctk.CTkFont(size=12, weight="bold"),
            command=self._export,
        )
        self.export_btn.pack(side="right")
        self.clear_btn = ctk.CTkButton(
            bar,
            text="Clear",
            width=80,
            height=34,
            corner_radius=9,
            fg_color="transparent",
            hover_color=C["primary_soft"],
            text_color=C["muted"],
            border_width=1,
            border_color=C["border"],
            font=ctk.CTkFont(size=12, weight="bold"),
            command=self._clear,
        )
        self.clear_btn.pack(side="right", padx=(0, 8))

        holder = tk.Frame(card, bg=C["card"])
        holder.grid(row=1, column=0, sticky="nsew", padx=1, pady=(0, 14))
        holder.grid_columnconfigure(0, weight=1)
        holder.grid_rowconfigure(0, weight=1)
        cols = [c[0] for c in self.COLUMNS]
        self.tree = ttk.Treeview(
            holder,
            columns=cols,
            show="headings",
            style="Modern.Treeview",
            selectmode="browse",
        )
        for cid, heading, width in self.COLUMNS:
            self.tree.heading(cid, text=heading, anchor="w")
            self.tree.column(
                cid, width=width, anchor="w", stretch=(cid == cols[0])
            )
        for tag, (fg, bg) in ROW_TAGS.items():
            self.tree.tag_configure(tag, foreground=fg, background=bg)
        scroll = ttk.Scrollbar(
            holder,
            orient="vertical",
            command=self.tree.yview,
            style="Modern.Vertical.TScrollbar",
        )
        self.tree.configure(yscrollcommand=scroll.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        scroll.grid(row=0, column=1, sticky="ns")

    # ---------------- actions ----------------
    def _browse(self) -> None:
        name = filedialog.askopenfilename(
            title="Select input file",
            filetypes=[
                ("Supported files", "*.txt *.csv *.xlsx"),
                ("Text", "*.txt"),
                ("CSV", "*.csv"),
                ("Excel", "*.xlsx"),
            ],
        )
        if name:
            self.file_var.set(name)

    def _toggle(self) -> None:
        if self.running:
            if self.token is not None:
                self.token.cancel()
            self.start_btn.configure(text="Stopping...", state="disabled")
            self._set_status("Stopping. Finishing the current step...")
            return
        self._start()

    def _make_token(self) -> CancelToken:
        last: list[Optional[int]] = [None]

        def on_wait(remaining: float) -> None:
            value = int(remaining)
            if value != last[0]:
                last[0] = value
                self.events.put(("wait", remaining))

        return CancelToken(on_wait=on_wait)

    def _start(self) -> None:
        path = self.file_var.get().strip()
        if not path or not Path(path).is_file():
            messagebox.showerror("File not found", f"Cannot open:\n{path}")
            return
        prepared = self.prepare(path)
        if prepared is None:
            return
        records, states, job = prepared
        self.records, self.states = records, states
        self._populate()
        self.token = self._make_token()
        self.running = True
        self.done_count = 0
        self.total_todo = sum(1 for s in states if s == "queued")
        self.started_at = time.monotonic()
        self.bar.set(0)
        self.eta_label.configure(text="")
        self.start_btn.configure(
            text="Stop",
            fg_color=C["danger"],
            hover_color=C["danger_hover"],
            state="normal",
        )
        self.clear_btn.configure(state="disabled")
        self.export_btn.configure(state="disabled")
        self.app.set_busy(True)
        self._set_status("Starting...")
        token = self.token
        threading.Thread(
            target=self._worker, args=(job, token), daemon=True
        ).start()

    def _worker(self, job: Any, token: CancelToken) -> None:
        try:
            self.run(job, token, self.events.put)
        except OperationCancelled:
            pass
        except Exception as exc:
            self.events.put(
                ("error", f"Unexpected error ({type(exc).__name__}).")
            )
        finally:
            self.events.put(("done",))

    def _populate(self) -> None:
        self.tree.delete(*self.tree.get_children())
        for i, (rec, state) in enumerate(zip(self.records, self.states)):
            values, tag = self.describe(rec, state)
            self.tree.insert("", "end", iid=str(i), values=values, tags=(tag,))
        self._refresh_stats()

    def _clear(self) -> None:
        if self.running:
            return
        self.tree.delete(*self.tree.get_children())
        self.records, self.states = [], []
        self.bar.set(0)
        self.eta_label.configure(text="")
        self._set_status("Ready. Choose a file and press Start.")
        self._refresh_stats()

    def _export(self) -> None:
        if not self.records:
            messagebox.showinfo("Export", "There are no results to export yet.")
            return
        filename = filedialog.asksaveasfilename(
            title="Export results",
            defaultextension=self.export_ext,
            filetypes=self.export_filetypes,
        )
        if not filename:
            return
        try:
            self.do_export(filename)
        except Exception as exc:
            messagebox.showerror("Export failed", str(exc))
            return
        messagebox.showinfo("Export complete", f"Saved to:\n{filename}")

    # ---------------- event loop ----------------
    def _set_status(self, text: str) -> None:
        self.phase = text
        self._render_status()

    def _render_status(self) -> None:
        text = self.phase
        if self.running and self.wait is not None:
            text = f"{self.phase}  -  waiting for API rate limit ({int(self.wait) + 1}s)"
        self.status_label.configure(text=text)

    def _refresh_stats(self) -> None:
        counts: dict[str, int] = {k: 0 for k in self.stat_labels}
        for rec, state in zip(self.records, self.states):
            cat = self.category(rec, state)
            if cat in counts:
                counts[cat] += 1
        counts["total"] = len(self.records)
        for key, label in self.stat_labels.items():
            label.configure(text=str(counts.get(key, 0)))
        self.count_label.configure(text=f"Results  ({len(self.records)})")

    def _pump(self) -> None:
        try:
            if not self.winfo_exists():
                return
        except Exception:
            return

        dirty = False
        try:
            for _ in range(200):
                event = self.events.get_nowait()
                kind = event[0]
                if kind == "update":
                    _, i, record, state = event
                    self.records[i] = record
                    self.states[i] = state
                    values, tag = self.describe(record, state)
                    if self.tree.exists(str(i)):
                        self.tree.item(str(i), values=values, tags=(tag,))
                        if state == "checking":
                            self.tree.see(str(i))
                    if state == "done":
                        self.done_count += 1
                    dirty = True
                elif kind == "progress":
                    _, text = event
                    self._set_status(text)
                    self._update_progress()
                elif kind == "wait":
                    remaining = event[1]
                    self.wait = remaining if remaining > 0 else None
                    self._render_status()
                elif kind == "error":
                    messagebox.showerror("Analysis stopped", event[1])
                elif kind == "done":
                    self._finish()
                    dirty = True
        except queue.Empty:
            pass
        if dirty:
            self._refresh_stats()
            self._update_progress()

        try:
            if self.winfo_exists():
                self.after(60, self._pump)
        except Exception:
            pass

    def _update_progress(self) -> None:
        if not self.running or self.total_todo == 0:
            return
        fraction = min(1.0, self.done_count / self.total_todo)
        self.bar.set(fraction)
        elapsed = time.monotonic() - self.started_at
        eta = ""
        if self.done_count >= 1:
            per = elapsed / self.done_count
            eta = f"  -  about {_fmt_duration(per * (self.total_todo - self.done_count))} left"
        self.eta_label.configure(
            text=f"{self.done_count} of {self.total_todo} done{eta}"
        )

    def _finish(self) -> None:
        cancelled = bool(self.token and self.token.cancelled)
        for i, state in enumerate(self.states):
            if state in ("queued", "checking"):
                rec = self._not_checked_record(self.records[i])
                self.records[i] = rec
                self.states[i] = "done"
                values, tag = self.describe(rec, "done")
                if self.tree.exists(str(i)):
                    self.tree.item(str(i), values=values, tags=(tag,))
        skipped = self.total_todo - self.done_count
        self.running = False
        self.wait = None
        self.start_btn.configure(
            text=self.START_TEXT,
            fg_color=C["primary"],
            hover_color=C["primary_hover"],
            state="normal",
        )
        self.clear_btn.configure(state="normal")
        self.export_btn.configure(state="normal")
        self.app.set_busy(False)
        self.bar.set(1.0 if skipped <= 0 else self.done_count / max(1, self.total_todo))
        if cancelled or skipped > 0:
            self._set_status(
                f"Stopped. {self.done_count} checked, {max(0, skipped)} left as Not checked."
            )
        else:
            self._set_status(f"Finished. {self.done_count} checked.")
        self.eta_label.configure(text="")

    def _not_checked_record(self, record: Any) -> Any:
        raise NotImplementedError


class VirusTotalPage(ToolPage):
    TITLE = "VirusTotal IOC Analyzer"
    SUBTITLE = "Check IPs, domains, URLs and file hashes, with an optional fresh reanalysis."
    FILE_LABEL = "IOC list"
    START_TEXT = "Start analysis"
    EXPORT_TEXT = "Export to Excel"
    COLUMNS = [
        ("ioc", "IOC", 560),
        ("status", "Vendor status", 190),
        ("score", "VT score", 130),
    ]
    STATS = [
        ("total", "Total IOCs", C["text"]),
        ("detected", "Detected", "#DC2626"),
        ("clean", "Clean", "#16A34A"),
        ("unknown", "Unknown", "#D97706"),
    ]
    export_filetypes = [("Excel workbook", "*.xlsx")]
    export_ext = ".xlsx"

    def build_options(self, parent: ctk.CTkFrame) -> None:
        ctk.CTkLabel(
            parent,
            text="Vendor",
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color=C["muted"],
        ).grid(row=0, column=0, sticky="w")
        self.vendor_var = tk.StringVar(value=DEFAULT_VENDOR)
        ctk.CTkOptionMenu(
            parent,
            variable=self.vendor_var,
            values=["Sophos", "Microsoft", "Kaspersky", "Fortinet", "CrowdStrike", "ESET-NOD32", "BitDefender"],
            width=170,
            height=36,
            corner_radius=9,
            fg_color=C["primary_soft"],
            button_color=C["primary_soft"],
            button_hover_color="#D6E4FF",
            text_color=C["primary"],
            dropdown_fg_color=C["card"],
            dropdown_text_color=C["text"],
            dropdown_hover_color=C["primary_soft"],
        ).grid(row=1, column=0, sticky="w", padx=(0, 22), pady=(4, 0))

        ctk.CTkLabel(
            parent,
            text="Fresh reanalysis",
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color=C["muted"],
        ).grid(row=0, column=1, sticky="w")
        sw = ctk.CTkFrame(parent, fg_color="transparent")
        sw.grid(row=1, column=1, sticky="w", pady=(4, 0))
        self.reanalyze_var = tk.BooleanVar(value=True)
        ctk.CTkSwitch(
            sw,
            text="Re-scan on VirusTotal before reading the result",
            variable=self.reanalyze_var,
            progress_color=C["primary"],
            text_color=C["text"],
            font=ctk.CTkFont(size=13),
            command=self._update_hint,
        ).pack(side="left")
        self.hint = ctk.CTkLabel(
            parent,
            text="",
            font=ctk.CTkFont(size=12),
            text_color=C["muted"],
            anchor="w",
        )
        self.hint.grid(row=2, column=0, columnspan=2, sticky="w", pady=(6, 0))
        self._update_hint()

    def _update_hint(self) -> None:
        try:
            rpm = load_settings(_env_path()).requests_per_minute
        except ConfigError:
            rpm = 4
        per_request = 60.0 / rpm
        if self.reanalyze_var.get():
            self.hint.configure(
                text=f"Reanalysis uses about 3 requests per IOC. At {rpm} requests/min that is roughly {_fmt_duration(per_request * 3)} per IOC."
            )
        else:
            self.hint.configure(
                text=f"Reads the latest stored result: 1 request per IOC, roughly {_fmt_duration(per_request)} each at {rpm} requests/min."
            )

    def prepare(self, path: str):
        try:
            settings = load_settings(_env_path())
        except ConfigError as exc:
            if messagebox.askyesno(
                "VirusTotal Key Missing",
                f"{exc}\n\nWould you like to open API Settings to configure your key now?",
            ):
                self.app.show("settings")
            return None
        try:
            raw = read_raw_values(path)
        except Exception as exc:
            messagebox.showerror("Cannot read file", str(exc))
            return None
        seen: set[str] = set()
        records: list[ReportRow] = []
        states: list[str] = []
        entries = []
        for item in raw:
            entry = make_entry(item)
            if entry.value in seen:
                continue
            seen.add(entry.value)
            entries.append(entry)
            if entry.ioc_type == IocType.INVALID:
                records.append(
                    ReportRow(ioc=entry.raw, ioc_type="Invalid", vendor_status=STATUS_INVALID)
                )
                states.append("done")
            else:
                records.append(
                    ReportRow(
                        ioc=entry.value,
                        ioc_type=entry.ioc_type.value,
                        vendor_status=STATUS_NOT_CHECKED,
                    )
                )
                states.append("queued")
        if not entries:
            messagebox.showinfo("Nothing to check", "The file has no indicators.")
            return None
        job = {
            "entries": entries,
            "states": list(states),
            "settings": settings,
            "vendor": self.vendor_var.get().strip(),
            "reanalyze": bool(self.reanalyze_var.get()),
        }
        return records, states, job

    def run(self, job, token: CancelToken, emit) -> None:
        settings = job["settings"]
        vendor = job["vendor"]
        client = VTClient(
            settings.api_key,
            RateLimiter(settings.requests_per_minute, sleep=token.sleep),
            sleep=token.sleep,
            reanalyze=job["reanalyze"],
        )
        todo = [i for i, s in enumerate(job["states"]) if s == "queued"]
        for n, i in enumerate(todo, start=1):
            token.check()
            entry = job["entries"][i]
            pending = ReportRow(
                ioc=entry.value, ioc_type=entry.ioc_type.value, vendor_status=STATUS_NOT_CHECKED
            )
            emit(("update", i, pending, "checking"))
            emit(("progress", f"Checking {n} of {len(todo)}: {entry.value[:70]}"))
            try:
                result = client.lookup(entry.ioc_type, entry.value)
            except (VTAuthError, VTQuotaExceededError) as exc:
                emit(("error", str(exc)))
                return
            except VTRequestError as exc:
                row = ReportRow(
                    ioc=entry.value,
                    ioc_type=entry.ioc_type.value,
                    vendor_status=STATUS_ERROR,
                    vt_score="Error",
                    note=str(exc),
                )
                emit(("update", i, row, "done"))
                continue
            except Exception as exc:
                row = ReportRow(
                    ioc=entry.value,
                    ioc_type=entry.ioc_type.value,
                    vendor_status=STATUS_ERROR,
                    vt_score="Error",
                    note=f"Unexpected error ({type(exc).__name__})",
                )
                emit(("update", i, row, "done"))
                continue
            verdict = build_verdict(result, vendor)
            row = ReportRow(
                ioc=entry.value,
                ioc_type=entry.ioc_type.value,
                vendor_status=verdict.vendor_status.value,
                vt_score=verdict.score if result.found else "Unknown",
                vt_malicious=verdict.malicious_count,
                vt_last_analysis=verdict.last_analysis,
            )
            emit(("update", i, row, "done"))

    def describe(self, record: ReportRow, state: str):
        if state == "queued":
            return (record.ioc, "Queued", ""), "queued"
        if state == "checking":
            return (record.ioc, "Checking...", ""), "checking"
        tag = {
            "Detected": "detected",
            "Clean": "clean",
            "Unknown": "unknown",
            "Error": "error",
            "Invalid": "invalid",
        }.get(record.vendor_status, "notchecked")
        return (record.ioc, record.vendor_status, record.vt_score), tag

    def category(self, record: ReportRow, state: str):
        if state != "done":
            return None
        return {"Detected": "detected", "Clean": "clean", "Unknown": "unknown"}.get(
            record.vendor_status
        )

    def _not_checked_record(self, record: ReportRow) -> ReportRow:
        return ReportRow(
            ioc=record.ioc, ioc_type=record.ioc_type, vendor_status=STATUS_NOT_CHECKED
        )

    def do_export(self, filename: str) -> None:
        meta = ReportMeta(
            vendor=self.vendor_var.get().strip(),
            input_name=Path(self.file_var.get()).name,
            generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        )
        write_report(filename, self.records, meta)


class AbuseIPDBPage(ToolPage):
    TITLE = "AbuseIPDB Bulk IP Check"
    SUBTITLE = "Look up abuse confidence, country and domain for a list of IP addresses."
    FILE_LABEL = "IP list"
    START_TEXT = "Run bulk check"
    EXPORT_TEXT = "Export to CSV"
    COLUMNS = [
        ("ip", "IP address", 300),
        ("score", "Abuse score", 160),
        ("country", "Country", 140),
        ("domain", "Domain", 320),
    ]
    STATS = [
        ("total", "Total IPs", C["text"]),
        ("high", "High risk (80%+)", "#DC2626"),
        ("moderate", "Suspicious (1-79%)", "#D97706"),
        ("clean", "Clean (0%)", "#16A34A"),
    ]
    export_filetypes = [("CSV file", "*.csv")]
    export_ext = ".csv"

    def build_options(self, parent: ctk.CTkFrame) -> None:
        ctk.CTkLabel(
            parent,
            text="Report age",
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color=C["muted"],
        ).grid(row=0, column=0, sticky="w")
        self.age_var = tk.StringVar(value=f"{DEFAULT_MAX_AGE_DAYS} days")
        ctk.CTkOptionMenu(
            parent,
            variable=self.age_var,
            values=["30 days", "90 days", "180 days", "365 days"],
            width=140,
            height=36,
            corner_radius=9,
            fg_color=C["primary_soft"],
            button_color=C["primary_soft"],
            button_hover_color="#D6E4FF",
            text_color=C["primary"],
            dropdown_fg_color=C["card"],
            dropdown_text_color=C["text"],
            dropdown_hover_color=C["primary_soft"],
        ).grid(row=1, column=0, sticky="w", padx=(0, 22), pady=(4, 0))

        ctk.CTkLabel(
            parent,
            text="Lookup limit (optional)",
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color=C["muted"],
        ).grid(row=0, column=1, sticky="w")
        self.cap_var = tk.StringVar(value="")
        ctk.CTkEntry(
            parent,
            textvariable=self.cap_var,
            width=140,
            height=36,
            corner_radius=9,
            border_color=C["border"],
            fg_color="#F8FAFD",
            text_color=C["text"],
            placeholder_text="No limit",
        ).grid(row=1, column=1, sticky="w", pady=(4, 0))

    def prepare(self, path: str):
        try:
            settings = load_abuseipdb_settings(_env_path())
        except ConfigError as exc:
            if messagebox.askyesno(
                "AbuseIPDB Key Missing",
                f"{exc}\n\nWould you like to open API Settings to configure your key now?",
            ):
                self.app.show("settings")
            return None
        try:
            raw = read_raw_values(path)
        except Exception as exc:
            messagebox.showerror("Cannot read file", str(exc))
            return None
        cap_text = self.cap_var.get().strip()
        cap: Optional[int] = None
        if cap_text:
            if not cap_text.isdigit() or int(cap_text) < 1:
                messagebox.showerror("Invalid limit", "Lookup limit must be a whole number of 1 or more.")
                return None
            cap = int(cap_text)
        seen: set[str] = set()
        records: list[AbuseIPDBResult] = []
        states: list[str] = []
        for item in raw:
            entry = make_entry(item)
            key = entry.value if entry.ioc_type == IocType.IP else entry.raw
            if key in seen:
                continue
            seen.add(key)
            if entry.ioc_type != IocType.IP:
                records.append(
                    AbuseIPDBResult(
                        ip_address=entry.raw, status=ABUSE_INVALID, error="Not a valid IP address"
                    )
                )
                states.append("done")
            else:
                records.append(
                    AbuseIPDBResult(ip_address=entry.value, status=ABUSE_NOT_CHECKED)
                )
                states.append("queued")
        if not records:
            messagebox.showinfo("Nothing to check", "The file has no indicators.")
            return None
        job = {
            "states": list(states),
            "settings": settings,
            "age": int(self.age_var.get().split()[0]),
            "cap": cap,
        }
        return records, states, job

    def run(self, job, token: CancelToken, emit) -> None:
        settings = job["settings"]
        client = AbuseIPDBClient(
            settings.api_key,
            RateLimiter(settings.requests_per_minute, sleep=token.sleep),
            sleep=token.sleep,
            max_age_in_days=job["age"],
        )
        todo = [i for i, s in enumerate(job["states"]) if s == "queued"]
        cap = job["cap"]
        if cap is not None:
            todo = todo[:cap]
        for n, i in enumerate(todo, start=1):
            token.check()
            ip = self.records[i].ip_address
            emit(("update", i, AbuseIPDBResult(ip_address=ip, status=ABUSE_NOT_CHECKED), "checking"))
            emit(("progress", f"Checking {n} of {len(todo)}: {ip}"))
            try:
                res = client.check_ip(ip)
            except (AbuseIPDBAuthError, AbuseIPDBQuotaExceededError) as exc:
                emit(("error", str(exc)))
                return
            except AbuseIPDBRequestError as exc:
                res = AbuseIPDBResult(ip_address=ip, status=ABUSE_ERROR, error=str(exc))
            emit(("update", i, res, "done"))

    def describe(self, record: AbuseIPDBResult, state: str):
        if state == "queued":
            return (record.ip_address, "Queued", "", ""), "queued"
        if state == "checking":
            return (record.ip_address, "Checking...", "", ""), "checking"
        if record.status == STATUS_CHECKED:
            score = record.abuse_score
            if score is None:
                return (record.ip_address, "Unknown", record.country, record.domain), "unknown"
            tag = "detected" if score >= 80 else "clean" if score == 0 else "unknown"
            return (record.ip_address, f"{score}%", record.country, record.domain), tag
        tag = "error" if record.status == ABUSE_ERROR else "invalid" if record.status == ABUSE_INVALID else "notchecked"
        return (record.ip_address, record.status, record.country, record.domain), tag

    def category(self, record: AbuseIPDBResult, state: str):
        if state != "done" or record.status != STATUS_CHECKED or record.abuse_score is None:
            return None
        score = record.abuse_score
        return "high" if score >= 80 else "clean" if score == 0 else "moderate"

    def _not_checked_record(self, record: AbuseIPDBResult) -> AbuseIPDBResult:
        return AbuseIPDBResult(ip_address=record.ip_address, status=ABUSE_NOT_CHECKED)

    def do_export(self, filename: str) -> None:
        write_abuseipdb_csv(filename, self.records)


class SettingsPage(ctk.CTkFrame):
    """Dedicated API Settings & Status Management Tab."""

    TITLE = "API Settings & Connections"
    SUBTITLE = "Configure, test, and save custom API keys and rate limits for all tools."

    def __init__(self, master: Any, app: "WorkbenchApp") -> None:
        super().__init__(master, fg_color=C["bg"], corner_radius=0)
        self.app = app

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        self._build_header()
        self._build_content()
        self.load_values()

    def _build_header(self) -> None:
        head = ctk.CTkFrame(self, fg_color="transparent")
        head.grid(row=0, column=0, sticky="ew", padx=28, pady=(24, 14))
        ctk.CTkLabel(
            head,
            text=self.TITLE,
            font=ctk.CTkFont(size=26, weight="bold"),
            text_color=C["text"],
        ).pack(anchor="w")
        ctk.CTkLabel(
            head,
            text=self.SUBTITLE,
            font=ctk.CTkFont(size=13),
            text_color=C["muted"],
        ).pack(anchor="w", pady=(2, 0))

    def _build_content(self) -> None:
        scroll = ctk.CTkScrollableFrame(
            self,
            fg_color="transparent",
            corner_radius=0,
        )
        scroll.grid(row=1, column=0, sticky="nsew", padx=28, pady=(0, 24))
        scroll.grid_columnconfigure(0, weight=1)

        # 1. VirusTotal Card
        self._build_vt_card(scroll)

        # 2. AbuseIPDB Card
        self._build_abuse_card(scroll)

        # 3. Actions Card
        self._build_actions_card(scroll)

    def _build_vt_card(self, parent: ctk.CTkFrame) -> None:
        card = ctk.CTkFrame(
            parent,
            fg_color=C["card"],
            corner_radius=14,
            border_width=1,
            border_color=C["border"],
        )
        card.grid(row=0, column=0, sticky="ew", pady=(0, 16))
        card.grid_columnconfigure(0, weight=1)

        # Header with Logo Badge
        top = ctk.CTkFrame(card, fg_color="transparent")
        top.grid(row=0, column=0, sticky="ew", padx=20, pady=(18, 12))
        top.grid_columnconfigure(1, weight=1)

        badge = ctk.CTkFrame(
            top, fg_color=C["primary"], corner_radius=8, width=34, height=34
        )
        badge.grid(row=0, column=0, padx=(0, 12))
        badge.pack_propagate(False)
        ctk.CTkLabel(
            badge, text="VT", text_color="white", font=ctk.CTkFont(size=12, weight="bold")
        ).pack(expand=True)

        names = ctk.CTkFrame(top, fg_color="transparent")
        names.grid(row=0, column=1, sticky="w")
        ctk.CTkLabel(
            names,
            text="VirusTotal API v3",
            font=ctk.CTkFont(size=16, weight="bold"),
            text_color=C["text"],
        ).pack(anchor="w")
        ctk.CTkLabel(
            names,
            text="Used for file hash, URL, domain, and IP reanalysis and detection verdicts.",
            font=ctk.CTkFont(size=12),
            text_color=C["muted"],
        ).pack(anchor="w")

        self.vt_status_pill = ctk.CTkLabel(
            top,
            text="Checking status...",
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color=C["muted"],
            fg_color=C["primary_soft"],
            corner_radius=8,
            padx=12,
            pady=4,
        )
        self.vt_status_pill.grid(row=0, column=2, sticky="e")

        # Fields
        fields = ctk.CTkFrame(card, fg_color="transparent")
        fields.grid(row=1, column=0, sticky="ew", padx=20, pady=(0, 16))
        fields.grid_columnconfigure(0, weight=1)

        # API Key
        ctk.CTkLabel(
            fields,
            text="API Key (VT_API_KEY)",
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color=C["muted"],
        ).grid(row=0, column=0, sticky="w", pady=(0, 4))

        key_box = ctk.CTkFrame(fields, fg_color="transparent")
        key_box.grid(row=1, column=0, sticky="ew", pady=(0, 12))
        key_box.grid_columnconfigure(0, weight=1)

        self.vt_key_var = tk.StringVar()
        self.vt_key_entry = ctk.CTkEntry(
            key_box,
            textvariable=self.vt_key_var,
            show="*",
            height=40,
            corner_radius=10,
            border_color=C["border"],
            fg_color="#F8FAFD",
            text_color=C["text"],
            placeholder_text="Enter your VirusTotal API key (64 characters)",
        )
        self.vt_key_entry.grid(row=0, column=0, sticky="ew", padx=(0, 8))

        self.vt_show_btn = ctk.CTkButton(
            key_box,
            text="Show",
            width=80,
            height=40,
            corner_radius=10,
            fg_color=C["primary_soft"],
            hover_color="#D6E4FF",
            text_color=C["primary"],
            font=ctk.CTkFont(size=12, weight="bold"),
            command=self._toggle_vt_show,
        )
        self.vt_show_btn.grid(row=0, column=1)

        # Rate Limit & Test Connection Row
        bot_row = ctk.CTkFrame(fields, fg_color="transparent")
        bot_row.grid(row=2, column=0, sticky="ew")
        bot_row.grid_columnconfigure(0, weight=1)

        rpm_box = ctk.CTkFrame(bot_row, fg_color="transparent")
        rpm_box.grid(row=0, column=0, sticky="w")

        ctk.CTkLabel(
            rpm_box,
            text="Requests Per Minute (RPM):",
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color=C["muted"],
        ).pack(side="left", padx=(0, 8))

        self.vt_rpm_var = tk.StringVar(value="4")
        self.vt_rpm_entry = ctk.CTkEntry(
            rpm_box,
            textvariable=self.vt_rpm_var,
            width=70,
            height=36,
            corner_radius=9,
            border_color=C["border"],
            fg_color="#F8FAFD",
            text_color=C["text"],
        )
        self.vt_rpm_entry.pack(side="left", padx=(0, 10))

        ctk.CTkLabel(
            rpm_box,
            text="(Free public key: 4 RPM / 500 daily. Enterprise key: set higher)",
            font=ctk.CTkFont(size=11),
            text_color=C["muted"],
        ).pack(side="left")

        self.vt_test_btn = ctk.CTkButton(
            bot_row,
            text="Test Connection",
            width=140,
            height=36,
            corner_radius=9,
            fg_color=C["primary_soft"],
            hover_color="#D6E4FF",
            text_color=C["primary"],
            font=ctk.CTkFont(size=12, weight="bold"),
            command=self._test_vt_connection,
        )
        self.vt_test_btn.grid(row=0, column=1, sticky="e")

        # Test Result Notification Line
        self.vt_test_result = ctk.CTkLabel(
            card,
            text="",
            font=ctk.CTkFont(size=12),
            text_color=C["muted"],
            anchor="w",
        )
        self.vt_test_result.grid(row=2, column=0, sticky="w", padx=20, pady=(0, 14))

    def _build_abuse_card(self, parent: ctk.CTkFrame) -> None:
        card = ctk.CTkFrame(
            parent,
            fg_color=C["card"],
            corner_radius=14,
            border_width=1,
            border_color=C["border"],
        )
        card.grid(row=1, column=0, sticky="ew", pady=(0, 16))
        card.grid_columnconfigure(0, weight=1)

        # Header with Logo Badge
        top = ctk.CTkFrame(card, fg_color="transparent")
        top.grid(row=0, column=0, sticky="ew", padx=20, pady=(18, 12))
        top.grid_columnconfigure(1, weight=1)

        badge = ctk.CTkFrame(
            top, fg_color=C["primary"], corner_radius=8, width=34, height=34
        )
        badge.grid(row=0, column=0, padx=(0, 12))
        badge.pack_propagate(False)
        ctk.CTkLabel(
            badge, text="IP", text_color="white", font=ctk.CTkFont(size=12, weight="bold")
        ).pack(expand=True)

        names = ctk.CTkFrame(top, fg_color="transparent")
        names.grid(row=0, column=1, sticky="w")
        ctk.CTkLabel(
            names,
            text="AbuseIPDB API v2",
            font=ctk.CTkFont(size=16, weight="bold"),
            text_color=C["text"],
        ).pack(anchor="w")
        ctk.CTkLabel(
            names,
            text="Used for bulk IP reputation, confidence scoring, country, and domain checks.",
            font=ctk.CTkFont(size=12),
            text_color=C["muted"],
        ).pack(anchor="w")

        self.abuse_status_pill = ctk.CTkLabel(
            top,
            text="Checking status...",
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color=C["muted"],
            fg_color=C["primary_soft"],
            corner_radius=8,
            padx=12,
            pady=4,
        )
        self.abuse_status_pill.grid(row=0, column=2, sticky="e")

        # Fields
        fields = ctk.CTkFrame(card, fg_color="transparent")
        fields.grid(row=1, column=0, sticky="ew", padx=20, pady=(0, 16))
        fields.grid_columnconfigure(0, weight=1)

        # API Key
        ctk.CTkLabel(
            fields,
            text="API Key (ABUSEIPDB_API_KEY)",
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color=C["muted"],
        ).grid(row=0, column=0, sticky="w", pady=(0, 4))

        key_box = ctk.CTkFrame(fields, fg_color="transparent")
        key_box.grid(row=1, column=0, sticky="ew", pady=(0, 12))
        key_box.grid_columnconfigure(0, weight=1)

        self.abuse_key_var = tk.StringVar()
        self.abuse_key_entry = ctk.CTkEntry(
            key_box,
            textvariable=self.abuse_key_var,
            show="*",
            height=40,
            corner_radius=10,
            border_color=C["border"],
            fg_color="#F8FAFD",
            text_color=C["text"],
            placeholder_text="Enter your AbuseIPDB API key (80 characters)",
        )
        self.abuse_key_entry.grid(row=0, column=0, sticky="ew", padx=(0, 8))

        self.abuse_show_btn = ctk.CTkButton(
            key_box,
            text="Show",
            width=80,
            height=40,
            corner_radius=10,
            fg_color=C["primary_soft"],
            hover_color="#D6E4FF",
            text_color=C["primary"],
            font=ctk.CTkFont(size=12, weight="bold"),
            command=self._toggle_abuse_show,
        )
        self.abuse_show_btn.grid(row=0, column=1)

        # Rate Limit & Test Connection Row
        bot_row = ctk.CTkFrame(fields, fg_color="transparent")
        bot_row.grid(row=2, column=0, sticky="ew")
        bot_row.grid_columnconfigure(0, weight=1)

        rpm_box = ctk.CTkFrame(bot_row, fg_color="transparent")
        rpm_box.grid(row=0, column=0, sticky="w")

        ctk.CTkLabel(
            rpm_box,
            text="Requests Per Minute (RPM):",
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color=C["muted"],
        ).pack(side="left", padx=(0, 8))

        self.abuse_rpm_var = tk.StringVar(value="60")
        self.abuse_rpm_entry = ctk.CTkEntry(
            rpm_box,
            textvariable=self.abuse_rpm_var,
            width=70,
            height=36,
            corner_radius=9,
            border_color=C["border"],
            fg_color="#F8FAFD",
            text_color=C["text"],
        )
        self.abuse_rpm_entry.pack(side="left", padx=(0, 10))

        ctk.CTkLabel(
            rpm_box,
            text="(Free tier: 1,000 checks/day. Standard burst: 60 RPM)",
            font=ctk.CTkFont(size=11),
            text_color=C["muted"],
        ).pack(side="left")

        self.abuse_test_btn = ctk.CTkButton(
            bot_row,
            text="Test Connection",
            width=140,
            height=36,
            corner_radius=9,
            fg_color=C["primary_soft"],
            hover_color="#D6E4FF",
            text_color=C["primary"],
            font=ctk.CTkFont(size=12, weight="bold"),
            command=self._test_abuse_connection,
        )
        self.abuse_test_btn.grid(row=0, column=1, sticky="e")

        # Test Result Notification Line
        self.abuse_test_result = ctk.CTkLabel(
            card,
            text="",
            font=ctk.CTkFont(size=12),
            text_color=C["muted"],
            anchor="w",
        )
        self.abuse_test_result.grid(row=2, column=0, sticky="w", padx=20, pady=(0, 14))

    def _build_actions_card(self, parent: ctk.CTkFrame) -> None:
        card = ctk.CTkFrame(
            parent,
            fg_color=C["card"],
            corner_radius=14,
            border_width=1,
            border_color=C["border"],
        )
        card.grid(row=2, column=0, sticky="ew", pady=(0, 16))
        card.grid_columnconfigure(0, weight=1)

        row = ctk.CTkFrame(card, fg_color="transparent")
        row.pack(fill="x", padx=20, pady=16)

        info_box = ctk.CTkFrame(row, fg_color="transparent")
        info_box.pack(side="left")
        ctk.CTkLabel(
            info_box,
            text="Security & Storage",
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color=C["text"],
        ).pack(anchor="w")
        ctk.CTkLabel(
            info_box,
            text="API keys are saved locally into your private .env file and never committed to Git.",
            font=ctk.CTkFont(size=12),
            text_color=C["muted"],
        ).pack(anchor="w")

        btn_box = ctk.CTkFrame(row, fg_color="transparent")
        btn_box.pack(side="right")

        self.reload_btn = ctk.CTkButton(
            btn_box,
            text="Reload",
            width=90,
            height=42,
            corner_radius=10,
            fg_color="transparent",
            hover_color=C["primary_soft"],
            text_color=C["muted"],
            border_width=1,
            border_color=C["border"],
            font=ctk.CTkFont(size=13, weight="bold"),
            command=self.load_values,
        )
        self.reload_btn.pack(side="left", padx=(0, 10))

        self.save_btn = ctk.CTkButton(
            btn_box,
            text="Save API Settings",
            width=180,
            height=42,
            corner_radius=10,
            fg_color=C["primary"],
            hover_color=C["primary_hover"],
            font=ctk.CTkFont(size=14, weight="bold"),
            command=self._save_settings,
        )
        self.save_btn.pack(side="left")

        self.save_result_label = ctk.CTkLabel(
            card,
            text="",
            font=ctk.CTkFont(size=12),
            text_color=C["ok"],
            anchor="w",
        )
        self.save_result_label.pack(anchor="w", padx=20, pady=(0, 14))

    def load_values(self) -> None:
        """Loads the current settings from .env into the input fields and updates status."""
        env_file = _env_path()
        data = get_api_settings_raw(env_file)

        self.vt_key_var.set(data["vt_api_key"])
        self.vt_rpm_var.set(str(data["vt_rpm"]))
        if data["vt_status"] == "Ready":
            self.vt_status_pill.configure(
                text="● Ready (Connected)",
                text_color=C["ok"],
                fg_color="#DCFCE7",
            )
        else:
            self.vt_status_pill.configure(
                text="● Not Configured",
                text_color="#DC2626",
                fg_color="#FEE2E2",
            )

        self.abuse_key_var.set(data["abuse_api_key"])
        self.abuse_rpm_var.set(str(data["abuse_rpm"]))
        if data["abuse_status"] == "Ready":
            self.abuse_status_pill.configure(
                text="● Ready (Connected)",
                text_color=C["ok"],
                fg_color="#DCFCE7",
            )
        else:
            self.abuse_status_pill.configure(
                text="● Not Configured",
                text_color="#DC2626",
                fg_color="#FEE2E2",
            )

        self.vt_test_result.configure(text="")
        self.abuse_test_result.configure(text="")
        self.save_result_label.configure(text="")

    def _toggle_vt_show(self) -> None:
        if self.vt_key_entry.cget("show") == "*":
            self.vt_key_entry.configure(show="")
            self.vt_show_btn.configure(text="Hide")
        else:
            self.vt_key_entry.configure(show="*")
            self.vt_show_btn.configure(text="Show")

    def _toggle_abuse_show(self) -> None:
        if self.abuse_key_entry.cget("show") == "*":
            self.abuse_key_entry.configure(show="")
            self.abuse_show_btn.configure(text="Hide")
        else:
            self.abuse_key_entry.configure(show="*")
            self.abuse_show_btn.configure(text="Show")

    def _test_vt_connection(self) -> None:
        key = self.vt_key_var.get().strip()
        if not key:
            self.vt_test_result.configure(
                text="Please enter a VirusTotal API key to test.",
                text_color="#DC2626",
            )
            return

        self.vt_test_btn.configure(text="Testing...", state="disabled")
        self.vt_test_result.configure(
            text="Testing VirusTotal API connection...", text_color=C["muted"]
        )

        def _worker() -> None:
            ok, msg = test_vt_api_connection(key)

            def _update() -> None:
                self.vt_test_btn.configure(text="Test Connection", state="normal")
                color = C["ok"] if ok else "#DC2626"
                self.vt_test_result.configure(text=msg, text_color=color)
                if ok:
                    self.vt_status_pill.configure(
                        text="● Ready (Verified)",
                        text_color=C["ok"],
                        fg_color="#DCFCE7",
                    )
                else:
                    self.vt_status_pill.configure(
                        text="● Auth Error",
                        text_color="#DC2626",
                        fg_color="#FEE2E2",
                    )

            self.after(0, _update)

        threading.Thread(target=_worker, daemon=True).start()

    def _test_abuse_connection(self) -> None:
        key = self.abuse_key_var.get().strip()
        if not key:
            self.abuse_test_result.configure(
                text="Please enter an AbuseIPDB API key to test.",
                text_color="#DC2626",
            )
            return

        self.abuse_test_btn.configure(text="Testing...", state="disabled")
        self.abuse_test_result.configure(
            text="Testing AbuseIPDB API connection...", text_color=C["muted"]
        )

        def _worker() -> None:
            ok, msg = test_abuseipdb_api_connection(key)

            def _update() -> None:
                self.abuse_test_btn.configure(
                    text="Test Connection", state="normal"
                )
                color = C["ok"] if ok else "#DC2626"
                self.abuse_test_result.configure(text=msg, text_color=color)
                if ok:
                    self.abuse_status_pill.configure(
                        text="● Ready (Verified)",
                        text_color=C["ok"],
                        fg_color="#DCFCE7",
                    )
                else:
                    self.abuse_status_pill.configure(
                        text="● Auth Error",
                        text_color="#DC2626",
                        fg_color="#FEE2E2",
                    )

            self.after(0, _update)

        threading.Thread(target=_worker, daemon=True).start()

    def _save_settings(self) -> None:
        vt_key = self.vt_key_var.get().strip()
        abuse_key = self.abuse_key_var.get().strip()

        vt_rpm_str = self.vt_rpm_var.get().strip()
        abuse_rpm_str = self.abuse_rpm_var.get().strip()

        try:
            vt_rpm = int(vt_rpm_str)
            if vt_rpm < 1 or vt_rpm > 1000:
                raise ValueError()
        except ValueError:
            messagebox.showerror(
                "Invalid Rate Limit",
                "VirusTotal RPM must be a whole number between 1 and 1000.",
            )
            return

        try:
            abuse_rpm = int(abuse_rpm_str)
            if abuse_rpm < 1 or abuse_rpm > 1000:
                raise ValueError()
        except ValueError:
            messagebox.showerror(
                "Invalid Rate Limit",
                "AbuseIPDB RPM must be a whole number between 1 and 1000.",
            )
            return

        try:
            env_file = _env_path() or (PROJECT_ROOT / ".env")
            save_api_settings(
                env_file,
                vt_api_key=vt_key,
                vt_rpm=vt_rpm,
                abuse_api_key=abuse_key,
                abuse_rpm=abuse_rpm,
            )
            self.save_result_label.configure(
                text=f"Settings successfully saved to {env_file.name}!",
                text_color=C["ok"],
            )
            self.load_values()
            self.app.refresh_sidebar_status()
            messagebox.showinfo(
                "Settings Saved",
                "API keys and rate limits have been saved successfully.\n"
                "Both analyzers are updated and ready to connect.",
            )
        except Exception as exc:
            messagebox.showerror("Save Error", f"Could not save settings: {exc}")


class WorkbenchApp(ctk.CTk):
    """Main window: sidebar navigation plus tool pages and settings."""

    def __init__(self) -> None:
        ctk.set_appearance_mode("light")
        ctk.set_default_color_theme("blue")
        super().__init__(fg_color=C["bg"])
        self.title("IOC Workbench")
        self.geometry("1240x860")
        self.minsize(1040, 720)
        _style_table()

        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)
        self._build_sidebar()

        self.container = ctk.CTkFrame(self, fg_color=C["bg"], corner_radius=0)
        self.container.grid(row=0, column=1, sticky="nsew")
        self.container.grid_columnconfigure(0, weight=1)
        self.container.grid_rowconfigure(0, weight=1)

        self.pages: dict[str, Any] = {
            "vt": VirusTotalPage(self.container, self),
            "abuse": AbuseIPDBPage(self.container, self),
            "settings": SettingsPage(self.container, self),
        }
        for page in self.pages.values():
            page.grid(row=0, column=0, sticky="nsew")
        self.show("vt")
        self.protocol("WM_DELETE_WINDOW", self._close)

    def _build_sidebar(self) -> None:
        bar = ctk.CTkFrame(self, fg_color=C["sidebar"], corner_radius=0, width=250)
        bar.grid(row=0, column=0, sticky="nsw")
        bar.grid_propagate(False)

        brand = ctk.CTkFrame(bar, fg_color="transparent")
        brand.pack(fill="x", padx=22, pady=(30, 24))
        badge = ctk.CTkFrame(brand, fg_color=C["primary"], corner_radius=11, width=40, height=40)
        badge.pack(side="left")
        badge.pack_propagate(False)
        ctk.CTkLabel(
            badge, text="IO", text_color="white", font=ctk.CTkFont(size=15, weight="bold")
        ).pack(expand=True)
        names = ctk.CTkFrame(brand, fg_color="transparent")
        names.pack(side="left", padx=12)
        ctk.CTkLabel(
            names, text="IOC Workbench", text_color="white", font=ctk.CTkFont(size=17, weight="bold")
        ).pack(anchor="w")
        ctk.CTkLabel(
            names, text=f"Version {__version__}", text_color="#8FA7D8", font=ctk.CTkFont(size=11)
        ).pack(anchor="w")

        # Navigation Buttons
        self.nav: dict[str, ctk.CTkButton] = {}
        for key, label in (
            ("vt", "VirusTotal Analyzer"),
            ("abuse", "AbuseIPDB Bulk Check"),
            ("settings", "API Settings"),
        ):
            btn = ctk.CTkButton(
                bar,
                text=label,
                anchor="w",
                height=44,
                corner_radius=10,
                fg_color="transparent",
                hover_color=C["sidebar_hover"],
                text_color="#DCE6FF",
                font=ctk.CTkFont(size=14, weight="bold"),
                command=lambda k=key: self.show(k),
            )
            btn.pack(fill="x", padx=16, pady=4)
            self.nav[key] = btn

        # Footer Area
        footer = ctk.CTkFrame(bar, fg_color="transparent")
        footer.pack(side="bottom", fill="x", padx=22, pady=24)

        ctk.CTkButton(
            footer,
            text="Open reports folder",
            height=36,
            corner_radius=9,
            fg_color=C["sidebar_hover"],
            hover_color="#1F3F88",
            text_color="white",
            font=ctk.CTkFont(size=12, weight="bold"),
            command=self._open_output,
        ).pack(fill="x")

    def refresh_sidebar_status(self) -> None:
        """Called when settings change."""
        pass

    def show(self, key: str) -> None:
        self.pages[key].tkraise()
        for name, btn in self.nav.items():
            btn.configure(fg_color=C["primary"] if name == key else "transparent")
        if key == "settings":
            self.pages["settings"].load_values()

    def set_busy(self, busy: bool) -> None:
        pass

    def _open_output(self) -> None:
        OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        if sys.platform == "darwin":
            subprocess.run(["open", str(OUTPUT_DIR)])
        elif sys.platform == "win32":
            import os

            os.startfile(str(OUTPUT_DIR))  # type: ignore[attr-defined]
        else:
            subprocess.run(["xdg-open", str(OUTPUT_DIR)])

    def _close(self) -> None:
        try:
            for page in self.pages.values():
                token = getattr(page, "token", None)
                if token is not None:
                    token.cancel()
        except Exception:
            pass

        try:
            self.quit()
        except Exception:
            pass

        try:
            self.destroy()
        except Exception:
            pass


def launch_gui() -> None:
    """Launches the desktop application."""
    app = WorkbenchApp()
    app.mainloop()


if __name__ == "__main__":
    launch_gui()
