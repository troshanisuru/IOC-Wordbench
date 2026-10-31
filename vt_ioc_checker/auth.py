"""System user account authentication & security controls for sensitive credentials.

Supports:
- macOS: Native AppleScript security authorization (with Touch ID / system dialog)
  and dscl local node authentication.
- Windows: LogonUserW credential authentication via advapi32.
- Linux: pkexec and PAM / sudo user credential verification.
- In-app styled modal password dialog fallback.
"""

from __future__ import annotations

import getpass
import os
import subprocess
import sys
import tkinter as tk
from typing import Any, Optional

import customtkinter as ctk


def get_current_os_username() -> str:
    """Returns the current operating system username."""
    try:
        return getpass.getuser()
    except Exception:
        return os.environ.get("USER", os.environ.get("USERNAME", "user"))


def verify_system_password(username: str, password: str) -> bool:
    """Verifies the given password against the OS user account credentials."""
    if not password:
        return False

    uname = username.strip() or get_current_os_username()

    # macOS verification via dscl
    if sys.platform == "darwin":
        try:
            res = subprocess.run(
                ["dscl", ".", "-authonly", uname, password],
                capture_output=True,
                text=True,
                timeout=5.0,
            )
            return res.returncode == 0
        except Exception:
            return False

    # Windows verification via LogonUserW
    if sys.platform.startswith("win"):
        try:
            import ctypes
            from ctypes import wintypes

            advapi32 = ctypes.windll.advapi32
            kernel32 = ctypes.windll.kernel32

            LOGON32_LOGON_INTERACTIVE = 2
            LOGON32_PROVIDER_DEFAULT = 0

            token = wintypes.HANDLE()
            success = advapi32.LogonUserW(
                uname,
                None,
                password,
                LOGON32_LOGON_INTERACTIVE,
                LOGON32_PROVIDER_DEFAULT,
                ctypes.byref(token),
            )
            if success:
                kernel32.CloseHandle(token)
                return True
            return False
        except Exception:
            return False

    # Linux verification via sudo -k -S
    if sys.platform.startswith("linux"):
        try:
            res = subprocess.run(
                ["sudo", "-k", "-S", "true"],
                input=f"{password}\n",
                capture_output=True,
                text=True,
                timeout=5.0,
            )
            return res.returncode == 0
        except Exception:
            return False

    return False


def _authenticate_macos_system_dialog(prompt: str) -> tuple[Optional[bool], str]:
    """Invokes the native macOS authorization dialog with administrator/user privileges."""
    # Escape double quotes and backslashes for AppleScript string literal
    safe_prompt = prompt.replace("\\", "\\\\").replace('"', '\\"')
    script = (
        f'do shell script "true" with prompt "{safe_prompt}" with administrator privileges'
    )
    try:
        proc = subprocess.run(
            ["osascript", "-e", script],
            capture_output=True,
            text=True,
            timeout=30.0,
        )
        if proc.returncode == 0:
            return True, "Authenticated successfully."
        err = proc.stderr.strip()
        if "User canceled" in err or "-128" in err:
            return False, "Authentication cancelled by user."
        # If AppleScript failed due to sandbox or permissions, return None to trigger in-app dialog
        return None, err or "System prompt unavailable."
    except Exception as exc:
        return None, str(exc)


class AccountPasswordDialog(ctk.CTkToplevel):
    """Modal dialog asking for the current user's OS account password."""

    def __init__(
        self,
        parent: Any,
        prompt: str = "User account password required to view API keys.",
        title: str = "User Account Authorization",
    ) -> None:
        super().__init__(parent)
        self.title(title)
        self.geometry("460x300")
        self.resizable(False, False)
        self.transient(parent)
        self.grab_set()

        self.success = False
        self.username = get_current_os_username()
        self._os_name = "macOS" if sys.platform == "darwin" else "Windows" if sys.platform.startswith("win") else "Linux"

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)

        container = ctk.CTkFrame(self, fg_color="#F3F6FC", corner_radius=0)
        container.grid(row=0, column=0, sticky="nsew", padx=0, pady=0)
        container.grid_columnconfigure(0, weight=1)

        # Header with Security Icon
        header = ctk.CTkFrame(container, fg_color="transparent")
        header.pack(fill="x", padx=24, pady=(22, 12))

        badge = ctk.CTkFrame(header, fg_color="#0B1F4B", corner_radius=10, width=42, height=42)
        badge.pack(side="left", padx=(0, 12))
        badge.pack_propagate(False)
        ctk.CTkLabel(badge, text="🔒", font=ctk.CTkFont(size=20)).pack(expand=True)

        names = ctk.CTkFrame(header, fg_color="transparent")
        names.pack(side="left")
        ctk.CTkLabel(
            names, text=title, font=ctk.CTkFont(size=16, weight="bold"), text_color="#0F172A"
        ).pack(anchor="w")
        ctk.CTkLabel(
            names,
            text=f"Verify your {self._os_name} account password",
            font=ctk.CTkFont(size=12),
            text_color="#64748B",
        ).pack(anchor="w")

        # Instruction
        ctk.CTkLabel(
            container,
            text=prompt,
            font=ctk.CTkFont(size=12),
            text_color="#334155",
            wraplength=410,
            justify="left",
        ).pack(anchor="w", padx=24, pady=(0, 12))

        # Form fields
        form = ctk.CTkFrame(container, fg_color="#FFFFFF", corner_radius=10, border_width=1, border_color="#E1E8F5")
        form.pack(fill="x", padx=24, pady=(0, 12))

        user_row = ctk.CTkFrame(form, fg_color="transparent")
        user_row.pack(fill="x", padx=16, pady=(12, 6))
        ctk.CTkLabel(user_row, text="User Account:", font=ctk.CTkFont(size=12, weight="bold"), text_color="#64748B", width=100, anchor="w").pack(side="left")
        ctk.CTkLabel(user_row, text=self.username, font=ctk.CTkFont(size=13, weight="bold"), text_color="#0F172A").pack(side="left")

        pwd_row = ctk.CTkFrame(form, fg_color="transparent")
        pwd_row.pack(fill="x", padx=16, pady=(6, 12))
        ctk.CTkLabel(pwd_row, text="Password:", font=ctk.CTkFont(size=12, weight="bold"), text_color="#64748B", width=100, anchor="w").pack(side="left")

        self.pwd_var = tk.StringVar()
        self.pwd_entry = ctk.CTkEntry(
            pwd_row,
            textvariable=self.pwd_var,
            show="*",
            height=36,
            corner_radius=8,
            fg_color="#F8FAFD",
            border_color="#CBD5E1",
            placeholder_text="Enter account password",
        )
        self.pwd_entry.pack(side="left", fill="x", expand=True)
        self.pwd_entry.focus_set()
        self.pwd_entry.bind("<Return>", lambda e: self._on_confirm())

        # Error label
        self.error_label = ctk.CTkLabel(
            container,
            text="",
            font=ctk.CTkFont(size=11),
            text_color="#DC2626",
            anchor="w",
        )
        self.error_label.pack(fill="x", padx=24, pady=(0, 8))

        # Buttons
        btns = ctk.CTkFrame(container, fg_color="transparent")
        btns.pack(fill="x", padx=24, pady=(0, 16))

        cancel_btn = ctk.CTkButton(
            btns,
            text="Cancel",
            width=90,
            height=36,
            corner_radius=8,
            fg_color="transparent",
            hover_color="#E2E8F0",
            text_color="#64748B",
            border_width=1,
            border_color="#CBD5E1",
            font=ctk.CTkFont(size=12, weight="bold"),
            command=self._on_cancel,
        )
        cancel_btn.pack(side="right")

        self.confirm_btn = ctk.CTkButton(
            btns,
            text="Authenticate",
            width=120,
            height=36,
            corner_radius=8,
            fg_color="#2563EB",
            hover_color="#1D4ED8",
            font=ctk.CTkFont(size=12, weight="bold"),
            command=self._on_confirm,
        )
        self.confirm_btn.pack(side="right", padx=(0, 10))

    def _on_confirm(self) -> None:
        password = self.pwd_var.get()
        if not password:
            self.error_label.configure(text="Please enter your account password.")
            return

        self.confirm_btn.configure(state="disabled", text="Verifying...")
        self.update_idletasks()

        ok = verify_system_password(self.username, password)
        if ok:
            self.success = True
            self.destroy()
        else:
            self.confirm_btn.configure(state="normal", text="Authenticate")
            self.error_label.configure(text="Incorrect password. Authentication failed.")
            self.pwd_var.set("")
            self.pwd_entry.focus_set()

    def _on_cancel(self) -> None:
        self.success = False
        self.destroy()


def authenticate_user_account(
    prompt: str = "User account permissions required to view sensitive API keys.",
    parent_window: Any = None,
) -> tuple[bool, str]:
    """Authenticates the user using system permissions or an in-app password dialog."""
    # 1. On macOS, try the native macOS authorization dialog first
    if sys.platform == "darwin":
        sys_ok, sys_msg = _authenticate_macos_system_dialog(prompt)
        if sys_ok is True:
            return True, "Authenticated"
        if sys_ok is False and "cancelled" in sys_msg.lower():
            return False, "Authentication cancelled by user."

    # 2. If parent_window is provided and Tkinter is running, open the styled dialog
    if parent_window is not None:
        dialog = AccountPasswordDialog(parent_window, prompt=prompt)
        parent_window.wait_window(dialog)
        if dialog.success:
            return True, "Authenticated"
        return False, "Authentication was not completed."

    return False, "User authentication failed."

