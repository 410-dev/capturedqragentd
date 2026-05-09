from __future__ import annotations

from AppContext import AppContext

import argparse
import importlib.util
import json
import os
import sys
import threading
from pathlib import Path
from typing import Any


APP_ID = "captured-qr-agent"
APP_NAME = "Captured QR Agent"
SETTINGS_VERSION = 1

DEFAULT_SETTINGS: dict[str, Any] = {
    "settings_version": SETTINGS_VERSION,
    "action_mode": "smart",
    "notify_on_detection": True,
    "copy_after_open": False,
    "detection_methods": ["gio"],
    "watch_dirs": [],
    "open_url_schemes": ["http", "https", "file", "mailto", "tel"],
    "clipboard_poll_interval_seconds": 1.0,
    "scan_existing_on_start": False,
}

VALID_DETECTION_METHODS = {"gio", "inotify", "clipboardd", "clipboard_tools"}
CLIPBOARDD_PROCESS_NAME = "clipboardd"


def xdg_config_home() -> Path:
    configured = os.environ.get("XDG_CONFIG_HOME")
    if configured:
        return Path(configured).expanduser()
    return Path.home() / ".config"


def settings_path() -> Path:
    return xdg_config_home() / APP_ID / "settings.json"


def module_available(module_name: str) -> bool:
    try:
        return importlib.util.find_spec(module_name) is not None
    except ModuleNotFoundError:
        return False


def normalize_detection_methods(methods: Any) -> list[str]:
    if isinstance(methods, str):
        methods = [methods]
    normalized: list[str] = []
    for method in methods if isinstance(methods, list) else []:
        if not isinstance(method, str):
            continue
        candidate = "clipboardd" if method == "clipboard" else method
        if candidate in VALID_DETECTION_METHODS and candidate not in normalized:
            normalized.append(candidate)
    return normalized or ["gio"]


def clipboardd_available(timeout: float = 0.75) -> bool:
    if not module_available("oscore.libipc"):
        return False

    try:
        from oscore.libipc import send
    except ImportError:
        return False

    result: dict[str, Any] = {}

    def ping() -> None:
        try:
            result["value"] = send(CLIPBOARDD_PROCESS_NAME, -1, "ping", {}, dict, timeout=timeout)
        except TypeError:
            result["value"] = send(CLIPBOARDD_PROCESS_NAME, -1, "ping", {}, dict)
        except Exception as error:
            result["error"] = error

    thread = threading.Thread(target=ping, name="captured-qr-agent-clipboardd-ping", daemon=True)
    thread.start()
    thread.join(timeout)
    if thread.is_alive() or "error" in result:
        return False

    value = result.get("value")
    return isinstance(value, dict) and bool(value.get("ok"))


def read_user_dirs() -> dict[str, Path]:
    user_dirs_file = xdg_config_home() / "user-dirs.dirs"
    result: dict[str, Path] = {}
    if not user_dirs_file.exists():
        return result

    for raw_line in user_dirs_file.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, raw_value = line.split("=", 1)
        value = raw_value.strip().strip('"')
        value = value.replace("$HOME", str(Path.home()))
        result[key] = Path(value).expanduser()
    return result


def default_watch_dirs() -> list[str]:
    user_dirs = read_user_dirs()
    pictures_dir = user_dirs.get("XDG_PICTURES_DIR", Path.home() / "Pictures")
    candidates = [
        pictures_dir / "Screenshots",
        pictures_dir,
        Path.home() / "Desktop",
    ]

    seen: set[Path] = set()
    existing: list[str] = []
    for candidate in candidates:
        resolved = candidate.expanduser()
        if resolved in seen:
            continue
        seen.add(resolved)
        if resolved.is_dir():
            existing.append(str(resolved))
    return existing


def load_settings() -> dict[str, Any]:
    path = settings_path()
    settings = DEFAULT_SETTINGS.copy()
    if path.exists():
        try:
            loaded = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                settings.update(loaded)
        except (OSError, json.JSONDecodeError):
            pass

    if not settings.get("watch_dirs"):
        settings["watch_dirs"] = default_watch_dirs()

    settings["detection_methods"] = normalize_detection_methods(settings.get("detection_methods", ["gio"]))

    try:
        settings["clipboard_poll_interval_seconds"] = max(
            0.25,
            float(settings.get("clipboard_poll_interval_seconds", 1.0)),
        )
    except (TypeError, ValueError):
        settings["clipboard_poll_interval_seconds"] = 1.0

    return settings


def save_settings(settings: dict[str, Any]) -> None:
    path = settings_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(settings, indent=2, sort_keys=True), encoding="utf-8")


def import_gtk():
    import gi

    for version in ("4.0", "3.0"):
        try:
            gi.require_version("Gtk", version)
            from gi.repository import Gtk

            return Gtk, version.startswith("4")
        except (ValueError, ImportError):
            continue
    raise ImportError("GTK 3 or GTK 4 through PyGObject is required.")


def run_gui(args: list[str]) -> int:
    Gtk, gtk4 = import_gtk()

    def box_append(box, child, expand: bool = False) -> None:
        if gtk4:
            box.append(child)
        else:
            box.pack_start(child, expand, expand, 0)

    def set_child(container, child) -> None:
        if gtk4:
            container.set_child(child)
        else:
            container.add(child)

    def set_margin(widget, margin: int) -> None:
        widget.set_margin_top(margin)
        widget.set_margin_bottom(margin)
        widget.set_margin_start(margin)
        widget.set_margin_end(margin)

    class SettingsWindow(Gtk.ApplicationWindow):
        ACTIONS = {
            "smart": "Open links and files, copy text",
            "always_copy": "Always copy",
            "always_open": "Open when possible",
        }

        def __init__(self, app):
            super().__init__(application=app, title=APP_NAME)
            self.context = AppContext()
            self.settings = load_settings()

            self.set_default_size(620, 540)
            self.context.update_icon(self)

            root = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=14)
            set_margin(root, 18)
            set_child(self, root)

            title = Gtk.Label()
            title.set_markup("<b>Captured QR Agent</b>")
            title.set_xalign(0)
            box_append(root, title)

            path_label = Gtk.Label(label=f"Settings: {settings_path()}")
            path_label.set_xalign(0)
            path_label.set_selectable(True)
            box_append(root, path_label)

            self.action_combo = Gtk.ComboBoxText()
            for key, label in self.ACTIONS.items():
                self.action_combo.append(key, label)
            self.action_combo.set_active_id(str(self.settings.get("action_mode", "smart")))
            box_append(root, self._row("Default action", self.action_combo))

            self.notify_check = Gtk.CheckButton(label="Show a GNOME notification when a QR code is detected")
            self.notify_check.set_active(bool(self.settings.get("notify_on_detection", True)))
            box_append(root, self.notify_check)

            self.copy_after_open_check = Gtk.CheckButton(label="Also copy QR content after opening links or files")
            self.copy_after_open_check.set_active(bool(self.settings.get("copy_after_open", False)))
            box_append(root, self.copy_after_open_check)

            self.scan_existing_check = Gtk.CheckButton(label="Scan existing images in watched folders when daemon starts")
            self.scan_existing_check.set_active(bool(self.settings.get("scan_existing_on_start", False)))
            box_append(root, self.scan_existing_check)

            methods = set(self.settings.get("detection_methods", ["gio"]))
            detection_label = Gtk.Label(label="Detection methods")
            detection_label.set_xalign(0)
            box_append(root, detection_label)

            self.gio_check = Gtk.CheckButton(label="Watch screenshot folders with GNOME/GIO")
            self.gio_check.set_active("gio" in methods)
            box_append(root, self.gio_check)

            self.inotify_check = Gtk.CheckButton(label="Watch screenshot folders with Linux inotify")
            self.inotify_check.set_active("inotify" in methods)
            box_append(root, self.inotify_check)

            self.clipboardd_available = clipboardd_available()
            self.clipboardd_check = Gtk.CheckButton(label="Watch clipboard via clipboardd")
            self.clipboardd_check.set_active("clipboardd" in methods)
            self.clipboardd_check.set_sensitive(self.clipboardd_available)
            box_append(root, self.clipboardd_check)

            self.schemes_entry = Gtk.Entry()
            self.schemes_entry.set_text(", ".join(self.settings.get("open_url_schemes", [])))
            box_append(root, self._row("Open URL schemes", self.schemes_entry))

            dirs_label = Gtk.Label(label="Watched screenshot folders")
            dirs_label.set_xalign(0)
            box_append(root, dirs_label)

            self.dirs_view = Gtk.TextView()
            self.dirs_view.set_monospace(True)
            self.dirs_view.set_wrap_mode(Gtk.WrapMode.NONE)
            self.dirs_view.get_buffer().set_text("\n".join(self.settings.get("watch_dirs", [])))

            scroller = Gtk.ScrolledWindow()
            scroller.set_min_content_height(150)
            set_child(scroller, self.dirs_view)
            box_append(root, scroller, expand=True)

            button_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
            self.save_button = Gtk.Button(label="Save")
            self.save_button.connect("clicked", self._on_save)
            reset_button = Gtk.Button(label="Use Default Folders")
            reset_button.connect("clicked", self._on_defaults)
            box_append(button_row, self.save_button)
            box_append(button_row, reset_button)
            box_append(root, button_row)

            self.status_label = Gtk.Label(label="")
            self.status_label.set_xalign(0)
            box_append(root, self.status_label)

        def _row(self, label: str, widget):
            row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
            caption = Gtk.Label(label=label)
            caption.set_xalign(0)
            if hasattr(caption, "set_width_chars"):
                caption.set_width_chars(20)
            box_append(row, caption)
            box_append(row, widget, expand=True)
            return row

        def _read_dirs(self) -> list[str]:
            buffer = self.dirs_view.get_buffer()
            start = buffer.get_start_iter()
            end = buffer.get_end_iter()
            text = buffer.get_text(start, end, True)
            return [line.strip() for line in text.splitlines() if line.strip()]

        def _read_schemes(self) -> list[str]:
            raw = self.schemes_entry.get_text()
            return [item.strip().lower() for item in raw.split(",") if item.strip()]

        def _read_detection_methods(self) -> list[str]:
            methods = []
            if self.gio_check.get_active():
                methods.append("gio")
            if self.inotify_check.get_active():
                methods.append("inotify")
            if self.clipboardd_check.get_active() and (
                self.clipboardd_available or "clipboardd" in self.settings.get("detection_methods", [])
            ):
                methods.append("clipboardd")
            if "clipboard_tools" in self.settings.get("detection_methods", []):
                methods.append("clipboard_tools")
            return methods or ["gio"]

        def _on_save(self, _button) -> None:
            settings = DEFAULT_SETTINGS.copy()
            settings.update(
                {
                    "action_mode": self.action_combo.get_active_id() or "smart",
                    "notify_on_detection": self.notify_check.get_active(),
                    "copy_after_open": self.copy_after_open_check.get_active(),
                    "scan_existing_on_start": self.scan_existing_check.get_active(),
                    "detection_methods": self._read_detection_methods(),
                    "clipboard_poll_interval_seconds": self.settings.get("clipboard_poll_interval_seconds", 1.0),
                    "watch_dirs": self._read_dirs(),
                    "open_url_schemes": self._read_schemes(),
                }
            )
            save_settings(settings)
            self.settings = settings
            self.status_label.set_text("Saved. Directory changes take effect after restarting the daemon.")

        def _on_defaults(self, _button) -> None:
            self.dirs_view.get_buffer().set_text("\n".join(default_watch_dirs()))
            self.status_label.set_text("Default folders loaded. Save to apply them.")

    class SettingsApp(Gtk.Application):
        def __init__(self):
            super().__init__(application_id="local.captured_qr_agent.Configurator")

        def do_activate(self):
            window = SettingsWindow(self)
            if gtk4:
                window.present()
            else:
                window.show_all()

    app = SettingsApp()
    return app.run(args)


def parse_args(args: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Configure Captured QR Agent.")
    parser.add_argument("--config-path", action="store_true", help="print the shared settings file path")
    parser.add_argument("--reset-defaults", action="store_true", help="write default settings and exit")
    return parser.parse_args(args)


def main(args: list[str]) -> int:
    parsed = parse_args(args)
    if parsed.config_path:
        print(settings_path())
        return 0
    if parsed.reset_defaults:
        settings = DEFAULT_SETTINGS.copy()
        settings["watch_dirs"] = default_watch_dirs()
        save_settings(settings)
        print(settings_path())
        return 0

    try:
        return run_gui(args)
    except ImportError as error:
        print(f"Cannot start configurator GUI: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
