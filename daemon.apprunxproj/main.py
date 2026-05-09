from __future__ import annotations

from AppContext import AppContext, ProcessAlreadyRunningError

import argparse
import base64
import binascii
import ctypes
import hashlib
import importlib.util
import json
import mimetypes
import os
import select
import shutil
import signal
import struct
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlparse


APP_ID = "captured-qr-agent"
APP_NAME = "Captured QR Agent"
SETTINGS_VERSION = 1
IMAGE_SUFFIXES = {".png", ".jpg", ".jpeg", ".webp", ".bmp", ".tif", ".tiff", ".gif"}
DEFAULT_DETECTION_METHODS = ["gio"]
VALID_DETECTION_METHODS = {"gio", "inotify", "clipboardd", "clipboard_tools"}
CLIPBOARD_IMAGE_TYPES = ["image/png", "image/jpeg", "image/bmp", "image/webp", "image/tiff", "image/gif"]
CLIPBOARD_WATCH_IMAGE_TYPE = "image/png"
CLIPBOARDD_PROCESS_NAME = "clipboardd"
CLIPBOARDD_CLIENT_PROCESS_NAME = "capturedqragentd"
CLIPBOARDD_CHANGED_IPC_ID = "clipboard_changed"
CLIPBOARDD_SUPPORTED_IMAGE_TYPES = set(CLIPBOARD_IMAGE_TYPES) | {"image/jpg"}


DEFAULT_SETTINGS: dict[str, Any] = {
    "settings_version": SETTINGS_VERSION,
    "action_mode": "smart",
    "notify_on_detection": True,
    "copy_after_open": False,
    "detection_methods": DEFAULT_DETECTION_METHODS,
    "watch_dirs": [],
    "open_url_schemes": ["http", "https", "file", "mailto", "tel"],
    "clipboard_poll_interval_seconds": 1.0,
    "scan_existing_on_start": False,
}


@dataclass(frozen=True)
class QRResult:
    source_path: Path
    content: str


Logger = Callable[[str, str], None]


def log_event(level: str, message: str) -> None:
    timestamp = datetime.now().astimezone().isoformat(timespec="seconds")
    print(f"{timestamp} [{level}] {message}", flush=True)


def log_error(message: str) -> None:
    log_event("ERROR", message)


def compact_json(data: Any) -> str:
    return json.dumps(data, ensure_ascii=False, sort_keys=True)


def xdg_config_home() -> Path:
    configured = os.environ.get("XDG_CONFIG_HOME")
    if configured:
        return Path(configured).expanduser()
    return Path.home() / ".config"


def settings_path() -> Path:
    return xdg_config_home() / APP_ID / "settings.json"


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

    settings["watch_dirs"] = [
        str(Path(item).expanduser())
        for item in settings.get("watch_dirs", [])
        if isinstance(item, str) and item.strip()
    ]
    settings["open_url_schemes"] = [
        scheme.lower()
        for scheme in settings.get("open_url_schemes", [])
        if isinstance(scheme, str) and scheme.strip()
    ]
    settings["detection_methods"] = normalize_detection_methods(
        settings.get("detection_methods", DEFAULT_DETECTION_METHODS)
    )

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
    return normalized or DEFAULT_DETECTION_METHODS


def decoder_availability() -> dict[str, bool]:
    return {
        "opencv": module_available("cv2"),
        "pyzbar": module_available("PIL") and module_available("pyzbar"),
        "zbarimg": shutil.which("zbarimg") is not None,
    }


def clipboard_availability() -> dict[str, bool]:
    return {
        "clipboardd_libipc": module_available("oscore.libipc"),
        "wl-paste": shutil.which("wl-paste") is not None,
        "wl-copy": shutil.which("wl-copy") is not None,
        "xclip": shutil.which("xclip") is not None,
        "xsel": shutil.which("xsel") is not None,
    }


def opener_availability() -> dict[str, bool]:
    return {
        "xdg-open": shutil.which("xdg-open") is not None,
        "gio": shutil.which("gio") is not None,
    }


def detection_source_availability() -> dict[str, bool]:
    return {
        "gio": module_available("gi"),
        "inotify": sys.platform.startswith("linux"),
        "clipboardd": module_available("oscore.libipc"),
        "clipboard_tools": any(shutil.which(command) is not None for command in ("wl-paste", "xclip")),
        "clipboard_watch": bool(os.environ.get("WAYLAND_DISPLAY") and shutil.which("wl-paste")),
    }


def is_image_file(path: Path) -> bool:
    suffix = path.suffix.lower()
    if suffix in IMAGE_SUFFIXES:
        return True
    guessed, _ = mimetypes.guess_type(str(path))
    return bool(guessed and guessed.startswith("image/"))


def wait_until_stable(path: Path, timeout: float = 8.0) -> bool:
    deadline = time.monotonic() + timeout
    previous: tuple[int, int] | None = None
    stable_count = 0

    while time.monotonic() < deadline:
        try:
            stat = path.stat()
        except FileNotFoundError:
            time.sleep(0.2)
            continue

        current = (stat.st_size, stat.st_mtime_ns)
        if stat.st_size > 0 and current == previous:
            stable_count += 1
            if stable_count >= 2:
                return True
        else:
            stable_count = 0
            previous = current
        time.sleep(0.25)

    return path.exists()


def clipboard_image_commands() -> list[tuple[str, list[str]]]:
    commands: list[tuple[str, list[str]]] = []
    if shutil.which("wl-paste"):
        for image_type in CLIPBOARD_IMAGE_TYPES:
            commands.append((image_type, ["wl-paste", "--no-newline", "--type", image_type]))
    if shutil.which("xclip"):
        for image_type in CLIPBOARD_IMAGE_TYPES:
            commands.append((image_type, ["xclip", "-selection", "clipboard", "-t", image_type, "-o"]))
    return commands


def read_clipboard_image(logger: Logger | None = None) -> tuple[bytes, str] | None:
    for image_type, command in clipboard_image_commands():
        try:
            completed = subprocess.run(
                command,
                check=False,
                capture_output=True,
                timeout=2,
            )
        except subprocess.TimeoutExpired:
            if logger:
                logger("ERROR", f"Clipboard image command timed out: {' '.join(command)}")
            continue
        except OSError as error:
            if logger:
                logger("ERROR", f"Clipboard image command failed to start ({' '.join(command)}): {error}")
            continue

        if completed.returncode == 0 and completed.stdout:
            return completed.stdout, image_type
    return None


def clipboard_image_path(image_data: bytes, image_type: str) -> Path:
    suffix_by_type = {
        "image/png": ".png",
        "image/jpeg": ".jpg",
        "image/jpg": ".jpg",
        "image/bmp": ".bmp",
        "image/webp": ".webp",
        "image/tiff": ".tiff",
        "image/gif": ".gif",
    }
    digest = hashlib.sha256(image_data).hexdigest()
    suffix = suffix_by_type.get(image_type, ".img")
    candidates = []
    if os.environ.get("XDG_RUNTIME_DIR"):
        candidates.append(Path(os.environ["XDG_RUNTIME_DIR"]))
    candidates.append(Path(tempfile.gettempdir()))

    last_error: OSError | None = None
    for base_dir in candidates:
        try:
            directory = base_dir / APP_ID / "clipboard"
            directory.mkdir(parents=True, exist_ok=True)
            path = directory / f"{digest}{suffix}"
            if not path.exists():
                path.write_bytes(image_data)
            return path
        except OSError as error:
            last_error = error

    if last_error is not None:
        raise last_error
    raise OSError("No clipboard cache directory is available")


def clipboard_watch_helper() -> int:
    image_data = sys.stdin.buffer.read()
    if not image_data or not looks_like_image_data(image_data):
        return 0

    image_type = image_type_from_data(image_data)
    path = clipboard_image_path(image_data, image_type)
    payload = {
        "path": str(path),
        "image_type": image_type,
        "size": len(image_data),
        "sha256": hashlib.sha256(image_data).hexdigest(),
    }
    print(compact_json(payload), flush=True)
    return 0


def looks_like_image_data(data: bytes) -> bool:
    return (
        data.startswith(b"\x89PNG\r\n\x1a\n")
        or data.startswith(b"\xff\xd8\xff")
        or data.startswith(b"BM")
        or data.startswith(b"GIF87a")
        or data.startswith(b"GIF89a")
        or data.startswith(b"RIFF") and b"WEBP" in data[:16]
        or data.startswith(b"II*\x00")
        or data.startswith(b"MM\x00*")
    )


def image_type_from_data(data: bytes, fallback: str = CLIPBOARD_WATCH_IMAGE_TYPE) -> str:
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    if data.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"
    if data.startswith(b"BM"):
        return "image/bmp"
    if data.startswith(b"GIF87a") or data.startswith(b"GIF89a"):
        return "image/gif"
    if data.startswith(b"RIFF") and b"WEBP" in data[:16]:
        return "image/webp"
    if data.startswith(b"II*\x00") or data.startswith(b"MM\x00*"):
        return "image/tiff"
    return fallback


def detect_qr_with_opencv(path: Path, logger: Logger | None = None) -> str | None:
    try:
        import cv2
    except ImportError:
        return None

    if logger:
        logger("INFO", f"Trying OpenCV QR decoder for {path}")

    image = cv2.imread(str(path))
    if image is None:
        if logger:
            logger("ERROR", f"OpenCV could not read image: {path}")
        return None

    detector = cv2.QRCodeDetector()
    try:
        data, _points, _straight = detector.detectAndDecode(image)
    except Exception as error:
        if logger:
            logger("ERROR", f"OpenCV detectAndDecode failed for {path}: {error}")
        return None

    if data:
        if logger:
            logger("INFO", f"OpenCV decoded QR content from {path}")
        return data

    try:
        ok, decoded_info, _points, _straight = detector.detectAndDecodeMulti(image)
    except Exception as error:
        if logger:
            logger("ERROR", f"OpenCV detectAndDecodeMulti failed for {path}: {error}")
        return None

    if ok:
        for item in decoded_info:
            if item:
                if logger:
                    logger("INFO", f"OpenCV decoded QR content from {path}")
                return item
    return None


def detect_qr_with_pyzbar(path: Path, logger: Logger | None = None) -> str | None:
    try:
        from PIL import Image
        from pyzbar.pyzbar import ZBarSymbol, decode
    except ImportError:
        return None

    if logger:
        logger("INFO", f"Trying pyzbar QR decoder for {path}")

    try:
        image = Image.open(path)
        results = decode(image, symbols=[ZBarSymbol.QRCODE])
    except Exception as error:
        if logger:
            logger("ERROR", f"pyzbar failed for {path}: {error}")
        return None

    for result in results:
        if result.data:
            if logger:
                logger("INFO", f"pyzbar decoded QR content from {path}")
            return result.data.decode("utf-8", errors="replace")
    return None


def detect_qr_with_zbarimg(path: Path, logger: Logger | None = None) -> str | None:
    if not shutil.which("zbarimg"):
        return None

    if logger:
        logger("INFO", f"Trying zbarimg QR decoder for {path}")

    try:
        completed = subprocess.run(
            ["zbarimg", "--quiet", "--raw", str(path)],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except subprocess.TimeoutExpired:
        if logger:
            logger("ERROR", f"zbarimg timed out for {path}")
        return None
    except OSError as error:
        if logger:
            logger("ERROR", f"zbarimg failed to start for {path}: {error}")
        return None

    if completed.returncode == 0:
        data = completed.stdout.strip()
        if data:
            if logger:
                logger("INFO", f"zbarimg decoded QR content from {path}")
            return data
    elif completed.stderr.strip() and logger:
        logger("ERROR", f"zbarimg returned {completed.returncode} for {path}: {completed.stderr.strip()}")
    return None


def detect_qr(path: Path, logger: Logger | None = None) -> str | None:
    for detector in (detect_qr_with_opencv, detect_qr_with_pyzbar, detect_qr_with_zbarimg):
        data = detector(path, logger)
        if data:
            return data
    return None


def content_is_openable(content: str, settings: dict[str, Any]) -> bool:
    parsed = urlparse(content)
    allowed_schemes = set(settings.get("open_url_schemes", []))
    if parsed.scheme:
        return parsed.scheme.lower() in allowed_schemes

    candidate = Path(content).expanduser()
    return candidate.exists()


def should_open(content: str, settings: dict[str, Any]) -> bool:
    action_mode = settings.get("action_mode", "smart")
    if action_mode == "always_copy":
        return False
    if action_mode == "always_open":
        return content_is_openable(content, settings)
    return content_is_openable(content, settings)


def copy_to_clipboard(text: str, logger: Logger | None = None) -> bool:
    commands: list[list[str]] = []
    if os.environ.get("WAYLAND_DISPLAY") and shutil.which("wl-copy"):
        commands.append(["wl-copy"])
    if shutil.which("xclip"):
        commands.append(["xclip", "-selection", "clipboard"])
    if shutil.which("xsel"):
        commands.append(["xsel", "--clipboard", "--input"])

    for command in commands:
        try:
            subprocess.run(command, input=text, text=True, check=True)
            if logger:
                logger("INFO", f"Copied QR content to clipboard using {command[0]}")
            return True
        except (OSError, subprocess.CalledProcessError) as error:
            if logger:
                logger("ERROR", f"Clipboard command failed ({' '.join(command)}): {error}")
            continue
    if logger:
        logger("ERROR", "No clipboard command succeeded; install wl-clipboard, xclip, or xsel")
    return False


def open_content(content: str, logger: Logger | None = None) -> bool:
    target = content
    parsed = urlparse(content)
    if not parsed.scheme:
        candidate = Path(content).expanduser()
        if candidate.exists():
            target = str(candidate)

    opener = shutil.which("xdg-open") or shutil.which("gio")
    if not opener:
        if logger:
            logger("ERROR", "No opener found; install xdg-utils or make gio available")
        return False

    command = [opener, "open", target] if Path(opener).name == "gio" else [opener, target]
    try:
        subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if logger:
            logger("INFO", f"Opened QR content with {Path(opener).name}: {target}")
        return True
    except OSError as error:
        if logger:
            logger("ERROR", f"Failed to open QR content with {Path(opener).name}: {error}")
        return False


def perform_preferred_action(result: QRResult, settings: dict[str, Any], logger: Logger | None = None) -> str:
    if logger:
        logger("INFO", f"Executing configured action for QR from {result.source_path}")

    if should_open(result.content, settings) and open_content(result.content, logger):
        if settings.get("copy_after_open", False):
            copy_to_clipboard(result.content, logger)
        return "opened"

    if copy_to_clipboard(result.content, logger):
        return "copied"
    if logger:
        logger("ERROR", "QR content was neither opened nor copied")
    return "unhandled"


class NotificationCenter:
    def __init__(self, settings: dict[str, Any], logger: Logger = log_event):
        self.settings = settings
        self.logger = logger
        self.pending: dict[int, QRResult] = {}
        self.bus = None
        self.subscription_id = None

        try:
            import gi

            gi.require_version("Gio", "2.0")
            gi.require_version("GLib", "2.0")
            from gi.repository import Gio, GLib

            self.Gio = Gio
            self.GLib = GLib
            self.bus = Gio.bus_get_sync(Gio.BusType.SESSION, None)
            self.subscription_id = self.bus.signal_subscribe(
                None,
                "org.freedesktop.Notifications",
                "ActionInvoked",
                "/org/freedesktop/Notifications",
                None,
                Gio.DBusSignalFlags.NONE,
                self._on_action_invoked,
            )
            self.logger("INFO", "Connected to GNOME notification service over session DBus")
        except Exception as error:
            self.Gio = None
            self.GLib = None
            self.bus = None
            self.logger("ERROR", f"Could not connect to GNOME notification action bus: {error}")

    def close(self) -> None:
        if self.bus is not None and self.subscription_id is not None:
            self.bus.signal_unsubscribe(self.subscription_id)
            self.logger("INFO", "Disconnected from notification action bus")

    def _on_action_invoked(self, _bus, _sender, _path, _interface, _signal, parameters) -> None:
        notification_id, action = parameters.unpack()
        self.logger("INFO", f"Notification action invoked: id={notification_id}, action={action}")
        result = self.pending.pop(int(notification_id), None)
        if result is None:
            self.logger("ERROR", f"Notification action had no pending QR payload: id={notification_id}")
            return

        if action == "copy":
            copy_to_clipboard(result.content, self.logger)
        else:
            action_result = perform_preferred_action(result, self.settings, self.logger)
            self.logger("INFO", f"Notification action result: {action_result}")

    def notify(self, result: QRResult) -> None:
        if not self.settings.get("notify_on_detection", True):
            self.logger("INFO", "Notifications disabled; executing configured action immediately")
            action_result = perform_preferred_action(result, self.settings, self.logger)
            self.logger("INFO", f"Immediate action result: {action_result}")
            return

        title = "QR code detected"
        preferred_action = "Open" if should_open(result.content, self.settings) else "Copy"
        body = result.content if len(result.content) <= 180 else result.content[:177] + "..."

        if self.bus is None:
            self.logger("INFO", "Using notify-send fallback; notification actions are unavailable")
            self._notify_send(title, body)
            action_result = perform_preferred_action(result, self.settings, self.logger)
            self.logger("INFO", f"Fallback immediate action result: {action_result}")
            return

        actions = ["default", preferred_action, "copy", "Copy"]
        hints: dict[str, Any] = {}
        try:
            response = self.bus.call_sync(
                "org.freedesktop.Notifications",
                "/org/freedesktop/Notifications",
                "org.freedesktop.Notifications",
                "Notify",
                self.GLib.Variant(
                    "(susssasa{sv}i)",
                    (APP_NAME, 0, "", title, body, actions, hints, 12000),
                ),
                self.GLib.VariantType.new("(u)"),
                self.Gio.DBusCallFlags.NONE,
                -1,
                None,
            )
            notification_id = int(response.unpack()[0])
            self.pending[notification_id] = result
            self.logger("INFO", f"Notification sent: id={notification_id}, default_action={preferred_action}")
        except Exception as error:
            self.logger("ERROR", f"Failed to send actionable notification: {error}")
            self._notify_send(title, body)
            action_result = perform_preferred_action(result, self.settings, self.logger)
            self.logger("INFO", f"Fallback immediate action result: {action_result}")

    def _notify_send(self, title: str, body: str) -> None:
        if not shutil.which("notify-send"):
            self.logger("ERROR", "notify-send is not available")
            return
        try:
            subprocess.run(["notify-send", title, body], check=False)
            self.logger("INFO", "Fallback notification sent with notify-send")
        except OSError as error:
            self.logger("ERROR", f"notify-send failed: {error}")


class ScreenshotMonitor:
    def __init__(self, settings: dict[str, Any], debug: bool = False):
        self.settings = settings
        self.debug = debug
        self.notification_center = NotificationCenter(settings, self.log)
        self.processed: dict[str, int] = {}
        self.recent_payloads: set[str] = set()
        self.clipboardd_subscription_id: str | None = None
        self.clipboardd_listener_registered = False
        self.clipboardd_last_digest: str | None = None
        self.clipboardd_send = None
        self.clipboardd_remove_listener = None
        self.stop_event = threading.Event()
        self.threads: list[threading.Thread] = []
        self.gio_monitors = []
        self.Gio = None
        self.GLib = None

        try:
            import gi

            gi.require_version("Gio", "2.0")
            gi.require_version("GLib", "2.0")
            from gi.repository import Gio, GLib

            self.Gio = Gio
            self.GLib = GLib
        except Exception as error:
            self.log("ERROR", f"PyGObject/GIO unavailable; gio detection disabled: {error}")

    def log(self, level: str, message: str) -> None:
        if level == "DEBUG" and not self.debug:
            return
        log_event(level, message)

    def start(self) -> int:
        self.log("INFO", f"Starting {APP_NAME} daemon")
        self.log("INFO", f"Settings file: {settings_path()}")
        self.log("INFO", f"Effective settings: {compact_json(self.settings)}")
        self.log("INFO", f"Detection source availability: {compact_json(detection_source_availability())}")
        self.log("INFO", f"Decoder availability: {compact_json(decoder_availability())}")
        self.log("INFO", f"Clipboard tools: {compact_json(clipboard_availability())}")
        self.log("INFO", f"Opener availability: {compact_json(opener_availability())}")

        detection_methods = set(self.settings.get("detection_methods", DEFAULT_DETECTION_METHODS))
        self.log("INFO", f"Enabled detection methods: {', '.join(sorted(detection_methods))}")

        watch_dirs = [Path(item).expanduser() for item in self.settings.get("watch_dirs", [])]
        valid_dirs = [item for item in watch_dirs if item.is_dir()]
        missing_dirs = [str(item) for item in watch_dirs if not item.is_dir()]
        for missing_dir in missing_dirs:
            self.log("ERROR", f"Configured watch directory does not exist: {missing_dir}")

        needs_directory_watcher = bool(detection_methods.intersection({"gio", "inotify"}))
        if needs_directory_watcher and not valid_dirs:
            self.log("ERROR", "No screenshot directories exist. Configure watch directories first.")
            return 2

        active_sources = 0
        if "gio" in detection_methods:
            active_sources += self._start_gio_monitors(valid_dirs)
        if "inotify" in detection_methods:
            active_sources += self._start_inotify_monitor(valid_dirs)
        if "clipboardd" in detection_methods:
            active_sources += self._start_clipboardd_subscription()
        if "clipboard_tools" in detection_methods:
            active_sources += self._start_clipboard_tools_monitor()

        if active_sources == 0:
            self.log("ERROR", "No detection source could be started.")
            return 2

        if self.settings.get("scan_existing_on_start", False):
            self.log("INFO", "Scanning existing images in watched directories")
            for directory in valid_dirs:
                try:
                    for path in directory.iterdir():
                        if path.is_file() and is_image_file(path):
                            self.queue_scan(path, reason="startup")
                except OSError as error:
                    self.log("ERROR", f"Failed to list directory {directory}: {error}")

        self.log("INFO", "Daemon is waiting for screenshot captures and clipboard images")
        signal.signal(signal.SIGTERM, self._handle_stop_signal)
        signal.signal(signal.SIGINT, self._handle_stop_signal)

        try:
            if self.GLib is not None:
                loop = self.GLib.MainLoop()
                self._main_loop = loop
                loop.run()
            else:
                while not self.stop_event.is_set():
                    time.sleep(0.5)
        finally:
            self.log("INFO", "Daemon shutting down")
            self.stop_event.set()
            self._stop_clipboardd_subscription()
            self.notification_center.close()
            for thread in self.threads:
                thread.join(timeout=2)
        return 0

    def _handle_stop_signal(self, _sig, _frame) -> None:
        self.log("INFO", "Stop signal received")
        self.stop_event.set()
        loop = getattr(self, "_main_loop", None)
        if loop is not None:
            loop.quit()

    def _start_gio_monitors(self, valid_dirs: list[Path]) -> int:
        if self.Gio is None:
            self.log("ERROR", "GIO detection requested, but PyGObject/GIO is unavailable")
            return 0

        started = 0
        for directory in valid_dirs:
            try:
                gfile = self.Gio.File.new_for_path(str(directory))
                monitor = gfile.monitor_directory(self.Gio.FileMonitorFlags.NONE, None)
                monitor.connect("changed", self._on_gio_changed)
                self.gio_monitors.append(monitor)
                started += 1
                self.log("INFO", f"GIO watching screenshot directory: {directory}")
            except Exception as error:
                self.log("ERROR", f"GIO failed to watch directory {directory}: {error}")
        return started

    def _start_inotify_monitor(self, valid_dirs: list[Path]) -> int:
        if not sys.platform.startswith("linux"):
            self.log("ERROR", "inotify detection requested on a non-Linux platform")
            return 0
        if not valid_dirs:
            return 0

        thread = threading.Thread(
            target=self._inotify_loop,
            args=(valid_dirs,),
            name="captured-qr-agent-inotify",
            daemon=True,
        )
        thread.start()
        self.threads.append(thread)
        self.log("INFO", f"inotify monitor started for {len(valid_dirs)} screenshot directories")
        return 1

    def _start_clipboard_tools_monitor(self) -> int:
        if self._start_wayland_clipboard_watch():
            return 1

        if not clipboard_image_commands():
            self.log("ERROR", "Clipboard tools detection requested, but wl-paste and xclip are unavailable")
            return 0

        thread = threading.Thread(
            target=self._clipboard_poll_loop,
            name="captured-qr-agent-clipboard",
            daemon=True,
        )
        thread.start()
        self.threads.append(thread)
        interval = self.settings.get("clipboard_poll_interval_seconds", 1.0)
        self.log("INFO", f"Legacy clipboard image polling started at {interval:.2f}s interval")
        return 1

    def _start_clipboardd_subscription(self) -> bool:
        try:
            from oscore.libipc import add_listener, remove_listener, send
        except ImportError as error:
            self.log("INFO", f"clipboardd integration unavailable because oscore.libipc is missing: {error}")
            return False

        try:
            add_listener(
                CLIPBOARDD_CLIENT_PROCESS_NAME,
                CLIPBOARDD_CHANGED_IPC_ID,
                self._on_clipboardd_changed,
                dict,
            )
            self.clipboardd_listener_registered = True
            self.clipboardd_remove_listener = remove_listener
            self.clipboardd_send = send

            subscription = self._send_clipboardd(
                "subscribe",
                {
                    "name": f"{APP_NAME} clipboard image watcher",
                    "forward_dest": {
                        "process_name": CLIPBOARDD_CLIENT_PROCESS_NAME,
                        "pid": os.getpid(),
                        "ipc_id": CLIPBOARDD_CHANGED_IPC_ID,
                    },
                },
            )
            subscription_id = subscription.get("subscription_id") if isinstance(subscription, dict) else None
            if not subscription_id:
                raise RuntimeError(f"clipboardd subscribe returned no subscription id: {subscription!r}")

            self.clipboardd_subscription_id = str(subscription_id)
            self.log("INFO", f"clipboardd subscription started: {self.clipboardd_subscription_id}")
            self._scan_clipboardd_latest()
            return True
        except Exception as error:
            self.log("ERROR", f"clipboardd subscription unavailable: {error}")
            self._stop_clipboardd_subscription()
            return False

    def _send_clipboardd(self, ipc_id: str, data: dict[str, Any]) -> Any:
        if self.clipboardd_send is None:
            raise RuntimeError("clipboardd send function is not initialized")
        try:
            return self.clipboardd_send(CLIPBOARDD_PROCESS_NAME, -1, ipc_id, data, dict, timeout=2.0)
        except TypeError:
            return self.clipboardd_send(CLIPBOARDD_PROCESS_NAME, -1, ipc_id, data, dict)

    def _stop_clipboardd_subscription(self) -> None:
        if self.clipboardd_subscription_id and self.clipboardd_send is not None:
            subscription_id = self.clipboardd_subscription_id
            self.clipboardd_subscription_id = None
            try:
                self._send_clipboardd("unsubscribe", {"subscription_id": subscription_id})
                self.log("INFO", f"clipboardd subscription stopped: {subscription_id}")
            except Exception as error:
                self.log("ERROR", f"Failed to unsubscribe from clipboardd: {error}")

        if self.clipboardd_listener_registered and self.clipboardd_remove_listener is not None:
            self.clipboardd_listener_registered = False
            try:
                self.clipboardd_remove_listener(CLIPBOARDD_CHANGED_IPC_ID)
            except Exception as error:
                self.log("ERROR", f"Failed to remove clipboardd listener: {error}")

    def _scan_clipboardd_latest(self) -> None:
        try:
            latest = self._send_clipboardd("get", {})
        except Exception as error:
            self.log("DEBUG", f"Could not fetch latest clipboardd value: {error}")
            return

        if isinstance(latest, dict) and latest.get("has_value"):
            self._handle_clipboardd_payload(latest, reason="clipboardd-latest")

    def _on_clipboardd_changed(self, _from_info, data: dict) -> None:
        self._handle_clipboardd_payload(data, reason="clipboardd")

    def _handle_clipboardd_payload(self, data: dict, reason: str) -> None:
        if not isinstance(data, dict):
            self.log("ERROR", f"clipboardd emitted invalid payload type: {type(data).__name__}")
            return
        if data.get("kind") != "image":
            self.log("DEBUG", f"clipboardd ignored non-image clipboard payload: {data.get('kind')}")
            return

        image_type = str(data.get("mime_type") or "").lower()
        if image_type == "image/jpg":
            image_type = "image/jpeg"
        if image_type not in CLIPBOARDD_SUPPORTED_IMAGE_TYPES:
            self.log("INFO", f"clipboardd image MIME type is not supported for QR scanning: {image_type}")
            return

        encoded = data.get("data_b64")
        if not isinstance(encoded, str) or not encoded:
            self.log("ERROR", "clipboardd image payload did not include data_b64")
            return

        try:
            image_data = base64.b64decode(encoded, validate=True)
        except (ValueError, binascii.Error) as error:
            self.log("ERROR", f"clipboardd image payload had invalid base64 data: {error}")
            return

        try:
            expected_size = int(data.get("size_bytes", len(image_data)))
        except (TypeError, ValueError):
            expected_size = len(image_data)
        if expected_size != len(image_data):
            self.log(
                "ERROR",
                f"clipboardd image payload size mismatch: expected={expected_size}, actual={len(image_data)}",
            )
            return
        if not looks_like_image_data(image_data):
            self.log("ERROR", f"clipboardd image payload did not look like a supported image: {image_type}")
            return

        digest = hashlib.sha256(image_data).hexdigest()
        if digest == self.clipboardd_last_digest:
            self.log("DEBUG", "clipboardd skipped unchanged image data")
            return
        self.clipboardd_last_digest = digest

        try:
            path = clipboard_image_path(image_data, image_type)
        except OSError as error:
            self.log("ERROR", f"Failed to cache clipboardd image for QR scan: {error}")
            return

        self.log("INFO", f"clipboardd image detected ({image_type}, {len(image_data)} bytes): {path}")
        self.queue_scan(path, reason=reason)

    def _start_wayland_clipboard_watch(self) -> bool:
        if not os.environ.get("WAYLAND_DISPLAY"):
            self.log("INFO", "Wayland clipboard watch unavailable because WAYLAND_DISPLAY is not set")
            return False
        if not shutil.which("wl-paste"):
            self.log("INFO", "Wayland clipboard watch unavailable because wl-paste is not installed")
            return False

        thread = threading.Thread(
            target=self._wayland_clipboard_watch_loop,
            name="captured-qr-agent-clipboard-watch",
            daemon=True,
        )
        thread.start()
        self.threads.append(thread)
        self.log("INFO", "Wayland clipboard subscription started with wl-paste --watch")
        return True

    def _on_changed(self, _monitor, file_obj, _other_file, event_type) -> None:
        event_name = self._event_name(event_type)
        if event_type not in (
            self.Gio.FileMonitorEvent.CREATED,
            self.Gio.FileMonitorEvent.CHANGES_DONE_HINT,
            self.Gio.FileMonitorEvent.MOVED_IN,
        ):
            self.log("DEBUG", f"Ignoring file event {event_name}: {file_obj.get_path()}")
            return

        path = Path(file_obj.get_path() or "")
        if path.is_file() and is_image_file(path):
            self.log("INFO", f"Capture detected ({event_name}): {path}")
            self.queue_scan(path, reason=event_name)
        else:
            self.log("DEBUG", f"Ignoring non-image file event {event_name}: {path}")

    def _on_gio_changed(self, monitor, file_obj, other_file, event_type) -> None:
        self._on_changed(monitor, file_obj, other_file, event_type)

    def queue_scan(self, path: Path, reason: str) -> None:
        self.log("INFO", f"Queued QR scan ({reason}): {path}")
        if self.GLib is not None:
            self.GLib.timeout_add(500, self._scan_once, str(path))
        else:
            timer = threading.Timer(0.5, self._scan_once, args=(str(path),))
            timer.daemon = True
            timer.start()

    def refresh_settings(self) -> None:
        refreshed = load_settings()
        self.settings.clear()
        self.settings.update(refreshed)
        self.log("INFO", f"Reloaded settings: {compact_json(self.settings)}")

    def _scan_once(self, raw_path: str) -> bool:
        path = Path(raw_path)
        self.log("INFO", f"Waiting for captured image to finish writing: {path}")
        if not wait_until_stable(path):
            self.log("ERROR", f"Captured image did not become stable before timeout: {path}")
            return False

        try:
            stat = path.stat()
        except FileNotFoundError:
            self.log("ERROR", f"Captured image disappeared before scan: {path}")
            return False
        except OSError as error:
            self.log("ERROR", f"Could not stat captured image {path}: {error}")
            return False

        processed_key = str(path)
        if self.processed.get(processed_key) == stat.st_mtime_ns:
            self.log("DEBUG", f"Skipping already processed image version: {path}")
            return False

        self.processed[processed_key] = stat.st_mtime_ns
        self.log("INFO", f"Starting QR decode: {path} ({stat.st_size} bytes)")
        content = detect_qr(path, self.log)
        if not content:
            self.log("INFO", f"QR decode failed; no QR code found: {path}")
            return False

        payload_hash = hashlib.sha256(f"{path}:{content}".encode("utf-8")).hexdigest()
        if payload_hash in self.recent_payloads:
            self.log("DEBUG", f"Skipping duplicate QR payload for image: {path}")
            return False

        self.recent_payloads.add(payload_hash)
        if len(self.recent_payloads) > 256:
            self.recent_payloads.clear()

        result = QRResult(source_path=path, content=content)
        self.log("INFO", f"QR decode success: {path}")
        self.log("INFO", f"QR content: {content}")
        self.refresh_settings()
        self.notification_center.notify(result)
        return False

    def _event_name(self, event_type) -> str:
        if self.Gio is None:
            return str(event_type)
        for name in dir(self.Gio.FileMonitorEvent):
            if name.startswith("_"):
                continue
            if getattr(self.Gio.FileMonitorEvent, name) == event_type:
                return name
        return str(event_type)

    def _inotify_loop(self, directories: list[Path]) -> None:
        mask_create = 0x00000100
        mask_close_write = 0x00000008
        mask_moved_to = 0x00000080
        mask_ignored = 0x00008000
        watch_mask = mask_create | mask_close_write | mask_moved_to

        libc = ctypes.CDLL("libc.so.6", use_errno=True)
        inotify_init1 = libc.inotify_init1
        inotify_init1.argtypes = [ctypes.c_int]
        inotify_init1.restype = ctypes.c_int
        inotify_add_watch = libc.inotify_add_watch
        inotify_add_watch.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_uint32]
        inotify_add_watch.restype = ctypes.c_int

        fd = inotify_init1(os.O_NONBLOCK | os.O_CLOEXEC)
        if fd < 0:
            error = ctypes.get_errno()
            self.log("ERROR", f"inotify_init1 failed: {os.strerror(error)}")
            return

        watch_dirs_by_id: dict[int, Path] = {}
        try:
            for directory in directories:
                wd = inotify_add_watch(fd, os.fsencode(directory), watch_mask)
                if wd < 0:
                    error = ctypes.get_errno()
                    self.log("ERROR", f"inotify_add_watch failed for {directory}: {os.strerror(error)}")
                    continue
                watch_dirs_by_id[wd] = directory
                self.log("INFO", f"inotify watching screenshot directory: {directory}")

            if not watch_dirs_by_id:
                self.log("ERROR", "inotify did not start any directory watch")
                return

            while not self.stop_event.is_set():
                readable, _writable, _errors = select.select([fd], [], [], 0.5)
                if not readable:
                    continue

                try:
                    data = os.read(fd, 65536)
                except BlockingIOError:
                    continue
                except OSError as error:
                    self.log("ERROR", f"inotify read failed: {error}")
                    return

                offset = 0
                while offset + 16 <= len(data):
                    wd, mask, _cookie, name_len = struct.unpack_from("iIII", data, offset)
                    offset += 16
                    raw_name = data[offset:offset + name_len].rstrip(b"\0")
                    offset += name_len

                    if mask & mask_ignored:
                        self.log("ERROR", f"inotify watch was removed for descriptor {wd}")
                        continue

                    directory = watch_dirs_by_id.get(wd)
                    if directory is None or not raw_name:
                        continue

                    path = directory / os.fsdecode(raw_name)
                    if path.is_file() and is_image_file(path):
                        self.log("INFO", f"Capture detected (INOTIFY mask=0x{mask:x}): {path}")
                        self.queue_scan(path, reason="inotify")
                    else:
                        self.log("DEBUG", f"Ignoring inotify event mask=0x{mask:x}: {path}")
        finally:
            os.close(fd)
            self.log("INFO", "inotify monitor stopped")

    def _clipboard_poll_loop(self) -> None:
        last_digest: str | None = None

        while not self.stop_event.is_set():
            interval = float(self.settings.get("clipboard_poll_interval_seconds", 1.0))
            self.stop_event.wait(interval)
            if self.stop_event.is_set():
                break

            result = read_clipboard_image(self.log if self.debug else None)
            if result is None:
                self.log("DEBUG", "Clipboard polling found no image data")
                continue

            image_data, image_type = result
            digest = hashlib.sha256(image_data).hexdigest()
            if digest == last_digest:
                self.log("DEBUG", "Clipboard polling skipped unchanged image data")
                continue

            last_digest = digest
            try:
                path = clipboard_image_path(image_data, image_type)
            except OSError as error:
                self.log("ERROR", f"Failed to cache clipboard image for QR scan: {error}")
                continue

            self.log("INFO", f"Clipboard image detected ({image_type}, {len(image_data)} bytes): {path}")
            self.queue_scan(path, reason="clipboard")

        self.log("INFO", "Clipboard polling stopped")

    def _wayland_clipboard_watch_loop(self) -> None:
        last_digest: str | None = None
        command = [
            "wl-paste",
            "--no-newline",
            "--type",
            CLIPBOARD_WATCH_IMAGE_TYPE,
            "--watch",
            sys.executable,
            str(Path(__file__).resolve()),
            "--clipboard-watch-helper",
        ]

        while not self.stop_event.is_set():
            self.log("INFO", f"Starting Wayland clipboard watch command: {' '.join(command)}")
            try:
                process = subprocess.Popen(
                    command,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
            except OSError as error:
                self.log("ERROR", f"Failed to start wl-paste clipboard watch: {error}")
                return

            try:
                while not self.stop_event.is_set():
                    if process.stdout is None:
                        self.log("ERROR", "wl-paste clipboard watch has no stdout pipe")
                        return

                    readable, _writable, _errors = select.select([process.stdout], [], [], 0.5)
                    if not readable:
                        return_code = process.poll()
                        if return_code is None:
                            continue
                        stderr = ""
                        if process.stderr is not None:
                            try:
                                stderr = process.stderr.read()
                            except OSError:
                                stderr = ""
                        message = stderr.strip()
                        if return_code == 0:
                            self.log("INFO", "Wayland clipboard watch exited normally")
                            return
                        if message:
                            self.log("ERROR", f"Wayland clipboard watch exited with {return_code}: {message}")
                        else:
                            self.log("ERROR", f"Wayland clipboard watch exited with {return_code}")
                        break

                    line = process.stdout.readline()
                    if line:
                        try:
                            payload = json.loads(line)
                        except json.JSONDecodeError:
                            self.log("ERROR", f"Wayland clipboard watch emitted invalid payload: {line.strip()}")
                            continue

                        path = Path(str(payload.get("path", "")))
                        image_type = str(payload.get("image_type", CLIPBOARD_WATCH_IMAGE_TYPE))
                        size = int(payload.get("size", 0))
                        digest = str(payload.get("sha256", ""))
                        if digest == last_digest:
                            self.log("DEBUG", "Wayland clipboard watch skipped unchanged image data")
                            continue

                        last_digest = digest
                        if not path.is_file():
                            self.log("ERROR", f"Wayland clipboard watch helper returned missing file: {path}")
                            continue

                        self.log("INFO", f"Clipboard image update received ({image_type}, {size} bytes): {path}")
                        self.queue_scan(path, reason="clipboard-watch")
                        continue

                    self.log("DEBUG", "Wayland clipboard watch produced an empty line")
            finally:
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        process.kill()

            if not self.stop_event.is_set():
                self.log("INFO", "Restarting Wayland clipboard watch after a short delay")
                self.stop_event.wait(2)

        self.log("INFO", "Wayland clipboard watch stopped")


def scan_file(path: Path, settings: dict[str, Any], execute: bool) -> int:
    if not path.is_file():
        log_error(f"File not found: {path}")
        return 2
    if not is_image_file(path):
        log_error(f"Not an image file: {path}")
        return 2

    log_event("INFO", f"Starting QR decode: {path}")
    content = detect_qr(path, log_event)
    if not content:
        log_event("INFO", "QR decode failed; no QR code detected.")
        return 1

    result = QRResult(source_path=path, content=content)
    log_event("INFO", "QR decode success")
    print(content)
    if execute:
        action = perform_preferred_action(result, settings, log_event)
        log_event("INFO", f"Action: {action}")
    return 0


def parse_args(args: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Recognize QR codes from GNOME screenshots.")
    parser.add_argument("--scan", metavar="IMAGE", help="scan one image and print the QR content")
    parser.add_argument("--execute", action="store_true", help="perform the configured action with --scan")
    parser.add_argument("--config-path", action="store_true", help="print the shared settings file path")
    parser.add_argument("--write-default-config", action="store_true", help="create the default settings file")
    parser.add_argument("--install-service", action="store_true", help="install this AppRun bundle as a global user service")
    parser.add_argument("--debug", action="store_true", help="print monitor diagnostics")
    parser.add_argument("--clipboard-watch-helper", action="store_true", help=argparse.SUPPRESS)
    return parser.parse_args(args)


def main(args: list[str]) -> int:
    parsed = parse_args(args)
    if parsed.clipboard_watch_helper:
        return clipboard_watch_helper()

    context = AppContext()

    if parsed.config_path:
        print(settings_path())
        return 0

    if parsed.write_default_config:
        settings = load_settings()
        save_settings(settings)
        print(settings_path())
        return 0

    if parsed.install_service:
        return 0 if context.install_as_global_user("simple", after=["graphical-session.target"]) else 1

    settings = load_settings()

    if parsed.scan:
        log_event("INFO", f"Manual scan requested: {parsed.scan}")
        log_event("INFO", f"Effective settings: {compact_json(settings)}")
        return scan_file(Path(parsed.scan).expanduser(), settings, parsed.execute)

    log_event("INFO", f"AppContext: {context}")
    try:
        context.ensure_single_process_user()
    except ProcessAlreadyRunningError as error:
        log_error(str(error))
        return 1
    except Exception as error:
        log_error(f"Failed to acquire daemon process lock: {error}")
        return 1
    log_event("INFO", "Acquired user-level daemon process lock")

    try:
        monitor = ScreenshotMonitor(settings, debug=parsed.debug)
    except ImportError as error:
        log_error(f"PyGObject/GIO is required to monitor screenshots: {error}")
        return 1
    except Exception as error:
        log_error(f"Failed to initialize screenshot monitor: {error}")
        return 1

    return monitor.start()


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
