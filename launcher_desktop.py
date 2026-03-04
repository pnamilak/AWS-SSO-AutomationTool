# launcher_desktop.py
import os
import sys
import time
import socket
import threading
import traceback
import webbrowser
import logging
from pathlib import Path

APP_TITLE = "SRC Platform SSO & SSM Control Panel"
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 5050

# --------------------------------------------------------------------------------------
# Cross-platform app data dir (matches main.py behavior)
# --------------------------------------------------------------------------------------
def get_app_data_dir(app_name: str = "AwsSsoSsmDashboardTool") -> Path:
    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
        return Path(base) / app_name
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / app_name
    xdg = os.environ.get("XDG_DATA_HOME")
    if xdg:
        return Path(xdg) / app_name
    return Path.home() / ".local" / "share" / app_name

APP_DATA_DIR = get_app_data_dir()
LOG_DIR = APP_DATA_DIR / "logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)

PRIMARY_LOG = LOG_DIR / "launcher.log"
FALLBACK_LOG = Path(os.environ.get("TMPDIR", str(Path.home()))) / "AwsSsoSsmDashboardTool_launcher_fallback.log"


def _write_fallback(text: str) -> None:
    try:
        with open(FALLBACK_LOG, "a", encoding="utf-8", errors="ignore") as f:
            f.write(text + ("\n" if not text.endswith("\n") else ""))
    except Exception:
        pass


def setup_logger() -> logging.Logger:
    logger = logging.getLogger("AwsSsoSsmDashboardTool.Launcher")
    logger.setLevel(logging.INFO)
    if logger.handlers:
        return logger

    fmt = logging.Formatter("[%(asctime)s] %(levelname)s %(message)s", "%Y-%m-%d %H:%M:%S")
    try:
        fh = logging.FileHandler(str(PRIMARY_LOG), encoding="utf-8")
        fh.setFormatter(fmt)
        logger.addHandler(fh)
        logger.info("Logger initialized: %s", str(PRIMARY_LOG))
    except Exception as ex:
        _write_fallback("LOGGER_PRIMARY_FAILED: " + repr(ex))
    return logger


LOG = setup_logger()

# Optional: pywebview
try:
    import webview  # type: ignore
except Exception as ex:
    webview = None
    LOG.info("pywebview import failed: %r", ex)


def is_frozen() -> bool:
    return getattr(sys, "frozen", False)


def app_base_dir() -> Path:
    if is_frozen() and hasattr(sys, "_MEIPASS"):
        return Path(getattr(sys, "_MEIPASS")).resolve()
    return Path(__file__).resolve().parent


def ensure_import_paths() -> None:
    base = app_base_dir()
    os.chdir(str(base))
    if str(base) not in sys.path:
        sys.path.insert(0, str(base))
    LOG.info("BaseDir=%s", str(base))
    LOG.info("CWD=%s", os.getcwd())
    LOG.info("Frozen=%s", str(is_frozen()))
    if hasattr(sys, "_MEIPASS"):
        LOG.info("sys._MEIPASS=%s", str(getattr(sys, "_MEIPASS")))


def port_is_listening(host: str, port: int) -> bool:
    try:
        with socket.create_connection((host, port), timeout=0.5):
            return True
    except Exception:
        return False


def can_bind(host: str, port: int) -> bool:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.bind((host, port))
        return True
    except Exception:
        return False
    finally:
        try:
            s.close()
        except Exception:
            pass


def pick_port(host: str, preferred: int, span: int = 50) -> int:
    if can_bind(host, preferred):
        return preferred
    for p in range(preferred + 1, preferred + span + 1):
        if can_bind(host, p):
            return p
    return preferred


def wait_for_port(host: str, port: int, timeout_sec: int = 40) -> bool:
    deadline = time.time() + timeout_sec
    while time.time() < deadline:
        if port_is_listening(host, port):
            return True
        time.sleep(0.35)
    return False


def _serve_using_main(host: str, port: int) -> None:
    os.environ["DASHBOARD_HOST"] = host
    os.environ["DASHBOARD_PORT"] = str(port)

    import main  # noqa

    if hasattr(main, "serve_app"):
        LOG.info("Server: calling main.serve_app(host=%s, port=%d)", host, port)
        main.serve_app(host=host, port=port)
        return

    # Fallback: run flask directly if exposed
    flask_app = getattr(main, "app", None) or getattr(main, "APP", None)
    if flask_app is not None:
        LOG.info("Server: fallback flask dev server host=%s port=%d", host, port)
        flask_app.run(host=host, port=port, debug=False, threaded=True)
        return

    raise RuntimeError("main.py does not expose serve_app(), app, or APP")


def start_server_thread(host: str, port: int) -> None:
    try:
        _serve_using_main(host, port)
    except Exception as ex:
        LOG.error("SERVER_CRASH: %r", ex)
        LOG.error(traceback.format_exc())
        _write_fallback("SERVER_CRASH: " + repr(ex) + "\n" + traceback.format_exc())


def run_browser_mode(url: str, server_thread: threading.Thread) -> None:
    try:
        webbrowser.open(url)
    except Exception:
        pass
    while server_thread.is_alive():
        time.sleep(1.0)


def main_entry() -> None:
    ensure_import_paths()

    host = os.environ.get("DASHBOARD_HOST", DEFAULT_HOST)
    preferred_port = int(os.environ.get("DASHBOARD_PORT", str(DEFAULT_PORT)))
    chosen_port = pick_port(host, preferred_port)
    url = f"http://{host}:{chosen_port}/"

    LOG.info("Launcher starting host=%s preferred_port=%d chosen_port=%d url=%s",
             host, preferred_port, chosen_port, url)
    LOG.info("primary_log=%s", str(PRIMARY_LOG))
    LOG.info("fallback_log=%s", str(FALLBACK_LOG))
    LOG.info("webview_available=%s", str(webview is not None))

    server_thread = threading.Thread(target=start_server_thread, args=(host, chosen_port), daemon=True)
    server_thread.start()

    ok = wait_for_port(host, chosen_port, timeout_sec=40)
    LOG.info("Port listening=%s host=%s port=%d", str(ok), host, chosen_port)

    if not ok:
        # show browser anyway so user sees something; but log will show crash
        run_browser_mode(url, server_thread)
        return

    if webview is None:
        run_browser_mode(url, server_thread)
        return

    # IMPORTANT: do NOT force gui="edgechromium" on macOS
    webview.create_window(APP_TITLE, url, width=1280, height=800, text_select=True, confirm_close=True)
    webview.start(debug=False)


if __name__ == "__main__":
    main_entry()
