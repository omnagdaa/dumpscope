import sys
import os
import argparse
import logging
from PyQt6.QtWidgets import QApplication
from core.case import Case, CaseError, remember_case
from core.plugins import PluginRegistry
from ui.case_manager import CaseManager
from ui.main_window import MainWindow


def setup_logging(log_file: str = None):
    handlers = [logging.StreamHandler(sys.stderr)]
    if log_file:
        os.makedirs(os.path.dirname(os.path.abspath(log_file)), exist_ok=True)
        handlers.append(logging.FileHandler(log_file, encoding="utf-8"))
    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s  %(levelname)-8s  %(name)s  —  %(message)s",
        handlers=handlers,
    )
    # Suppress noisy vol3 debug unless explicitly wanted
    logging.getLogger("volatility3").setLevel(logging.WARNING)


def parse_args():
    p = argparse.ArgumentParser(
        prog="dumpscope",
        description="DumpScope — Memory Forensics Platform",
    )
    p.add_argument(
        "--log",
        metavar="FILE",
        help="Write exceptions and debug logs to FILE (e.g. --log dumpscope.log)",
    )
    p.add_argument(
        "--refresh-plugins",
        action="store_true",
        help="Re-inspect volatility3 for its plugin list instead of using the cache.",
    )
    p.add_argument(
        "--analysis",
        action="store_true",
        help="Skip the case manager and open a Quick Analysis window directly. "
             "Nothing is saved in this mode.",
    )
    p.add_argument(
        "--case",
        metavar="DIR",
        help="Open the case in DIR without showing the case manager.",
    )
    return p.parse_args()


def main():
    args = parse_args()
    setup_logging(args.log)
    log = logging.getLogger("dumpscope.main")

    app = QApplication(sys.argv)
    app.setApplicationName("DumpScope")
    app.setOrganizationName("DumpScope Forensics")
    _register_with_windows_shell()

    # Built before any window exists: the first inspection imports every
    # volatility3 plugin module and takes a few seconds, and doing it here means
    # that cost is paid on a bare screen rather than freezing a visible window.
    # Subsequent launches read the cache and return immediately.
    registry = PluginRegistry.load(refresh=args.refresh_plugins)
    if registry.available:
        log.info("volatility3 %s — %d plugins", registry.vol_version, len(registry.all()))
    else:
        log.warning("volatility3 could not be inspected; plugin metadata is unavailable")

    # Closing a case returns here rather than exiting, so an examiner can move
    # between investigations without restarting the application.
    while True:
        case = _select_case(args, log)
        if case is None:
            return 0

        window = MainWindow(case, registry=registry)
        window.show()
        app.exec()

        if not getattr(window, "_reopen_manager", False):
            return 0
        # Only the first pass may be driven by --case/--analysis; afterwards the
        # examiner picks, otherwise Close Case would reopen the same case.
        args.case = None
        args.analysis = False
        log.info("Case closed — returning to the case manager")


def _register_with_windows_shell():
    """
    Claim a taskbar identity on Windows.

    Without an explicit AppUserModelID the shell attributes the window to
    python.exe, so DumpScope shares a taskbar button with every other Python
    program running and cannot carry its own icon.
    """
    if sys.platform != "win32":
        return
    try:
        import ctypes
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(
            "DumpScope.Forensics.Analysis.1"
        )
    except Exception:                       # nothing here is worth failing over
        logging.getLogger("dumpscope.main").debug("Could not set the app id")


def _select_case(args, log):
    """Resolve which case to open, or None when the user backed out."""
    if args.analysis:
        log.info("--analysis mode: opening a quick-analysis session")
        return Case.quick()

    if args.case:
        try:
            case = Case.open(args.case)
        except CaseError as exc:
            log.error("Could not open %s: %s", args.case, exc)
            print(f"Could not open case: {exc}", file=sys.stderr)
            return None
        remember_case(case)
        log.info("Opened case %s", case.display_label)
        return case

    manager = CaseManager()
    if manager.exec() != CaseManager.DialogCode.Accepted or manager.selected_case is None:
        log.info("No case selected — exiting.")
        return None
    log.info("Opened case %s", manager.selected_case.display_label)
    return manager.selected_case


if __name__ == "__main__":
    sys.exit(main())
