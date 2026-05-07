import sys
import os
import argparse
import logging
from PyQt6.QtWidgets import QApplication
from ui.wizard import CaseWizard
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
        "--analysis",
        action="store_true",
        help="Skip case wizard and open analysis window directly. "
             "Use File → Open Image to load a memory dump.",
    )
    return p.parse_args()


def main():
    args = parse_args()
    setup_logging(args.log)
    log = logging.getLogger("dumpscope.main")

    app = QApplication(sys.argv)
    app.setApplicationName("DumpScope")
    app.setOrganizationName("DumpScope Forensics")

    if args.analysis:
        # Skip wizard — open a bare analysis window with no case data
        log.info("--analysis mode: skipping case wizard")
        dummy = {
            "case_name":      "Quick Analysis",
            "case_number":    "N/A",
            "date_time":      "",
            "base_dir":       os.path.expanduser("~"),
            "examiner_id":    "",
            "examiner_name":  "",
            "examiner_email": "",
            "examiner_phone": "",
            "notes":          "",
            "image_path":     "",
            "md5":            "",
            "sha256":         "",
            "is_dark":        True,
            "quick_mode":     True,
        }
        window = MainWindow(dummy)
        window.show()
        sys.exit(app.exec())
    else:
        wizard = CaseWizard()
        if wizard.exec() == CaseWizard.DialogCode.Accepted:
            case_data = wizard.get_case_data()
            log.info(
                "Case created: %s  [%s]",
                case_data["case_name"], case_data["case_number"]
            )
            window = MainWindow(case_data)
            window.show()
            sys.exit(app.exec())
        else:
            log.info("Wizard cancelled — exiting.")
            sys.exit(0)


if __name__ == "__main__":
    main()
