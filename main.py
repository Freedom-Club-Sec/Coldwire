from ui.contact_list import ContactListWindow
import logging
import argparse
import sys

class LevelBasedFormatter(logging.Formatter):
    FORMATS = {
        logging.DEBUG:    "%(asctime)s [%(levelname)s] %(name)s:%(funcName)s:%(lineno)d - %(message)s",
        logging.INFO:     "%(asctime)s [%(levelname)s] -  %(message)s",
        logging.WARNING:  "%(asctime)s [%(levelname)s] %(name)s - %(message)s",
        logging.ERROR:    "%(asctime)s [%(levelname)s] %(name)s:%(funcName)s:%(lineno)d - %(message)s",
        logging.CRITICAL: "%(asctime)s [%(levelname)s] %(name)s:%(funcName)s:%(lineno)d - %(message)s"
    }

    def format(self, record):
        fmt = self.FORMATS.get(record.levelno, self._fmt)
        formatter = logging.Formatter(fmt)
        return formatter.format(record)

def setup_logging(debug: bool) -> None:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(LevelBasedFormatter())
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG if debug else logging.INFO)
    logger.addHandler(handler)

def parse_args():
    parser = argparse.ArgumentParser(description="Coldwire - Ultra-Paranoid, Post-Quantum Secure Messenger")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    setup_logging(args.debug)
    app = ContactListWindow()
    app.mainloop()
   
