import logging
import traceback


def handle():
    try:
        return 10 / 0
    except ZeroDivisionError:
        logging.error("error: %s", traceback.format_exc())
        return "internal error"
