import logging


def log_failed_login(username: str):
    logging.info("failed login for %s", username)
