# log_utils.py
import logging

logger = logging.getLogger("contract_logger")
handler = logging.FileHandler("contract_errors.log")
formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
handler.setFormatter(formatter)
logger.addHandler(handler)
logger.setLevel(logging.ERROR)

def log_error(error_message: str):
    logger.error(error_message)
