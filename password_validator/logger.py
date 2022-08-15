"""
Module create new logger
"""

import logging

formatter = logging.Formatter('%(asctime)s %(name)s %(levelname)s %(message)s')


def set_logger(name: str, log_file: str, level=logging.INFO, mode: str = "a"):
    """
    Function for configure new logger
    :param name: logger name
    :param log_file: filename
    :param level: level of logger: INFO, DEBUG, WARNING etc.
    :param mode: mode for logging file: r - read, w - write, a - append
    :return: logger object
    """
    logger_handler = logging.FileHandler(log_file, mode=mode)
    logger_handler.setFormatter(formatter)

    logger = logging.getLogger(name)
    logger.setLevel(level)
    logger.addHandler(logger_handler)

    return logger
