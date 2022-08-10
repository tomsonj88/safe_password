import logging

formatter = logging.Formatter('%(asctime)s %(name)s %(levelname)s %(message)s')


def set_logger(name, log_file, level=logging.INFO, mode="a"):
    logger_handler = logging.FileHandler(log_file, mode=mode)
    logger_handler.setFormatter(formatter)

    logger = logging.getLogger(name)
    logger.setLevel(level)
    logger.addHandler(logger_handler)

    return logger
