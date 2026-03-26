import logging


def setup_logging(log_level: str = "INFO") -> None:
    """Setup basic logging configuration.

    :param log_level: Logging level (DEBUG, INFO, WARNING, ERROR)
    """
    level = getattr(logging, str(log_level).upper(), logging.INFO)
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
    )
