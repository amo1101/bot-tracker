import asyncio
import os
import logging
import time
import sys
from datetime import datetime

CUR_DIR = os.path.dirname(os.path.abspath(__file__))
log_format = '%(asctime)s-%(levelname)s-%(process)d-%(name)s: %(message)s'


class TaskStreamHandler(logging.StreamHandler):
    def __init__(self):
        super().__init__()

    def emit(self, record: logging.LogRecord) -> None:
        try:
            task = asyncio.current_task(asyncio.get_running_loop())
            task_name = 'null'
            if task is not None:
                task_name = task.get_name()
            record.__setattr__("name", f"{record.name}-{task_name}")
        except RuntimeError:
            pass
        super().emit(record)

class TaskFileHandler(logging.FileHandler):
    def __init__(self, filename):
        super().__init__(filename)

    def emit(self, record: logging.LogRecord) -> None:
        try:
            task = asyncio.current_task(asyncio.get_running_loop())
            task_name = 'null'
            if task is not None:
                task_name = task.get_name()
            record.__setattr__("name", f"{record.name}-{task_name}")
        except RuntimeError:
            pass
        super().emit(record)


class TaskLogger:
    _log_root = ''
    _logger = logging.getLogger(_log_root)
    #  _handler = TaskStreamHandler()
    _log_file = CUR_DIR + os.sep + 'log' + os.sep +\
                'bot-tracker-' +\
                datetime.now().strftime('%Y-%m-%d-%H-%M-%S') +\
                '.log'
    _handler = TaskFileHandler(_log_file)
    _handler.setFormatter(logging.Formatter(fmt=log_format))
    _logger.addHandler(_handler)
    _logger.setLevel(logging.DEBUG)

    def __init__(self, name):
        self._logger = logging.getLogger(name)

    def debug(self, *args, **kwargs):
        self._logger.debug(*args, **kwargs)

    def info(self, *args, **kwargs):
        self._logger.info(*args, **kwargs)

    def warning(self, *args, **kwargs):
        self._logger.warning(*args, **kwargs)

    def error(self, *args, **kwargs):
        self._logger.error(*args, **kwargs)

    def critical(self, *args, **kwargs):
        self._logger.critical(*args, **kwargs)
