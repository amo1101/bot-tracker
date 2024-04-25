import asyncio
import os
import logging
import time
import sys
from datetime import datetime

log_format = '%(asctime)s-%(process)d-%(name)s-%(levelname)s: %(message)s'


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
    _log_root = 'bot-tracker'
    _logger = logging.getLogger(_log_root)
    #  _handler = TaskStreamHandler()
    _handler = TaskFileHandler('bot-tracker-' +\
                               datetime.now().strftime('%m-%d-%Y-%H_%M_%S') +\
                               '.log')
    _logger.addHandler(_handler)
    _logger.setLevel(logging.DEBUG)

    def __init__(self, name):
        self._logger = logging.getLogger(TaskLogger.log_root + '.' + name)

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
