import asyncio
import os
import logging
import time
import sys

log_format = '%(asctime)s-%(name)s-%(levelname)s-%(message)s'

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

class TaskLogger():

    def __init__(self, name):
        self._logger = logging.getLogger(name)
        self._handler = TaskStreamHandler()
        self._handler.setFormatter(logging.Formatter(fmt=log_format))
        self._logger.addHandler(self._handler)
        self._logger.setLevel(logging.DEBUG)

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

