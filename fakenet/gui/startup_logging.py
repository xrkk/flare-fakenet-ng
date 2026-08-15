# -*- coding: utf-8 -*-
"""Pure-standard-library startup logging for the GUI process."""

import datetime
import logging
import os
import platform
import sys


_LOGGER = None
_LOG_PATH = None


def runtime_directory():
    """Directory beside the frozen GUI, or the source repository root."""
    if getattr(sys, 'frozen', False):
        return os.path.dirname(os.path.abspath(sys.executable))
    return os.path.dirname(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__))))


def _reserve_log_path(now=None, pid=None):
    now = now or datetime.datetime.now()
    pid = pid if pid is not None else os.getpid()
    directory = os.path.join(runtime_directory(), 'Logs')
    os.makedirs(directory, exist_ok=True)
    stem = 'fakenet-GUI-%s-p%d' % (
        now.strftime('%Y%m%d-%H%M%S-%f'), pid)
    for number in range(1000):
        suffix = '' if number == 0 else '-%d' % number
        path = os.path.join(directory, stem + suffix + '.log')
        try:
            descriptor = os.open(
                path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        except FileExistsError:
            continue
        os.close(descriptor)
        return path
    raise OSError('无法分配唯一的 fakenet-GUI 日志文件名')


def configure():
    """Install and return the GUI process's sole UTF-8 file logger."""
    global _LOGGER, _LOG_PATH
    if _LOGGER is not None:
        return _LOGGER, _LOG_PATH

    path = _reserve_log_path()
    try:
        handler = logging.FileHandler(path, mode='a', encoding='utf-8')
    except BaseException:
        try:
            os.remove(path)
        except OSError:
            pass
        raise

    handler.setLevel(logging.DEBUG)
    handler.setFormatter(logging.Formatter(
        '%(asctime)s [%(levelname)-8s] [%(name)18s] '
        'pid=%(process)d thread=%(threadName)s %(message)s',
        datefmt='%m/%d/%y %I:%M:%S %p'))
    logger = logging.getLogger('fakenet.GUI')
    logger.handlers = []
    logger.propagate = False
    logger.setLevel(logging.DEBUG)
    logger.addHandler(handler)

    _LOGGER = logger
    _LOG_PATH = path
    logger.info(
        'fakenet-GUI startup: log=%s executable=%s frozen=%s cwd=%s '
        'argv=%r python=%s platform=%s',
        path, sys.executable, bool(getattr(sys, 'frozen', False)),
        os.getcwd(), sys.argv, sys.version, platform.platform())
    return logger, path
