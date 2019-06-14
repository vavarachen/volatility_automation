# -*- coding: utf-8 -*-
import logging
import sys
import shutil
from datetime import datetime
import pathlib
import subprocess
import re
from pathlib import Path
import time


def set_default_logger(logger_name=None, logger_level=logging.DEBUG, propagate=False):
    if logger_name is None:
        logger = logging.getLogger(__name__)
    else:
        logger = logging.getLogger(logger_name)
    logger.setLevel(logger_level)
    logger.propagate = propagate
    return logger


def add_logger_streamhandler(logger=set_default_logger(), logger_level=logging.INFO, log_format=None, log_filter=None):
    """
    :param logger: Logging instance
    :param logger_level: Log verbosity level
    :param log_format: Log format string
    :param log_filter: logging.Filter object
    :return: logging.Logger
    """
    if format is None:
        _format = logging.Formatter(u"%(asctime)s - %(name)s - %(levelname)s - %(message)s")
    else:
        _format = logging.Formatter(log_format)
    try:
        handler = logging.StreamHandler()
        handler.set_name("{}_stream".format(logger.name))
        handler.setLevel(logger_level)
        if log_filter is not None:
            handler.addFilter(log_filter)
    except Exception as e:
        print("Failed to set logger (%s).  Falling back to defaults." % e)
        handler = logging.StreamHandler()
        handler.setLevel(logging.DEBUG)
    else:
        handler.setFormatter(_format)
        logger.addHandler(handler)
        return logger


def add_logger_filehandler(logger=set_default_logger(), logger_level=logging.INFO, filename='default.log',
                           log_format=None, log_filter=None):
    """
    add a file log handler to an existing logger
    :param logger: Typically, name of calling module
    :param logger_level: Log verbosity level
    :param filename: log output filename
    :param log_format: Log output format
    :param log_filter: Logging Filter object
    :return: logging.Logger
    """
    if format is None:
        _format = logging.Formatter(u"%(asctime)s - %(name)s - %(levelname)s - %(message)s")
    else:
        _format = logging.Formatter(log_format)
    try:
        fh = logging.FileHandler(filename)
        fh.set_name("{}_file".format(logger.name))
        fh.setLevel(logger_level)
        fh.setFormatter(_format)
        if log_filter is not None:
            fh.addFilter(log_filter)
        logger.addHandler(fh)
    except Exception as e:
        logger.error("Failed to set %s as log file handler. Error: %s" % (filename, e))
    finally:
        return logger


def add_logger_splunkhandler(logger=set_default_logger(), log_filter=None, **kwargs):
    """
    Handler for writing logs to Splunk index.
    :param logger: logging instance
    :param log_filter: logging Filter object
    :param kwargs: Splunk configuration options
    :return: logger with Splunk Handler attached
    """
    try:
        from splunk_hec_handler import SplunkHecHandler
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    except Exception as err:
        logger.warning("Failed to add Splunk log handler. Error: %s" % err)
        return logger
    else:
        try:
            host = kwargs.pop('host')
            token = kwargs.pop('token')
            level = kwargs.get('level', 'INFO')
            sh = SplunkHecHandler(host, token, **kwargs)
            sh.set_name("{}_splunk".format(logger.name))
        except Exception as err:
            logger.warning("Failed to add Splunk log handler.  Error: %s" % err)
            raise err
        else:
            sh.setLevel(level)
            if log_filter is not None:
                sh.addFilter(log_filter)
            logger.addHandler(sh)
    return logger


# https://www.oreilly.com/library/view/python-cookbook/0596001673/ch14s08.html
def whoami():
    return sys._getframe(1).f_code.co_name


def archive_dir(src_dir, dest_dir, logger, **kwargs):
    """
    Zip compress src_dir as archive_name to dest_dir.
    Archive name stem-YYYY-MM-DDTHH:mm.zip
    :param src_dir: Directory to archive
    :param dest_dir: Directory to store archive
    :param logger: logger instance
    :param kwargs: other args for shutil.make_archive
    :return: (str) path to archive
    """
    s_dir = src_dir
    d_dir = dest_dir
    try:
        if type(src_dir) != pathlib.PosixPath:
            s_dir = pathlib.Path(src_dir)
        assert s_dir.is_dir() and s_dir.exists()

        if type(dest_dir) != pathlib.PosixPath:
            d_dir = pathlib.Path(dest_dir)
        dest_dir.mkdir(parents=True, exist_ok=True)

    except Exception:
        raise
    else:
        try:
            s_dir_ctime = datetime.strftime(datetime.utcfromtimestamp(s_dir.stat().st_ctime), "%Y-%m-%dT%H-%M")
            archive_name = pathlib.Path.joinpath(d_dir, "%s_%s" % (s_dir.stem, s_dir_ctime))

            ret = shutil.make_archive(archive_name, 'zip', s_dir.parent.as_posix(), s_dir.as_posix(), logger, **kwargs)
        except Exception:
            raise
        else:
            shutil.rmtree(s_dir.as_posix(), ignore_errors=True)
            return ret


def run_command(args, **kwargs):
    try:
        proc = subprocess.run(args,
                              shell=kwargs.get('shell', False),
                              stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE,
                              encoding=kwargs.get('encoding','utf-8'),
                              errors=kwargs.get('errors','replace'),
                              timeout=kwargs.get('timeout', 300),
                              check=kwargs.get('check', True)
                              )
    except (subprocess.TimeoutExpired, subprocess.CalledProcessError):
        raise
    else:
        return proc


def volatility_error(stderr):
    try:
        if 'volatility.debug' in stderr:
            return re.findall(r"volatility.debug\s+:\s+(?P<error>.+)\s?", stderr)[0]
        elif 'error:' in stderr:
            return re.findall(r"error:\s+(?P<error>.+)\s?", stderr)[0]
    except IndexError:
        return stderr


def file_transfer_complete(file_path, timeout=600, pause=10):
    try:
        dump = Path(file_path)
    except Exception:
        raise
    else:
        # Ensure file transfer is complete
        prev_file_size = dump.stat().st_size
        time.sleep(pause)
        cur_file_size = dump.stat().st_size
        while prev_file_size != cur_file_size:
            time.sleep(pause)
            prev_file_size = cur_file_size
            cur_file_size = dump.stat().st_size
            timeout -= pause
            if timeout < 0:
                return False

        return True
