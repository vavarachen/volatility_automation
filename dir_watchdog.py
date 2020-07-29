# -*- coding: utf-8 -*-
import time
from pathlib import Path
from datetime import datetime
from watchdog.observers import Observer
from watchdog.events import PatternMatchingEventHandler
from configs.defaults import MEM_DUMP_FILE_PATTERN, MONITORED_FOLDERS, \
    log_level, enable_splunk_integration, splunk_config, case_output_dir, AUTO_EXTRACT_SUFFIX, case_processed_flag, \
    file_transfer_timeout
from volatility_worker.core.utils import whoami, set_default_logger, add_logger_filehandler, \
    add_logger_streamhandler, add_logger_splunkhandler, file_transfer_complete
from volatility_worker.core.exceptions import *
from volatility_worker.core.vol_worker import VolWorker

JOBS_QUEUE = list()

logger = set_default_logger('root')
_format = "%(asctime)s  %(levelname)s  %(module)s  %(message)s"
add_logger_streamhandler(logger, logger_level=log_level, log_format=_format)

DEFAULT_LOG = Path.joinpath(Path(__file__).resolve().parents[0],
                            "logs", "default-%s.log" % datetime.now().strftime("%Y-%m-%d"))
add_logger_filehandler(logger, logger_level="DEBUG", filename=DEFAULT_LOG.as_posix(), log_format=_format)

if enable_splunk_integration:
    try:
        add_logger_splunkhandler(logger, **splunk_config)
    except Exception as err:
        logger.warning("Failed to add Splunk log handler. %s" % err)


class DirectoryMonitor:
    def __init__(self, directory_to_watch):
        self.directory_to_watch = directory_to_watch
        self.observer = Observer()

    def run(self):
        event_handler = Handler()
        self.observer.schedule(event_handler, path=self.directory_to_watch, recursive=True)
        logger.info({'_action': whoami(),
                     'message': "Start monitoring %s" % self.directory_to_watch})
        self.observer.start()
        try:
            while True:
                logger.debug("Current Queue Length: %d" % len(JOBS_QUEUE))
                while len(JOBS_QUEUE) > 0:
                    exit_code = threader()
                    if exit_code == 0:
                        logger.info("Job successful")
                    else:
                        logger.warning("Job unsuccessful")

                time.sleep(35)
        except KeyboardInterrupt:
            logger.info({'_action': whoami(),
                         'message': "End monitoring %s" % self.directory_to_watch})
            self.observer.stop()

        self.observer.join()


class Handler(PatternMatchingEventHandler):
    patterns = MEM_DUMP_FILE_PATTERN

    @staticmethod
    def process(event):
        """
                event.event_type
                    'modified' | 'created' | 'moved' | 'deleted'
                event.is_directory
                    True | False
                event.src_path
                    path/to/observed/file
                """
        # Ignore newly created files as a result of running Volatility plugsins (such as .dmp by memorydump plugin)
        # Ignore memory image extracted from non-standard format (i.e output created by hpackextract)
        if (event.src_path.count(case_output_dir) == 0) or (event.src_path.endswith(".%s" % AUTO_EXTRACT_SUFFIX)):
            JOBS_QUEUE.append(event)
            logger.info({'_action': whoami(),
                         'message': "Queue length: %d" % len(JOBS_QUEUE),
                         'details': {'path': event.src_path,
                                     'type': event.event_type}
                         })

    def on_created(self, event):
        """
        Depending on how file is created (scp, remote copy etc.), it might not be fully there.
        Ensure file size has stopped changing before sending it for processing.
        :param event: Watchdog event
        :return: none
        """
        logger.info({'_action': whoami(),
                     'message': "New file detected. Checking file transfer status...",
                     'details': {'path': event.src_path,
                                 'type': event.event_type,
                                 'timeout': file_transfer_timeout}
                     })

        if file_transfer_complete(event.src_path, file_transfer_timeout):
            self.process(event)
        else:
            logger.error({'_action': whoami(),
                          'message': "File transfer failure.  Skipping %s" % event.src_path,
                          })

    def on_modified(self, event):
        """
        On Windows and scp, copying or moving a file triggers a create and modify event.  Check to see if the file is
        already in queue, and if not, call on_create to handle any file transfer slowness.
        :param event: watchdog event
        :return: none
        """
        for _job in JOBS_QUEUE:
            if _job.src_path == event.src_path:
                logger.info({'_action': whoami(),
                             'message': "File is already in queue.",
                             'details': {'path': event.src_path,
                                         'type': event.event_type}
                             })
                return

        self.on_created(event)

    def on_moved(self, event):
        _q_len = len(JOBS_QUEUE)
        for _job in JOBS_QUEUE:
            if _job.src_path == event.src_path:
                JOBS_QUEUE.pop(JOBS_QUEUE.index(_job))
                logger.info({'_action': whoami(),
                             'message': "Removing moved file from queue.  Queue length changed from %d to %d."
                                        % (_q_len, len(JOBS_QUEUE)),
                             'details': {'path': event.src_path,
                                         'type': event.event_type}
                             })
        self.process(event)

    def on_deleted(self, event):
        _q_len = len(JOBS_QUEUE)
        for _job in JOBS_QUEUE:
            if _job.src_path == event.src_path:
                JOBS_QUEUE.pop(JOBS_QUEUE.index(_job))
                logger.info({'_action': whoami(),
                             'message': "Removing deleted file from queue.  Queue length changed from %d to %d."
                                        % (_q_len, len(JOBS_QUEUE)),
                             'details': {'path': event.src_path,
                                         'type': event.event_type}
                             })


def threader():
    w = JOBS_QUEUE.pop()
    logger.info({'_action': whoami(),
                 'message': "Starting worker thread for %s" % w.src_path})
    try:
        worker = VolWorker(w.src_path)
        worker.run()
    except CaseFolderNotFound as _err:
        logger.error({'_action': whoami(),
                      'message': "Unable to determine case ID. Skipping.",
                      'errors': [str(_err)]})
    except PreviouslyProcessed as _err:
        logger.warning({'_action': whoami(),
                        'message': "Previously processed case %s. Remove %s to re-process."
                                   % (Path(w.src_path).name, case_processed_flag),
                        'details': [str(_err)]
                        })
        return 0
    except MemoryImageLoadFailure as _err:
        logger.error({'_action': whoami(),
                      'message': "Unable to load image. Skipping.",
                      'details': {'path': w.src_path},
                      'errors': [str(_err)]})
    except MemoryImageProfileFailure:
        logger.error({'_action': whoami(),
                      'message': "Unable to determine profile. Terminating.",
                      'details': {'path': w.src_path}
                      })
    except OverrideConfigFailure as _err:
        logger.error({'_action': whoami(),
                      'message': "Override configuration import failed.",
                      'errors': [str(_err)]})
    except Exception as _err:
        logger.warning({'_action': whoami(),
                        'message': "Failed to process %s" % w.src_path,
                        'details': {'path': w.src_path,
                                    'error': str(_err)}
                        })
        return -1
    else:
        return 0


if __name__ == '__main__':
    for monitored_folder in MONITORED_FOLDERS:
        d = DirectoryMonitor(monitored_folder.as_posix())
        d.run()
