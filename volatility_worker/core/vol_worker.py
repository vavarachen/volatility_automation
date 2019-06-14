import sys
import json
import shutil
import importlib
from configs.base_plugins import BasePlugins  # Default plugins set
from configs.base_plugins_configs import VolPlugin, BasePluginsConfigs  # Default plugin configs
from configs.defaults import case_dir_filter, case_archive_dir, case_processed_flag, \
    case_log_dir, case_output_dir, log_level, enable_splunk_integration, extracted_mem_dump_cleanup, AUTO_EXTRACT_SUFFIX
from .memory import MemoryDump
from .exceptions import *
from .memory_utils import execute_volatility_command
from .utils import whoami, set_default_logger, add_logger_filehandler, \
        add_logger_streamhandler, archive_dir, volatility_error
from pathlib import Path
from logging import Filter
from collections import Counter
from time import time

if enable_splunk_integration:
    from .utils import add_logger_splunkhandler
    from configs.defaults import splunk_config, splunk_results_index, \
        splunk_results_sourcetype, splunk_output_max, splunk_output


class ResultsExcludeFilter(Filter):
    """
    Logging filter to filter out results sent to Splunk.
    """
    def filter(self, record):
        if enable_splunk_integration:
            return not record.getMessage().count(splunk_results_index) >= 1
        else:
            return True


class VolWorker:
    def __init__(self, mem_image_path):
        s_time = int(time())
        self.dump_path = Path(mem_image_path)
        self.image_name = self.dump_path.stem
        self.case_id, self.case_dir = self.get_case_id()

        self.logger = None
        self.logging_args = None
        self.set_loggers()

        # Case ID's are key to Splunk logging and results correlation.
        # Refuse to process if Case ID folder structure is absent.
        if self.case_id == "":
            self.logger.error({'_action': whoami(), 'message': "Unable to determine case ID. Skipping."})
            raise CaseFolderNotFound(errors=self.dump_path.as_posix())
        elif Path.joinpath(self.case_dir, "{}{}".format(self.image_name, case_processed_flag)).exists():
            self.logger.warning({'_action': whoami(),
                                 'message': "Previously processed file %s. Remove %s.%s to re-process."
                                            % (self.image_name, self.image_name, case_processed_flag),
                                 })
            raise PreviouslyProcessed(errors=self.dump_path.as_posix())

        # Check to see if the memory dump is supported by Volatility.
        try:
            self.memory_dump = MemoryDump(self.dump_path.as_posix(), self.logger)
        except Exception as _err:
            self.logger.error({'_action': whoami(), 'message': "Unable to load image. Skipping."})
            raise MemoryImageLoadFailure(errors=_err)

        try:
            self.memory_dump.identify_profile()
        except Exception as err:
            self.del_auto_extracted_image()
            self.logger.error({'_action': whoami(),
                               'message': "Unable to determine profile. Terminating.",
                               'errors': [str(err)]
                               })
            raise MemoryImageProfileFailure
        else:
            if self.memory_dump.profile is None:
                self.del_auto_extracted_image()
                self.logger.error({'_action': whoami(), 'message': "Unable to determine profile. Terminating."})
                raise MemoryImageProfileFailure

        self.plugins_output_dir = Path.joinpath(self.case_dir, case_output_dir, self.image_name)
        self.archive_dir = Path.joinpath(self.case_dir, case_archive_dir)
        self.create_output_dir()

        try:
            # Get default or override plugins and associated configurations
            self.plugins = self.get_plugins()
        except Exception:
            self.logger.error({'_action': whoami(), 'message': "Unable to get plugins configuration. Terminating."})
            raise
        else:
            # collect stats on plugin execution
            self.runtime_stats = Counter({k: 0 for k in self.plugins.keys()})
            self.runtime_stats['initialization'] = int(time()) - s_time

    def del_auto_extracted_image(self):
        # Clean-up *.vol file
        if extracted_mem_dump_cleanup \
                and self.memory_dump.memory_path.suffix.lower() == "." + AUTO_EXTRACT_SUFFIX.lower():
            self.logger.info({'_action': whoami(),
                              'message': "Deleting %s" % self.memory_dump.memory_path.name,
                              'details': {'path': self.case_dir.as_posix()}
                              })
            self.memory_dump.memory_path.unlink()

    def run(self):
        self.logger.info({'_action': whoami(),
                          'message': "Processing %s." % self.dump_path.name,
                          'details': {'path': self.dump_path.as_posix(),
                                      'profile': self.memory_dump.profile,
                                      'plugins': list(self.plugins.keys())}
                          })
        self.run_plugins()

        # Drop processing completed flag
        Path.joinpath(self.case_dir, "{}{}".format(self.image_name, case_processed_flag)).touch()

        # housecleaning
        self.del_auto_extracted_image()

        self.logger.info({'_action': whoami(),
                          'message': "Runtime stats",
                          'details': self.runtime_stats})

    def create_output_dir(self):
        if self.plugins_output_dir.exists():
            try:
                # Archive results from previous runs
                archive_loc = archive_dir(self.plugins_output_dir, self.archive_dir, self.logger)
            except Exception as _err:
                self.logger.warning({'_action': whoami(),
                                     'message': "Failed to archive older plugins output",
                                     'details': {'src_dir': self.plugins_output_dir.as_posix(),
                                                 'dest_dir': self.archive_dir.as_posix()},
                                     'errors': [str(_err)]
                                     })
            else:
                self.logger.info({'_action': whoami(),
                                  'message': "Successfully archived plugins output folder.",
                                  'details': {'archive_file': archive_loc}
                                  })
        else:
            self.plugins_output_dir.mkdir(parents=True)

    def set_loggers(self):
        """
        Each worker uses an independent log handler.  This is largely done to leverage the ability to control the
        source, index fields for Splunk HEC logging.
        Operational logs are sent to the value of 'index' key defined in SPLUN_CONFIG.
        The source is set to 'volatility' or 'volatility:CaseID'.

        For plugins output, the logs are sent using source 'volatility:CaseID:plugin'.
        :return: None
        """
        self.logger = set_default_logger(self.image_name, logger_level=log_level.upper())
        _format = "%(asctime)s  %(levelname)s  %(module)s  %(message)s"

        _handlers = [handler.get_name() for handler in self.logger.handlers]

        if (log_level.upper() == "DEBUG") and ("{}_stream".format(self.image_name) not in _handlers):
            add_logger_streamhandler(self.logger, logger_level=log_level, log_format=_format,
                                     log_filter=ResultsExcludeFilter())

        if "{}_file".format(self.image_name) not in _handlers:
            log_file = Path.joinpath(self.case_dir, case_log_dir,
                                     "%s-%s.log" % (self.case_id, self.dump_path.stem))
            if log_file.parent.exists() is False:
                log_file.parent.mkdir()

            add_logger_filehandler(self.logger, logger_level=log_level,
                                   filename=log_file.as_posix(), log_format=_format, log_filter=ResultsExcludeFilter())

        if enable_splunk_integration and ("{}_splunk".format(self.image_name) not in _handlers):
            self.logging_args = splunk_config.copy()
            self.logging_args['source'] = "%s:%s" % (splunk_config['source'], self.case_id)
            try:
                add_logger_splunkhandler(self.logger, **self.logging_args)
            except Exception as _err:
                self.logger.warning("Failed to add Splunk log handler. %s" % _err)

        return

    def get_case_id(self):
        """
        Each memory dump must be associated with a case ID/Security Incident Request (SIR).
        From the memory dump path, the top most folder matching the case_dir_filter is used as the case_id folder.
        case_id folder is where the logs, archives, outputs folders will be created.
        :return: (str) case_id, (str) path to top most case ID folder
        """
        _case_id = None
        _parent_parts = self.dump_path.parent.parts
        for part in _parent_parts:
            if case_dir_filter.search(part):
                _case_id = part
                break

        if _case_id is None:
            _case_id = ""
            _case_dir = Path.joinpath(self.dump_path.parent, _case_id)
        else:
            _path = self.dump_path.as_posix()
            _case_dir = _path[0:_path.find(_case_id) + len(_case_id)]

        return _case_id.upper(), Path(_case_dir)

    def get_plugins(self):
        """
        Establish active plugins and merge default and override plugins configs
        :return: None
        """
        # override config must be named as upper-case CASE_ID.py
        _plugins = dict({})
        _plugins_set = BasePlugins().active_plugins

        case_override_config = Path.joinpath(self.case_dir, "%s.py" % self.case_id)
        if case_override_config.exists():
            sys.path.append(self.case_dir.as_posix())
            try:
                _override_config = importlib.import_module('{}'.format(self.case_id))
            except Exception as _err:
                sys.path.remove(self.case_dir.as_posix())
                self.logger.error({'_action': whoami(), 'message': "Override configuration import failed."})
                raise OverrideConfigFailure(errors=_err)
            else:
                self.logger.debug({'_action': whoami(),
                                  'message': "Override configuration import successful.",
                                   'details': {'config': case_override_config.as_posix()}})

                # Only run plugins specified in override file
                if hasattr(_override_config, "active_plugins"):
                    _plugins_set = _override_config.active_plugins

                # Run default plugins + additional plugins
                if hasattr(_override_config, "additional_plugins"):
                    _plugins_set.update(_override_config.additional_plugins)

                # Remove any excluded plugins
                if hasattr(_override_config, "exclude_plugins"):
                    _plugins_set.difference_update(_override_config.exclude_plugins)

                # Get default configs for active plugins
                _plugins = BasePluginsConfigs(self).get_active_plugins_configs(_plugins_set)

                # Override default configs
                if case_override_config.exists() and hasattr(_override_config, "plugins_configs"):
                    for _plugin in _plugins_set:
                        if _plugin in _override_config.plugins_configs.keys():
                            _plugins[_plugin] = VolPlugin(_plugin, **_override_config.plugins_configs[_plugin])
        else:
            _plugins = BasePluginsConfigs(self).get_active_plugins_configs(_plugins_set)

        # Plugins output folder clean-up.
        for _dir in self.plugins_output_dir.iterdir():
            if _dir.name not in _plugins_set:
                shutil.rmtree(_dir.as_posix())

        return _plugins

    def run_plugins(self):
        """
        This is the meat of the automation.  This function iterates over ACTIVE_PLUGINS and runs each using the
        associated configuration option (PLUGINS_CONFIG).
        :return: None
        """

        for plugin in self.plugins.values():
            s_time = int(time())
            try:
                self.logger.info({'_action': whoami(),
                                  'message': "Executing plugin '%s'." % plugin.name,
                                  'details': vars(plugin)
                                  })
                plugin_output = execute_volatility_command(self.memory_dump,
                                                           plugin.name,
                                                           self.logger,
                                                           **vars(plugin))
            except Exception as _err:
                self.logger.error({'_action': whoami(),
                                   'message': "Failed to run plugin '%s'" % plugin.name,
                                   'details': vars(plugin),
                                   'errors': [volatility_error(_err.stderr)]
                                   })
            else:
                if len(plugin_output) > 0:
                    try:
                        self.store_result(plugin, plugin_output)
                    except Exception as _err:
                        self.logger.error({'_action': whoami(),
                                           'message': "Failed to commit results for plugin '%s'" % plugin.name,
                                           'details': {'length': len(plugin_output)}.update(vars(plugin)),
                                           'errors': [str(_err)]
                                           })
                else:
                    self.logger.warning({'_action': whoami(),
                                         'message': "Plugin '%s' ran successfully but produced no output; maybe normal."
                                                    % plugin.name,
                                         'details': vars(plugin)
                                         })
            finally:
                self.runtime_stats[plugin.name] = int(time()) - s_time

    def store_result(self, plugin, plugin_output):
        """
        This function is responsible for writing the Volatility output to disk and Splunk.
        if splunk_output is set to "Auto" (default), then events are only committed to Splunk if the output
        is less than splunk_output_max limit.
        :param plugin: (str) plugin name
        :param plugin_output: (str) Volatility output
        :return:
        """
        results = plugin_output
        try:
            results = json.loads(plugin_output)
        except (TypeError, json.JSONDecodeError):
            file_ext = 'txt'
        else:
            file_ext = 'json'

        plugin_output_file = Path.joinpath(self.plugins_output_dir, plugin.name, "%s.%s" % (plugin.name, file_ext))

        self._save_to_disk(plugin, results, plugin_output_file)

        if enable_splunk_integration:
            self._send_to_splunk(plugin, results, plugin_output_file)

        self.logger.info({'_action': whoami(),
                          'message': "Plugin '%s' results processing successful." % plugin.name,
                          'details': {'results_file': plugin_output_file.as_posix(),
                                      'length': len(results)}
                          })

    def _save_to_disk(self, plugin, results, plugin_output_file):
        if not plugin_output_file.exists():
            Path(plugin_output_file.parent).mkdir(parents=True, exist_ok=True)
            results_file = open(plugin_output_file.as_posix(), 'w')
            results_file.writelines(results)
            results_file.close()
        else:
            # Some plugins (shellbags, mftparser, timeliner) can specify output file as part of the config.
            # We don't want to clobber that output.
            self.logger.warning({'_action': whoami(),
                                 'message': "Plugin output file (%s) exists.  Refusing to overwrite."
                                            % plugin_output_file.name,
                                 'details': vars(plugin)
                                 })

    def _send_to_splunk(self, plugin, results, plugin_output_file):
        results_len = len(results)
        if (plugin.splunk_output and results_len <= splunk_output_max) and (splunk_output.lower() == "auto"):
            self.logger.info({'_action': whoami(),
                              'fields': {'source': "%s:%s" % (self.logging_args['source'], plugin.name),
                                         'index': splunk_results_index,
                                         'sourcetype': splunk_results_sourcetype},
                              'results': results,
                              'details': {'results_file': plugin_output_file.as_posix(),
                                          'length': results_len,
                                          'splunk_output': plugin.splunk_output}
                              })
        else:
            # Plugin output too large for Splunk
            # Placeholder event for plugin output
            self.logger.info({'_action': whoami(),
                              'fields': {'source': "%s:%s" % (self.logging_args['source'], plugin.name),
                                         'index': splunk_results_index,
                                         'sourcetype': splunk_results_sourcetype},
                              'message': "Plugin output suppressed.",
                              'details': {'results_file': plugin_output_file.as_posix(),
                                          'length': results_len,
                                          'splunk_output': plugin.splunk_output,
                                          'splunk_threshold': splunk_output_max}
                              })

    def __del__(self):
        try:
            # Override config is sourced by adding the Case ID folder to the sys.path.  Remove on exit.
            sys.path.remove(self.case_dir.as_posix())
        except ValueError:
            pass
