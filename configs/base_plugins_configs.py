from pathlib import Path
from collections import OrderedDict
from configs.base_plugins import BasePlugins
from configs.vol_config import volatility_default_timeout


class VolPlugin:
    def __init__(self, plugin_name, **kwargs):
        self.name = plugin_name
        self.extra_flags = kwargs.get('extra_flags', None)
        self.splunk_output = kwargs.get('splunk_output', True)
        self.json_output = kwargs.get('json_output', False)
        self.timeout = volatility_default_timeout


class BasePluginsConfigs:
    def __init__(self, vol_worker):
        # vol_worker is used to access details like case id, folder, profile etc.
        self.worker = vol_worker
        self.default_active_plugins = BasePlugins().active_plugins

        # Options for plug-ins shipped with default Volatility
        # 'extra_flags' are plug-in specific options.  Default: None
        # 'output_format' format of plug-in output. Default: Text
        # 'timeout' how long the plugin should run before timing out.  Default: 300 seconds
        # 'splunk_output' Should the plugin output be written to Splunk.  Subjected to SPLUNK_OUTPUT_MAX
        # if SPLUNK_OUTPUT is set to "Auto".  Non Splunk-SIEMs can simply ingest from plugins output folder.
        self.all_plugins_config = dict({
            #
            # See https://github.com/volatilityfoundation/volatility/wiki/Command-Reference
            #
            'dumpcerts': VolPlugin('dumpcerts',
                                   **{'extra_flags': "--dump-dir %s" % self._make_plugin_output_dir('dumpcerts'),
                                      'splunk_output': False
                                      }),
            'dlldump': VolPlugin('dlldump', **{'splunk_output': False,
                                               'extra_flags': "--dump-dir %s"
                                                              % self._make_plugin_output_dir('dlldump')
                                               }),
            'dumpfiles': VolPlugin('dumpfiles', **{'splunk_output': True,
                                                   'extra_flags': "--dump-dir %s --summary-file %s" %
                                                                  (self._make_plugin_output_dir('dumpfiles'),
                                                                   self._make_plugin_output_file('dumpfiles',
                                                                                                 'summary.txt'))
                                                   }),
            'dumpregistry': VolPlugin('dumpregistry', **{'splunk_output': True,
                                                         'extra_flags': "--dump-dir %s"
                                                                        % self._make_plugin_output_dir('dumpregistry')
                                                         }),
            'evtlogs': VolPlugin('evtlogs',
                                 **{'extra_flags': "--dump-dir %s" % self._make_plugin_output_dir('evtlogs')
                                    }),
            'filescan': VolPlugin('filescan', **{'splunk_output': False}),
            'handles': VolPlugin('handles', **{'splunk_output': False}),
            'malfind': VolPlugin('malfind',
                                 **{'extra_flags': "--dump-dir %s" % self._make_plugin_output_dir('malfind')
                                    }),
            'memdump': VolPlugin('memdump',
                                 **{'extra_flags': "--dump-dir %s" % self._make_plugin_output_dir('memdump')
                                    }),
            # set for mactime - https://volatility-labs.blogspot.com/2013/05/movp-ii-23-creating-timelines-with.html
            'mftparser': VolPlugin('mftparser', **{'splunk_output': False,
                                                   'extra_flags': "--output=body --output-file %s"
                                                                  % self._make_plugin_output_file('mftparser',
                                                                                                  'mftparser.txt')
                                                   }),
            'moddump': VolPlugin('moddump', **{'splunk_output': False,
                                               'extra_flags': "--dump-dir %s"
                                                              % self._make_plugin_output_dir('moddump')
                                               }),
            'mutantscan': VolPlugin('mutantscan', **{'extra_flags': "--silent"}),
            'procdump': VolPlugin('procdump',
                                  **{'extra_flags': "--dump-dir %s" % self._make_plugin_output_dir('procdump')
                                     }),
            'screenshot': VolPlugin('screenshot',
                                    **{'extra_flags': "--dump-dir %s" % self._make_plugin_output_dir('screenshot'),
                                       'splunk_output': False
                                       }),
            # set for mactime - https://volatility-labs.blogspot.com/2013/05/movp-ii-23-creating-timelines-with.html
            'shellbags': VolPlugin('shellbags', **{'splunk_output': False,
                                                   'extra_flags': "--output body --output-file %s"
                                                                  % self._make_plugin_output_file('shellbags',
                                                                                                  'shellbags.txt')
                                                   }),
            'ssdt': VolPlugin('ssdt', **{'splunk_output': False}),
            # set for mactime - https://volatility-labs.blogspot.com/2013/05/movp-ii-23-creating-timelines-with.html
            'timeliner': VolPlugin('timeliner', **{'splunk_output': False,
                                                   'extra_flags': "--output body --output-file %s"
                                                                  % self._make_plugin_output_file('timeliner',
                                                                                                  'timeliner.txt')
                                                   }),
            'verinfo': VolPlugin('verinfo', **{'splunk_output': False}),
            'vadinfo': VolPlugin('vadinfo', **{'splunk_output': False}),
            'vadwalk': VolPlugin('vadwalk', **{'splunk_output': False}),
            'vadtree': VolPlugin('vadtree', **{'splunk_output': False}),
            'vaddump': VolPlugin('vaddump', **{'splunk_output': False,
                                               'extra_flags': "--dump-dir %s" % self._make_plugin_output_dir('vaddump')
                                               }),
            # 'mactime' should be run after 'mftparser', 'shellbags' and 'timeliner' plugins have run
            'mactime': VolPlugin(
                'mactime', **{'extra_flags': "--mftparser_body=%s --shellbags_body=%s --timeliner_body=%s --mactime_output=%s"
                                             % (self._make_plugin_output_file('mftparser', 'mftparser.txt'),
                                                self._make_plugin_output_file('shellbags', 'shellbags.txt'),
                                                self._make_plugin_output_file('timeliner', 'timeliner.txt'),
                                                self._make_plugin_output_file('mactime', 'mactime.txt')),
                              'splunk_output': False
                              }),
        })

        # defaults for plugins not explicitly configured in all_plugins_config
        for plugin in self.default_active_plugins:
            if plugin not in self.all_plugins_config.keys():
                self.all_plugins_config[plugin] = VolPlugin(plugin)

    def _make_plugin_output_dir(self, plugin):
        """
        Sometimes plugins create artifacts on disk.  This function allows us to create a folder specific to the
        case and memory image in the outputs folder.
        :param plugin: volatility plugin name
        :return: path to plugin output folder
        """
        p_dir = Path.joinpath(self.worker.plugins_output_dir, plugin)
        if p_dir.exists() is False:
            p_dir.mkdir(parents=True)

        if p_dir.exists() and p_dir.is_dir():
            return p_dir.as_posix()
        else:
            return self.worker.plugins_output_dir

    def _make_plugin_output_file(self, plugin, file_name):
        """
        Sometimes plugins create artifacts on disk.  This function allows us to create a folder specific to the
        case and memory image in the outputs folder.
        :param plugin: volatility plugin name
        :return: path to plugin output folder
        """
        p_dir = Path(self._make_plugin_output_dir(plugin))
        return Path.joinpath(p_dir, file_name).as_posix()

    def get_active_plugins_configs(self, plugins=None):
        """
        Default configurations for Activated plugins or specified plugins
        :param plugins: iterable with plugin names
        :return: dict of configurations
        """
        # Beyond some common plugin flags (-f, --profile etc.), there could be any number of arbitrary flags.
        # These flags can be specified in 'base_plugins_configs.py'
        # or at a Case ID level using the override config file.
        active_plugins_config = OrderedDict({plugin: self.all_plugins_config[plugin] for plugin in plugins
                                             if plugin in self.all_plugins_config.keys()})

        return active_plugins_config
