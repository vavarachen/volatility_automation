from ordered_set import OrderedSet


class BasePlugins:
    """
    This file is sourced heavily by VolWorker class for plugins and associated configurations.
    This file controls what plugins will be run by default by an instance of VolWorker, unless there is an
    override configuration file in the case folder.
    """
    def __init__(self):
        """
        Default plugins and associated configuration
        """
        #
        # Volatility Plugins
        # Plugin Collections
        #

        # GROUPS defined based on https://github.com/volatilityfoundation/volatility/wiki/Command-Reference
        image_id_group = ['imageinfo', 'kdbgscan', 'kpcrscan']

        processes_dlls_group = ['pslist', 'pstree', 'psscan', 'dlllist', 'dlldump', 'handles', 'ldrmodules', 'getsids',
                                'cmdscan', 'consoles', 'privs', 'envars', 'verinfo']

        process_memory_group = ['atoms', 'atomscan', 'bigpools', 'bioskbd', 'callbacks', 'clipboard', 'cmdline',
                                'cmdscan', 'dumpcerts', 'eventhooks', 'gahti', 'gditimers', 'gdt', 'idt',
                                'joblinks', 'memmap', 'memdump', 'procdump', 'vaddump', 'windows', 'wintree',
                                'evtlogs', 'iehistory', 'notepad', 'screenshot', 'servicediff', 'sessions']

        kernel_memory_objects_group = ['modules', 'modscan', 'moddump', 'ssdt', 'driverscan', 'filescan',
                                       'mutantscan', 'symlinkscan', 'thrdscan', 'dumpfiles', 'unloadedmodules',
                                       'crashinfo', 'devicetree', 'driverirp', 'drivermodule', 'hibinfo', 'mbrparser',
                                       ]

        networking_group = ['cachedump', 'connections', 'connscan', 'sockets', 'sockscan', 'netscan']

        registry_group = ['auditpol', 'amcache', 'hivescan', 'hivelist', 'lsadump', 'userassist',
                          'shellbags', 'shimcache', 'getservicesids', 'dumpregistry', 'shutdowntime', 'svcscan']

        filesystem_group = ['mftparser', 'yarascan']

        contrib_group = ['timeliner']

        # Note: 'mactime' depends on the outputs of mftparser, shellbags and timeliner.  'custom_group' should be the
        # last entry in 'active_plugins' below
        custom_group = ['mactime']

        # Volatility plugin groups to run by default
        self.active_plugins = OrderedSet()
        self.active_plugins.update(image_id_group + processes_dlls_group + process_memory_group +
                                   kernel_memory_objects_group + networking_group + registry_group +
                                   filesystem_group + contrib_group + custom_group)

        # Specific plugins to exclude
        exclude_group = ['apihooks', 'kpcrscan', 'malfind', 'memdump', 'memmap', 'dlldump', 'dumpfiles', 'moddump', 'procdump',
                         'verinfo', 'vaddump', 'vadtree', 'vadwalk', 'vadinfo', 'handles', 'printkey',
                         'hivedump', 'hashdump', 'ssdt', 'strings', 'volshell']

        for plugin in exclude_group:
            try:
                self.active_plugins.remove(plugin)
            except KeyError:
                pass
