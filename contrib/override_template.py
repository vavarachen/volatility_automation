from ordered_set import OrderedSet
from pathlib import Path
#
# This is a template for the Case-level override configuration file.
# To use it, the file name must match the case ID (i.e SR000005.py for case ID SR000005)
#

# Example of running minimal set of plugins for mactime
limited_plugins_group = ['shellbags', 'mftparser', 'timeliner', 'mactime']

# Only run custom list of plugins
active_plugins = OrderedSet()
active_plugins.update(limited_plugins_group)

# Run default + additional set of plugins
#additional_plugins = set()
#additional_plugins.update(limited_plugins_group)

# Exclude specific plugins
#exclude_plugins = set(['dlldump'])

#plugins_config = dict({
#    'dlldump': {'extra_flags': "--dump-dir=%s" % Path(r"/var/tmp/memdumps/").as_posix(),
#                'splunk_output': False
#                },
#    'dumpregistry': {'splunk_output': False}
#})
