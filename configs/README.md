# defaults.py
The parameters in this file heavily influence 'dir_watchdog.py' operations, logging and some 'vol_worker.py' features.

# vol_config.py
Controls location of Volatility binary and plugins folders.

# base_plugins.py
The parameters in this file control which Volatility plugins will run by default ('active_plugins').  You can also globally exclude plugins.

# base_plugins_configs.py
This file controls any special parameters required for the successful execution of a plugin.
It also controls Splunk logging, execution timeout and output format.