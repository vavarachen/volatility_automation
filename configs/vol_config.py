import sys
from pathlib import Path

if sys.platform == 'darwin':
    VOLATILITY_PATH = Path(r'/usr/local/homebrew/bin/vol.py')
elif sys.platform == 'linux':
    VOLATILITY_PATH = Path(r'/usr/bin/volatility')
elif sys.platform == 'win32':
    VOLATILITY_PATH = Path.joinpath(Path(__file__).resolve().parents[1],
                                    "contrib", "volatility_2.6_win64_standalone.exe")
else:
    raise OSError

# --plugins=PLUGINS     Additional plugin directories to use (colon separated)
# Paths must be absolute (https://volatilevirus.home.blog/2018/09/06/writing-plugins-for-volatility/)
VOLATILITY_CONTRIB_PLUGINS = r'%s' % Path.joinpath(Path(__file__).resolve().parents[1], "vol_plugins").as_posix()

# Timeout for volatility sub-process commands
# This timeout can be overridden at plugin level (global and per-plugin)
volatility_default_timeout = None
