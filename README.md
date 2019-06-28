# Volatility Automation
A tool to automate processing of memory dumps using Volatility.

## Features
1. Monitor one or more folders for memory images and process automatically using global and override configurations.  Memory images are detected using file extension, which is configurable.
2. Supports raw and hpak memory image formats.  Code can be easily extended to add support for other formats.
3. Allows plugin selection and configuration at a global and case ID level.  Case ID may contain one or more memory images.  Plugins can also be excluded at a global or case ID level.
4. Plugin results are written to disk (within case ID folder) and optionally can be sent to Splunk.  Code can be easily extended to support other SIEMs.
5. If Splunk integration is enabled, events are created using HEC.  Operational events are logged separately from Volatility output.
    * Splunk events are created using CaseID:Plugin source so it is easy to search, correlate, alert etc.
    * If events are larger than a configurable Splunk event size threshold, a place holder event is created with reference to plugin output results on disk.
    * If JSON format is supported and enabled for a plugin, Splunk events are created as such.  Default is 'text' format.
6. Image profile is detected using 'imageinfo' plugin and profile is cached to speed up re-processing.
7. Image profile detection can be overridden by dropping a '.profile' file specifying the Volatility profile in the case ID folder.
8. Script dictates use of a case ID folder structure.  Case ID format is configurable.  Images found outside of a case ID folders are ignored.
9. Upon successful completion, '.processed' flag is dropped to avoid accidental re-processing.
10. Plugins output is automatically archived upon re-processing so as not to lose previous results.
11. Plugins can be configured with any custom flags, including support for custom output files and folders.
12. New 'mactime' plugin has been added to process 'mftparser', 'timeliner' and 'shellbags' output to create timeline.
13. Paths to Volatility and 'mactime' are configurable.
14. Execution timeout values can be specified at a plugin-level

# Requirements
1. Python 3.6+
2. Volatility 2.6.x ('vol.py' on *nix and '[volatility_*.exe](http://downloads.volatilityfoundation.org/releases/2.6/volatility_2.6_win64_standalone.zip)' on Windows)
3. '[ordered-set](https://pypi.org/project/ordered-set/)'
4. '[splunk-hec-handler](https://pypi.org/project/splunk-hec-handler/)' if Splunk integration is desired.
5. '[watchdog](https://pypi.org/project/watchdog/)'

# Installation
Create and activate a new Python virtual environment (optional, but recommended).
```
> python.exe -m venv volatility_venv
> .\volatility_venv\Scripts\activate
```

Check out or unzip the code
```
> git clone https://github.com/vavarachen/volatility_automation.git
```

Install project dependencies (Python modules) using the 'requirements.txt' file in project root folder.
```
> pip install -r requirements.txt
```

Customize the script configurations to meet your needs.
..* 'defaults.py'
Windows
```python
# Folders to monitor for memory dumps
MONITORED_FOLDERS = [Path(r'C:\temp\memdumps')]
```

*nix
```python
MONITORED_FOLDERS = [Path(r'/var/tmp/memdumps')]
```


..* 'vol_config.py'
Windows
```python
VOLATILITY_PATH = Path(r'C:\Program Files (x86)\volatility_2.6_win64_standalone\volatility_2.6_win64_standalone.exe')
```

*nix
```python
VOLATILITY_PATH = Path(r'/usr/local/homebrew/bin/vol.py')
```

# Execution
Start the directory watchdog from the Python virtual environment (if used).  This will start active monitoring of all 'MONITORED_FOLDERS'
```
> .\volatility_venv\Scripts\activate
> cd volatility-automation.git\splunk_volatility_input\
> python dir_watchdog.py
```

Drop a case ID folder (naming defined by 'case_dir_filter' in 'defaults.py') containing one or more memory images. This should trigger the auto-processing of the memory image(s).

# Case ID Folder
The case ID folder requirements, while somewhat artificial, should be a norm for most forensics shops.  By requiring the memory images be placed in a case ID folder, the script is able to contain logs, plugins output, archiving etc at a case level.
Case ID also lends itself to logically group Splunk events.  For example, the following Splunk query can be used to get an overview of Volatility execution for a specific case ID.

```
(index="sec_input_logs" OR index="sec_volatility") source="volatility:SR000003"
| stats values(details.plugin) as "Executed Plugins", dc(details.plugin) as "Executed Plugins Count" by source
| appendcols [search (index="sec_input_logs" OR index="sec_volatility") source="volatility:SR000003:*"
    | stats values(source) as sources, dc(source) as count | table sources, count]
| table source, "Executed Plugins Count", "Executed Plugins", sources, count
| rename source as "Plugin Output Sources" , count as "Successful Output Plugins Count"
```
