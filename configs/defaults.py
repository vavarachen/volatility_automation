from pathlib import Path
import re


# Default log level
log_level = "INFO"

enable_splunk_integration = False
splunk_config = {'host': 'localhost',
                 'port': 38088,
                 'proto': 'http',
                 'ssl_verify': False,
                 'token': '89775b93-6c77-4251-bd98-d300002dbbaf',
                 'source': 'volatility',
                 'sourcetype': '_json',
                 'index': 'sec_input_logs',
                 'level': 'INFO'}

splunk_results_index = 'sec_volatility'
splunk_results_sourcetype = 'notrunc_json'
# If plugin results is larger than SPLUNK_OUTPUT_MAX
# Only create a placeholder event
splunk_output_max = 100000
splunk_output = "Auto"

# Folders to monitor for memory dumps
memdumps = Path.joinpath(Path(__file__).resolve().parents[1], "memdumps")
MONITORED_FOLDERS = [Path(memdumps.as_posix())]
#MONITORED_FOLDERS = [Path(r'/var/tmp/memdumps')]

# File extensions of memory dumps.
# hpak format is auto-extracted to *.raw using 'hpakextract' plugin
MEM_DUMP_FILE_PATTERN = ["*.hpak", "*.vmem", "*.dump", "*.img", "*.dmp", "*.raw"]

# File extension of converted memory dumps.  Do not add this to MEM_DUMP_FILE_PATTERN.
AUTO_EXTRACT_SUFFIX = "vol"

# Clean-up converted memory dumps (*.vol) following successful execution.
extracted_mem_dump_cleanup = True

# How long to wait for file transfer to complete
file_transfer_timeout = 600

# Regex to identify task folders
case_dir_filter = re.compile('^SIR[0-9]{6,8}', re.I)
# Directories created in each task folder
case_log_dir = 'logs'
# Vol plugin output
case_output_dir = 'plugins_output'
# backup of previous runs
case_archive_dir = 'archives'
# File to indicate previously successfully processed
case_processed_flag = '.processed'


#
# Volatility Profile
#
# File containing image profile; skips and overrides profile detection
vol_profile_file = '.profile'
