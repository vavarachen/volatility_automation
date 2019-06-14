# git clone https://pig.abbvienet.com/cti/volatility-automation.git
# sudo python3 -m venv /opt/volatility-automation/venv
# sudo touch /opt/volatility-automation/venv/.gitignore
# sudo chown -R <unprivileged-user>:<group> /opt/volatility-automation
# source /opt/volatility-automation/venv/bin/activate
# pip install -r /opt/volatility-automation/requirements.txt

# Adjust configuration files in 'splunk_volatility_input/configs' as needed.
# At a minimum review 'defaults.py' and 'vol_config.py'

# Edit '/opt/volatility-automation/contrib/vol-watchdog.service' as necessary (i.e 'User', 'Group', 'ExecStart')
# sudo cp /opt/volatility-automation/contrib/vol-watchdog.service /lib/systemd/system/
# sudo systemctl daemon-reload
# sudo systemctl enable vol-watchdog.service

# Service start
# sudo systemctl start vol-watchdog.service

# Service status
# sudo systemctl status vol-watchdog.service

# Service stop
# sudo systemctl stop vol-watchdog.service

[Unit]
Description = Volatility Automation Watchdog
After = multi-user.target
Conflicts = getty@tty1.service

[Service]
Type = simple
User=nobody
Group=nobody
ExecStart = /opt/volatility-automation/venv/bin/python3 /opt/volatility-automation/splunk_volatility_input/dir_watchdog.py
StandardInput = tty-force

[Install]
WantedBy = multi-user.target