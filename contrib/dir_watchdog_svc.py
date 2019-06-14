# -*- coding: utf-8 -*-
"""
Volatility Memory Dump Monitoring Windows Service
Install: python.exe dir_watchdog_svc.py --startup=auto --wait 5 install
Uninstall: sc delete volatilitywatchdog
"""
import win32service
import win32serviceutil
import win32event
import servicemanager
from splunk_volatility_input.dir_watchdog import DirectoryMonitor, logger
from splunk_volatility_input.configs.defaults import MONITORED_FOLDERS
import sys


class VolService(win32serviceutil.ServiceFramework):
    # you can NET START/STOP the service by the following name
    _svc_name_ = "VolatilityWatchdog"
    # this text shows up as the service name in the Service
    # Control Manager (SCM)
    _svc_display_name_ = "Volatility Automation"
    # this text shows up as the description in the SCM
    _svc_description_ = "Service to monitor for new memory dumps for Volatility processing"

    def __init__(self, args):
        win32serviceutil.ServiceFramework.__init__(self, args)
        # create an event to listen for stop requests on
        self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)
        self.timeout = 120000

    # core logic of the service
    def SvcDoRun(self):
        servicemanager.LogInfoMsg("VolatilityWatchdog - START")
        logger.info("Starting VolatilityWatchdog Service")
        servicemanager.LogMsg(servicemanager.EVENTLOG_INFORMATION_TYPE, servicemanager.PYS_SERVICE_STARTED,
                              (self._svc_name_, ''))
        for monitored_folder in MONITORED_FOLDERS:
            d = DirectoryMonitor(monitored_folder.as_posix())
            d.run()
        while True:
            rc = win32event.WaitForSingleObject(self.hWaitStop, self.timeout)
            # if the stop event hasn't been fired keep looping
            if rc == win32event.WAIT_OBJECT_0:
                logger.debug("Stop signal received")
                # Stop signal encountered
                servicemanager.LogInfoMsg("VolatilityWatchdog - STOP")
                logger.info("Stopping VolatilityWatchdog Service")
                break
            # else:
            #     w.run()
        sys.exit(0)

    # called when we're being shut down
    def SvcStop(self):
        # tell the SCM we're shutting down
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        # fire the stop event
        win32event.SetEvent(self.hWaitStop)


if __name__ == '__main__':
    if len(sys.argv) == 1:
        servicemanager.Initialize()
        servicemanager.PrepareToHostSingle(VolService)
        servicemanager.StartServiceCtrlDispatcher()
    else:
        win32serviceutil.HandleCommandLine(VolService)
