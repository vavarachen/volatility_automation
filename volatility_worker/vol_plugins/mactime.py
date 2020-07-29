import volatility.plugins.common as common
import volatility.debug as debug
import os
import tempfile
import subprocess
import shlex
from shutil import copyfileobj


def which(cmd):
    paths = os.getenv('PATH')
    for path in paths.split(os.path.pathsep):
        cmd_path = os.path.join(path,cmd)
        if os.path.exists(cmd_path) and os.access(cmd_path,os.X_OK):
            return cmd_path


def get_mactime_cmd(mactime_path=None):
    if mactime_path is not None and os.path.exists(mactime_path) and os.access(mactime_path,os.X_OK):
        return mactime_path
    else:
        return which('mactime')


class MacTime(common.AbstractWindowsCommand):
    """ Runs 'mactime' on combines outputs from 'mftparser', 'timeliner' and 'shellbags' volatility plugins"""
    def __init(self, config, *args, **kwargs):
        common.AbstractWindowsCommand.__init__(self, config, *args, **kwargs)
        super(MacTime, self).register_options(config)

    @staticmethod
    def register_options(config):
        config.add_option("MFTPARSER_BODY", default=None, help="mftparser plugin output (body)")
        config.add_option("SHELLBAGS_BODY", default=None, help="shellbags plugin output (body)")
        config.add_option("TIMELINER_BODY", default=None, help="timeliner plugin output (body)")
        config.add_option("MACTIME_PATH", default=get_mactime_cmd(), help="mactime binary path")
        config.add_option("MACTIME_OUTPUT", default="mactime.csv", help="mactime output file")
        config.add_option("MACTIME_OPTIONS", default=None, help="See 'mactime --help'")

    def calculate(self):
        inputs = [self._config.TIMELINER_BODY, self._config.MFTPARSER_BODY, self._config.SHELLBAGS_BODY]
        if None in inputs:
            debug.warning("Not all input files specified ('mftparser', 'timeliner' and 'shellbags').")

        debug.info("Combining mftparser, shellbags and timeliner bodies")
        debug.info("mftparser: %s" % self._config.MFTPARSER_BODY)
        debug.info("shellbags: %s" % self._config.SHELLBAGS_BODY)
        debug.info("timeliner: %s" % self._config.TIMELINER_BODY)

        tmpfile = tempfile.NamedTemporaryFile(mode='wb')
        debug.info("Combined body file: %s" % tmpfile.name)

        for infile in inputs:
            try:
                with open(infile, mode='rb') as f:
                    copyfileobj(f, tmpfile)
            except Exception:
                pass

        tmpfile.seek(0)

        if self._config.MACTIME_OPTIONS is not None:
            command = "{} -d -b {}".format(self._config.MACTIME_PATH,tmpfile.name,
                                           self._config.MACTIME_OPTIONS)
        else:
            command = "{} -d -b {}".format(self._config.MACTIME_PATH, tmpfile.name)
        debug.info("Executing %s" % command)

        try:
            args = shlex.split(command)
            proc = subprocess.Popen(args, shell=False, stdin=tmpfile, stdout=subprocess.PIPE)
            cmd_output = proc.stdout.read()
        except Exception as err:
            debug.error("Failed to run 'mactime' command.  Error: %s" % err)
            return("Exception: {},\nmftparser: {},\n shellbags: {},\n timeliner: {},\n mactime path:{},\n "
                   "mactime options: {},\noutput file:{}".format(str(err),
                                                                 self._config.MFTPARSER_BODY,
                                                                 self._config.SHELLBAGS_BODY,
                                                                 self._config.TIMELINER_BODY,
                                                                 self._config.MACTIME_PATH,
                                                                 self._config.MACTIME_OPTIONS,
                                                                 self._config.MACTIME_OUTPUT))
        else:
            return cmd_output
        finally:
            tmpfile.close()

    def render_text(self, outfd, data):
        if self._config.MACTIME_OUTPUT is not None:
            debug.info("Writing output to %s" % self._config.MACTIME_OUTPUT)
            with open(self._config.MACTIME_OUTPUT, 'wb') as outputfile:
                outputfile.write(data)
        else:
            outfd.write(data)
