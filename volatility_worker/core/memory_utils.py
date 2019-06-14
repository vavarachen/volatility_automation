# Original author: Martin Korman
# https://github.com/mkorman90/VolatilityBot/tree/master/lib/core

import json
import subprocess
import shlex
from .utils import whoami, run_command

import re

from configs.vol_config import VOLATILITY_PATH, VOLATILITY_CONTRIB_PLUGINS, volatility_default_timeout


def execute_volatility_command(memory_instance, plugin_name, logger, **kwargs):
    """
    Execute a volatility command, and return the output, if it is json, return as dict
    :param memory_instance: memory dump object
    :param plugin_name: name of the plugin to execute, i.e malfind
    :param logger: log handler from worker
    :return:
    """
    profile = memory_instance.profile
    memory_path = memory_instance.memory_path
    logger.info({'_action': whoami(),
                 'message': "Executing '{}' plugin on '{}' image.".format(plugin_name, memory_path.name)
                 })

    if len(VOLATILITY_CONTRIB_PLUGINS) > 0:
        # https://volatilevirus.home.blog/2018/09/06/writing-plugins-for-volatility/
        # Due to some limitations of the framework, it is mandatory to write “–plugins” immediately after volatility.
        command = '{} --plugins {} --profile {} -f "{}" {} '.format(VOLATILITY_PATH.as_posix(),
                                                                    VOLATILITY_CONTRIB_PLUGINS,
                                                                    profile,
                                                                    memory_path,
                                                                    plugin_name)
    else:
        command = '{} --profile {} -f "{}" {} '.format(VOLATILITY_PATH.as_posix(), profile, memory_path, plugin_name)

    extra_flags = kwargs.get('extra_flags', None)
    # If the command has additional flags, add them here
    if extra_flags is not None:
        command += extra_flags + ' '

    # If the command has json output, add the output flag
    json_output = kwargs.get('json_output', False)
    if json_output:
        command += '--output=json'

    if logger.isEnabledFor(30):  # DEBUG
        print(command)
    logger.debug({'_action': whoami(),
                  'message': command
                  })

    args = shlex.split(command)
    try:
        proc = run_command(args, timeout=kwargs.get('timeout', volatility_default_timeout))
    except Exception:
        raise
    else:
        outs, errs = proc.stdout, proc.stderr
        # Volatility screen output for debugging
        logger.debug({'_action': whoami(),
                      'message': errs
                      })

    final_output = []
    if json_output:
        try:
            # Clean the output, to only contain the JSON
            match = re.search(r'(\{.+\})', outs)
            if match:
                output = match.group(1)
                plugin_output = json.loads(output)
                # Sort the plugin data to dictionary with key:value.
                for row in plugin_output['rows']:
                    entry = dict()
                    for column_index, parameter in enumerate(row):
                        entry[plugin_output['columns'][column_index]] = parameter
                    final_output.append(entry)
                return final_output
            else:
                logger.error({'_action': whoami(),
                              'message': 'The output of this plugin was not json.  Returning as raw.'
                              })
                return outs
        except (KeyError, ValueError):
            # If there is a problem with loading the JSON, return None for this plugin.
            logger.exception({'_action': whoami(),
                              'message': 'Plugin output is not JSON format or corrupted. Returning as raw.',
                              'details': errs
                              })
            return outs
    else:
        return outs
