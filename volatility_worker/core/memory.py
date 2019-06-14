# Original author: Martin Korman
# https://github.com/mkorman90/VolatilityBot/tree/master/lib/core

import logging
import subprocess
import shlex
from pathlib import Path

import re
from configs.vol_config import VOLATILITY_PATH, volatility_default_timeout
from configs.defaults import AUTO_EXTRACT_SUFFIX, vol_profile_file
from .utils import whoami, run_command


class MemoryDump:
    def __init__(self, dump_path, logger):
        self.logger = logger
        self.profile = None
        self.logger.info({'_action': whoami(),
                          'message': 'Start processing {}'.format(dump_path)
                          })
        # hpak handling
        if Path(dump_path).suffix.lower() == '.hpak':
            self.memory_path = self.extract_hpak(dump_path)
        else:
            self.memory_path = Path(dump_path)
        self.logger.info({'_action': whoami(),
                          'message': 'Loaded memory dump: {}'.format(self.memory_path.name)
                          })

    def identify_profile(self):
        """
        Determine Volatility Profile to process image
        :return: Profile name (str)
        """
        self.logger.info({'_action': whoami(),
                          'message': "Starting profile identification for {}.".format(self.memory_path.name)})
        profile_hint = Path.joinpath(self.memory_path.parent, "{}{}".format(self.memory_path.stem, vol_profile_file))

        # Determine profile using .profile override file
        if profile_hint.exists() and profile_hint.is_file():
            with profile_hint.open('r') as pf:
                self.profile = pf.readline().strip()
                self.logger.info({'_action': whoami(),
                                  'message': "Profile override file found. "
                                             "'{}' will be processed using '{}' profile.".format(
                                      self.memory_path.name, self.profile)
                                  })
            return

        # Determine profile using 'imageinfo' plugin
        self.logger.info({'_action': whoami(),
                          'message': "Determining Volatility profile for {} using 'imageinfo' plugin.".format(
                              self.memory_path.name)})
        self.profile = None
        command = '{0} -f "{1}" imageinfo'.format(VOLATILITY_PATH.as_posix(), self.memory_path.as_posix())
        args = shlex.split(command)
        try:
           proc = run_command(args, timeout=volatility_default_timeout)
        except Exception:
            raise
        else:
            outs, errs = proc.stdout, proc.stderr
            output_list = outs.splitlines()
            for single_line in output_list:
                result = re.match(r'Suggested Profile\(s\) : (.+)', single_line.strip())

                if result:
                    self.profile = result.groups(0)[0].split(',')[0].strip() \
                        if result.groups(0)[0].count("No suggestion") == 0 else None
                    break

            if self.profile:
                self.logger.info({'_action': whoami(),
                                  'message': "'{}' will be processed using '{}' profile.".format(
                                      self.memory_path.name, self.profile)
                                  })
                # Save the profile for re-runs
                with profile_hint.open('w') as pf:
                    pf.write(self.profile)

        return

    def extract_hpak(self, dump_path):
        """
        Extract a Volatility compatible raw image from hpak file.
        https://github.com/volatilityfoundation/volatility/wiki/Hpak-Address-Space
        :param dump_path: (str) path to .hpak file
        :return: Path object to extracted .raw file
        TODO: Convert to a more generic method capable of handling other formats.
        i.e .vmss/.vmsn, firewire, crash dumps, hibernation files, e01, LiME, vbox
        """
        self.logger.info({'_action': whoami(),
                          'message': "Extracting 'hpak' file using Volatility 'hpakextract'."
                          })
        _dump_path = Path(dump_path)
        output_folder = _dump_path.parent
        output_file = Path.joinpath(output_folder, "%s.%s" % (_dump_path.stem, AUTO_EXTRACT_SUFFIX))

        if output_file.exists():
            self.logger.warning({'_action': whoami(),
                                 'message': "%s output file exists. Skipping hpak extraction." % output_file.name
                                 })
            return output_file

        command = '{0} -f "{1}" hpakextract --output-file "{2}"'.format(VOLATILITY_PATH.as_posix(),
                                                                        _dump_path.as_posix(),
                                                                        output_file.as_posix())
        args = shlex.split(command)
        try:
            proc = run_command(args, timeout=volatility_default_timeout)
        except Exception:
            raise
        else:
            if output_file.exists():
                self.logger.info({'_action': whoami(),
                                  'message': "HPAK extraction successful.  "
                                             "Continuing processing using '{}' image.".format(output_file.name)
                                  })
                return output_file
            else:
                raise IOError("Failed to extract HPAK file %s" % _dump_path.as_posix())
