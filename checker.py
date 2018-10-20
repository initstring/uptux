#!/usr/bin/env python3

"""
systemd-privesc by initstring (gitlab.com/initstring)

This tool checks for basic settings with systemd-implemented services,
tasks, etc that may accidentally lead to privilege escalation.

"""

import os
import sys
import datetime


BANNER = r'''

__________                             ____ ___       ._.
\______   \______  _  __ ___________  |    |   \______| |
 |     ___/  _ \ \/ \/ // __ \_  __ \ |    |   /\____ \ |
 |    |  (  <_> )     /\  ___/|  | \/ |    |  / |  |_> >|
 |____|   \____/ \/\_/  \___  >__|    |______/  |   __/__
                            \/                  |__|   \/

                  systemd-privesc checker
                   gitlab.com/initstring
'''


if sys.version_info < (3, 0):
    print("\nSorry mate, you'll need to use Python 3+ on this one...\n")
    sys.exit(1)


class PC:
    """PC (Print Color)
    Used to generate some colorful, relevant, nicely formatted status messages.
    """
    green = '\033[92m'
    blue = '\033[94m'
    orange = '\033[93m'
    red = '\033[91m'
    endc = '\033[0m'
    ok_box = blue + '[*] ' + endc
    note_box = green + '[+] ' + endc
    warn_box = orange + '[!] ' + endc
    vuln_box = red + '[VULNERABLE]     ' + endc
    sus_box = orange + '[INVESTIGATE]    ' + endc


def parse_arguments():
    """Handle user-supplied arguments"""
    return False


def init_log():
    """Creates a new log file"""
    timestamp = '{:%Y-%m-%d-%H:%M:%S}'.format(datetime.datetime.now())
    logfile = 'privsec-output-{}'.format(timestamp)
    with open (logfile, 'w') as f:
        f.write('#### Output ###\n\n')
    return logfile


def main():
    """Main function"""
    print(BANNER)
    args = parse_arguments()
    logfile = init_log()


if __name__ == "__main__":
    main()
