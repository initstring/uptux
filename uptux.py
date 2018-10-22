#!/usr/bin/env python3

"""
uptux by initstring (gitlab.com/initstring)

This tool checks for configuration issues on Linux systems that may lead to
privilege escalation. The core focus in on systemd, which seems to be left
alone by other similar tools.

All functionality is contained in a single file, because installing packages
in restricted shells is a pain.
"""


import os
import sys
import argparse
import datetime
import subprocess
import inspect


BANNER = r'''

                ____ ___      ___________           ._.
               |    |   \_____\__    ___/_ _____  __| |
               |    |   /\____ \|    | |  |  \  \/  / |
               |    |  / |  |_> >    | |  |  />    < \|
               |______/  |   __/|____| |____//__/\_ \__
                         |__|                      \/\/
               
                    PrivEsc for modern Linux systems
                        gitlab.com/initstring


'''

# This tool doesn't process a lot of arguments. Keeping argparse and logfile
# as globals for simplicity with the 'tee' function.
LOGFILE = 'log-uptux-{:%Y-%m-%d-%H.%M.%S}'.format(datetime.datetime.now())
PARSER = argparse.ArgumentParser(description=
                                 "PrivEsc for modern Linux systems,"
                                 " by initstring (gitlab.com/initstring)")
PARSER.add_argument('-n', '--nologging', action='store_true',
                    help='Disable logging functionality')
ARGS = PARSER.parse_args()


# Will not be supporting legacy Python 2.
if sys.version_info < (3, 0):
    print("\nSorry mate, you'll need to use Python 3+ on this one...\n")
    sys.exit(1)


def tee(text, **kwargs):
    """Used to log and print concurrently"""

    # Defining variables to print color-coded messages to the console.
    colors = {'green': '\033[92m',
              'blue': '\033[94m',
              'orange': '\033[93m',
              'red': '\033[91m',}
    end_color = '\033[0m'
    boxes = {'ok': colors['blue'] + '[*] ' + end_color,
             'note': colors['green'] + '[+] ' + end_color,
             'warn': colors['orange'] + '[!] ' + end_color,
             'vuln': colors['red'] + '[VULNERABLE] ',
             'sus': colors['orange'] + '[INVESTIGATE] '}

    # If this function is called with an optional 'box=xxx' parameter, these
    # will be prepended to the message.
    box = kwargs.get('box', '')
    if box:
        box = boxes[box]

    # First, just print the item to the console.
    print(box + text)

    # Then, write it to the log if logging is not disabled
    if not ARGS.nologging:
        try:
            with open(LOGFILE, 'a') as logfile:
                logfile.write(box + text + '\n')
        except PermissionError:
            ARGS.nologging = True
            print(boxes['warn'] + "Could not create a log file due to"
                  " insufficient permissions. Continuing with checks...")

def shell_exec(command):
    """Executes Linux shell commands"""
    # Split the command into a list as needed by subprocess
    command = command.split()

    # Get both stdout and stderror from command. Grab the Python exception
    # if there is one.
    try:
        out_bytes = subprocess.check_output(command,
                                            stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError as error:
        out_bytes = error.output

    # Return the lot as a text string for processing.
    out_text = out_bytes.decode('utf-8')
    out_text = out_text.rstrip()
    return out_text


def check_handler(check, check_name, check_desc):
    """Check handler

    This function takes a dictionary of check_desc,check_name and will
    iterate through them all.
    """
    tee("\n\n++++++++++  {}: {}  ++++++++++\n\n"
        .format(check_name, check_desc))
    tee("Starting module at {:%Y-%m-%d-%H.%M.%S}"
        .format(datetime.datetime.now()), box='note')
    tee("\n")
    check()
    tee("\n")
    tee("Finished module at {:%Y-%m-%d-%H.%M.%S}\n"
        .format(datetime.datetime.now()), box='note')


def get_function_order(function):
    """Helper function for build_checks_list"""
    # Grabs the line number of a function it is passed.
    order = function.__code__.co_firstlineno
    return order


def build_checks_list():
    """Dynamically build list of checks to execute

    This function will grab, in order, all functions that start with
    'uptux_check_' and populate a list. This is then used to run the checks.
    """
    # Start to build a list of functions we will execute.
    uptux_checks = []

    # Get the name of this python script and all the functions inside it.
    current_module = sys.modules[__name__]
    all_functions = inspect.getmembers(current_module, inspect.isfunction)

    # If the function name matches 'uptux_check_' we will include it.
    for function in all_functions:
        function_name = function[0]
        function_object = function[1]
        if 'uptux_check_' in function_name:
            uptux_checks.append(function_object)

    # Use the helper function to sort by line number in script.
    uptux_checks.sort(key=get_function_order)

    # Return the sorted list of functions.
    return uptux_checks


########## Individual Checks Follow ##########

# Note: naming a new function 'uptux_check_xxxx' will automatically
# include it in execution. These will trigger in the same order listed
# in the script.

def uptux_check_sysinfo():
    """Gather basic OS information"""
    # Gather a few basics for the report.
    uname = os.uname()
    tee("Host: {}".format(uname.nodename))
    tee("OS: {}, {}".format(uname.sysname, uname.version))
    tee("Kernel: {}".format(uname.release))
    tee("Current user: {} (UID {} GID {})".format(os.getlogin(),
                                                  os.getuid(),
                                                  os.getgid()))
    tee("Member of following groups:\n  {}".format(shell_exec('groups')))


def uptux_check_sudo():
    """Check for sudo rights"""
    # Check if we can read the sudoers file
    try:
        sudoers_file = open('/etc/sudoers', 'r')
        sudoers_content = sudoers_file.read()
        username = shell_exec('whoami')
        if username in sudoers_content:
            tee("Your username appears in /etc/sudoers, check it out:\n{}"
                .format(sudoers_content), box='vuln')
        else:
            tee("Interesting, you can read /etc/sudoers. Check it out:\n{}"
                .format(sudoers_content), box='sus')
    except PermissionError:
        tee("You can't open /etc/sudoers as yourself, this is expected...",
            box='ok')
    except FileNotFoundError:
        tee("Can't find /etc/sudoers, moving on...", box='ok')

    tee("")
    tee("Checking for sudo, prompting for password now...", box='ok')

    # Check what commands the user is allowed to sudo.
    tee("")
    command = 'sudo -l'
    sudo_list = shell_exec(command)
    if 'Sorry' in sudo_list:
        tee("No sudo for you, moving on...", box='ok')
    elif '(ALL : ALL) ALL' in sudo_list:
        tee("God mode enabled, sudo your heart away:\n"
            "$ {}\n"
            "{}"
            .format(command, sudo_list), box='vuln')
    else:
        tee("Interesting output:\n"
            "$ {}\n"
            "{}"
            .format(command, sudo_list), box='sus')

    # Go for gold, check if we are already root.
    tee("")
    command = 'sudo id'
    sudo_id = shell_exec(command)
    if 'uid=0(root)' in sudo_id:
        tee("Congrats, you have root:\n"
            "$ {}\n"
            "{}"
            .format(command, sudo_id), box='vuln')


def uptux_check_system_conf():
    """Check /etc/system/system.conf settings"""
    return


def uptux_check_user_conf():
    """Check /etc/system/user.conf settings"""
    return


def uptux_check_journal_conf():
    """Check /etc/system/journal.conf settings"""
    return


def uptux_check_login_conf():
    """Check /etc/system/login.conf settings"""
    return


########## Individual Checks Complete ##########

def main():
    """Main function"""
    print(BANNER)

    # Dynamically build list of checks to execute.
    uptux_checks = build_checks_list()

    # Use the handler to execute each check.
    for check in uptux_checks:
        check_name = check.__name__
        check_desc = check.__doc__
        check_handler(check, check_name, check_desc)

    # Good luck!
    tee("")
    tee("All done, good luck!", box='note')

if __name__ == "__main__":
    main()
