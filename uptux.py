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
import glob
import re

BANNER = r'''



                      ____ ___      ___________            
                     |    |   \_____\__    ___/_ _____  ___
                     |    |   /\____ \|    | |  |  \  \/  /
                     |    |  / |  |_> >    | |  |  />    < 
                     |______/  |   __/|____| |____//__/\_ \
                               |__|                      \/
                     
                     
                   
                        PrivEsc for modern Linux systems
                          gitlab.com/initstring/uptux


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
             'vuln': colors['red'] + '[VULNERABLE] ' + end_color,
             'sus': colors['orange'] + '[INVESTIGATE] ' + end_color}

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


def check_handler(check, check_name, check_desc):
    """Check handler

    This function takes a dictionary of check_desc,check_name and will
    iterate through them all.
    """
    tee("\n\n++++++++++  {}: {}  ++++++++++\n\n"
        .format(check_name, check_desc))
    tee("Starting module at {:%Y-%m-%d-%H.%M.%S}"
        .format(datetime.datetime.now()), box='ok')
    tee("\n")
    check()
    tee("\n")
    tee("Finished module at {:%Y-%m-%d-%H.%M.%S}\n"
        .format(datetime.datetime.now()), box='ok')


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


########################### Helper Functions Follow ###########################

# This is the place to put functions that are used by multiple "Individual
# Checks" (those starting with uptux_check_).

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

def regex_vuln_search(**kwargs):
    """Helper function for searching text files

    This function will take a list of file paths and search through
    them with a given regex. Relevant messages will be printed to the console
    and log.

    Expected kwargs: file_paths, regex, message_text, message_box
    """
    # Start a list of dictionaries for files with interesting content.
    return_list = []

    # Open up each individual file and read the text into memory.
    for file_name in kwargs['file_paths']:
        return_dict = {}
        try:
            file_object = open(file_name, 'r')
            file_text = file_object.read()
            # Use the regex we pass in to the function to look for vulns.
            found = re.findall(kwargs['regex'], file_text)

            # Save the file name and the interesting lines of text
            if found:
                return_dict['file_name'] = file_name
                return_dict['text'] = found
                return_list.append(return_dict)

        # Handle any issues with individual files.
        except PermissionError:
            tee("Could not open {} for analysis, permission denied."
                .format(file_name), box='warn')
        except FileNotFoundError:
            tee("File not found. Broken link?\n"
                "  {} -->  {}".format(file_name, os.path.realpath(file_name)),
                box='warn')

    if return_list:
        # Print to console and log the interesting file names and content.
        tee("")
        tee(kwargs['message_text'], box=kwargs['message_box'])
        for item in return_list:
            tee("  {}:".format(item['file_name']))
            for text in item['text']:
                tee("    {}".format(text))
            tee("")


def check_permissions(**kwargs):
    """Helper function to check permissions and symlink status

    This function will take a list of file paths, resolve them to their
    actual location (for symlinks), and determine if they are writeable
    by the current user. Will also alert on broken symlinks and whether
    the target directory for the broken link is writeable.

    Expected kwargs: file_paths, files_message_text, dirs_message_text,
    message_box
    """
    # Start deuplicated sets for interesting files and directories.
    writeable_files = set()
    writeable_dirs = set()

    for file_name in kwargs['file_paths']:
        try:
            # Is it a symlink? If so, get the real path and check permissions.
            # If it is broken, check permissions on the parent directory.
            if os.path.islink(file_name):
                target = os.path.realpath(file_name)
                if os.path.exists(target):
                    if os.access(target, os.W_OK):
                        writeable_files.add(target)
                else:
                    parent_dir = os.path.dirname(target)
                    if os.access(parent_dir, os.W_OK):
                        writeable_dirs.add((file_name, parent_dir))

            # OK, not a symlink. Just check permissions.
            else:
                if os.access(file_name, os.W_OK):
                    writeable_files.add(file_name)

        # Handle any permissions issues with individual files.
        except PermissionError:
            tee("Could not open {} for analysis, permission denied."
                .format(file_name), box='warn')
        except FileNotFoundError:
            tee("File not found. Broken link?:\n"
                "  {} -->  {}".format(file_name, os.path.realpath(file_name)),
                box='warn')

    if writeable_files:
        # Print to console and log the interesting findings.
        tee("")
        tee(kwargs['files_message_text'], box=kwargs['message_box'])
        for item in writeable_files:
            tee("  {}".format(item))

    if writeable_dirs:
        # Print to console and log the interesting findings.
        tee("")
        tee(kwargs['dirs_message_text'], box=kwargs['message_box'])
        for item in writeable_dirs:
            tee("  {} --> {}".format(item[0], item[1]))

    if not writeable_files and not writeable_dirs:
        tee("")
        tee("No writeable targets. This is expected...",
            box='ok')

########################## Helper Functions Complete ##########################


########################### Individual Checks Follow ##########################

# Note: naming a new function 'uptux_check_xxxx' will automatically
# include it in execution. These will trigger in the same order listed
# in the script. The docstring will be pulled and used in the console and
# log file, so keep it short (one line).

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
        output = shell_exec('whoami')
        if output in sudoers_content:
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
    output = shell_exec(command)
    if 'Sorry' in output:
        tee("No sudo for you, moving on...", box='ok')
    elif '(ALL : ALL) ALL' in output:
        tee("God mode enabled, sudo your heart away:\n"
            "$ {}\n"
            "{}"
            .format(command, output), box='vuln')
    else:
        tee("Interesting output:\n"
            "$ {}\n"
            "{}"
            .format(command, output), box='sus')

    # Go for gold, check if we are already root.
    tee("")
    command = 'sudo id'
    output = shell_exec(command)
    if 'uid=0(root)' in output:
        tee("Congrats, you have root:\n"
            "$ {}\n"
            "{}"
            .format(command, output), box='vuln')


def uptux_check_systemd_paths():
    """Check if systemd PATH is writeable"""
    # Define the bash command.
    command = 'systemctl show-environment'
    output = shell_exec(command)

    # Define the regex to find in the output.
    regex = re.compile(r'PATH=(.*$)')

    # Take the output from bash and split it into a list of paths.
    output = re.findall(regex, output)
    output = output[0].split(':')

    # Check each path - if it is writable, add it to a list.
    writeable_paths = []
    for item in output:
        if os.access(item, os.W_OK):
            writeable_paths.append(item)

    # Write the satus to the console and log.
    if writeable_paths:
        tee("The following systemd paths are writeable. See if you can combine"
            " this with a relative path Exec statement for privesc:",
            box='vuln')
        for path in writeable_paths:
            tee("  {}".format(path))
    else:
        tee("No systemd paths are writeable. This is expected...",
            box='ok')


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


def uptux_check_services():
    """Inspect systemd service unit files"""
    # Define known Linux folders for storing service unit definitions
    service_units = set()
    service_dirs = ['/etc/systemd/system/',
                    '/lib/systemd/system/',
                    '/run/systemd/system/']
    service_pattern = '*.service'

    # Recursively gather all service unit files from the known directories
    # and add them to a deduplicated set.
    for directory in service_dirs:
        found_units = glob.glob(directory + service_pattern,
                                recursive=True)
        for unit in found_units:
            # We don't care about units that point to /dev/null.
            if '/dev/null' not in os.path.realpath(unit):
                service_units.add(unit)
    tee("Found {} service units to analyse...\n".format(len(service_units)),
        box='ok')

    # Test for write access to any service files.
    # Will resolve symlinks to their target and also check for broken links.
    text = 'Found writeable service unit files:'
    text2 = 'Found writeable directories referred to by broken symlinks'
    box = 'vuln'
    tee("")
    tee("Checking permissions on service unit files...",
        box='ok')
    check_permissions(file_paths=service_units,
                      files_message_text=text,
                      dirs_message_text=text2,
                      message_box=box)


    # Look for relative calls to binaries.
    # Example: ExecStart=somfolder/somebinary
    regex = re.compile(r'^Exec(?:Start|Stop|Reload)='
                       r'(?:@[^/]'    # special exec
                       r'|-[^/]'      # special exec
                       r'|\+[^/]'     # special exec
                       r'|![^/]'      # special exec
                       r'|!![^/]'     # special exec
                       r'|)'          # or maybe no special exec
                       r'[^/@\+!-]'   # not abs path or special exec
                       r'.*',         # rest of line
                       re.MULTILINE)
    text = 'Possible relative path in Exec statement:'
    box = 'sus'
    tee("")
    tee("Checking for relative paths in service unit files [check 1]...",
        box='ok')
    regex_vuln_search(file_paths=service_units,
                      regex=regex,
                      message_text=text,
                      message_box=box)

    # Look for relative calls to binaries but invoked by an interpreter.
    # Example: ExecStart=/bin/sh -c 'somefolder/somebinary'
    regex = re.compile(r'^Exec(?:Start|Stop|Reload)='
                       r'(?:@[^/]'    # special exec
                       r'|-[^/]'      # special exec
                       r'|\+[^/]'     # special exec
                       r'|![^/]'      # special exec
                       r'|!![^/]'     # special exec
                       r'|)'          # or maybe no special exec
                       r'.*?(?:/bin/sh|/bin/bash) '   # interpreter
                       r'(?:[\'"]|)'  # might have quotes
                       r'(?:-[a-z]+|)'# might have params
                       r'(?:[ ]+|)'   # might have more spaces now
                       r'[^/-]'       # not abs path or param
                       r'.*',         # rest of line
                       re.MULTILINE)
    text = 'Possible relative path invoked with interpreter in Exec statement:'
    box = 'sus'
    tee("")
    tee("Checking for relative paths in service unit files [check 2]...",
        box='ok')
    regex_vuln_search(file_paths=service_units,
                      regex=regex,
                      message_text=text,
                      message_box=box)

    ## Check for write access to any commands invoked by Exec statements.
    regex = re.compile

########################## Individual Checks Complete #########################

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
