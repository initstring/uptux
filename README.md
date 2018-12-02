# uptux
Privilege escalation checks for Linux systemd.

This tool checks for issues on Linux systems that may lead to
privilege escalation. The core focus in on systemd configuration.

uptux officially lives on [GitLab](https://gitlab.com/initstring/uptux) and is mirrored to GitHub. Please open issues on GitLab.

This tool is under active development and is still at a very early stage. So
far it does the following:
- Basic sudo checks (nothing new and exciting here)
- Checks for systemd paths that may be writeable (fat chance)
- Checks for writable service, timer, and socket units (blah)
- Disassembles these unit files and looks inside them for (EXCITING):
    - References to executables that are writable
    - References to broken symlinks pointing to writeable directories
    - Relative path statements

This disassembly and analysis of unit files is what makes this tool unique.
For general purpose privesc, the classic tools are far superior.

Future improvements may include things like:
- Socket configuration issues
- .conf file analysis

# Usage
All functionality is contained in a single file, because installing packages
in restricted shells is a pain. Written for Python2, as unfortunately we get
stuck on on crap boxes without modern versions.

There is nothing to install, just grab the script and run it.

```
usage: uptux.py [-h] [-n] [-d]

PrivEsc for modern Linux systemd, by initstring (gitlab.com/initstring)

optional arguments:
  -h, --help       show this help message and exit
  -n, --nologging  do not write the output to a logfile
  -d, --debug      print some extra debugging info to the console
```

# Testing
For testing purposes, you can run the `tests/r00tme.sh` script, which will
create many vulnerable configuration issues on your system that uptux can
identify. Running `tests/unr00tme.sh` will undo these changes, but don't hold
me to it. Needless to say, this is dangerous.

Use a VM for testing this way.
