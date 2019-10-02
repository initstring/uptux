# uptux
Specialized privilege escalation checks for Linux systems.

Implemented so far:
- Writable systemd paths, services, timers, and socket units
- Disassembles systemd unit files looking for:
    - References to executables that are writable
    - References to broken symlinks pointing to writeable directories
    - Relative path statements
    - Unix socket files that are writeable (sneaky APIs)
- Writable D-Bus paths
- Overly permissive D-Bus service settings
- HTTP APIs running as root and responding on file-bound unix domain sockets

These checks are based on things I encounter during my own research, and this
tool is certainly not inclusive of everything you should be looking at. Don't
skip the classics!

# Usage
All functionality is contained in a single file, because installing packages
in restricted shells is a pain. Python2 compatibility will be maintained for
those crap old boxes we get stuck with. However, as the checks are really
aimed at more modern user-space stuff, it is unlikely to uncover anything
interesting on an old box anyway.

There is nothing to install, just grab the script and run it.

```
usage: uptux.py [-h] [-n] [-d]

PrivEsc for modern Linux systems, by initstring (github.com/initstring)

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
