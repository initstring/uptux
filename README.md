# uptux
Privilege escalation checks for Linux systemd.

This tool checks for issues on Linux systems that may lead to
privilege escalation. The core focus in on systemd configuration issues.



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
