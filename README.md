# uptux
Privilege escalation for modern Linux systems.

This tool checks for configuration issues on Linux systems that may lead to
privilege escalation. The core focus in on systemd, which seems to be left
alone by other similar tools.



# Usage
All functionality is contained in a single file, because installing packages
in restricted shells is a pain.

There is nothing to install, just grab the script and run it.

```
usage: uptux.py [-h] [-n]

PrivEsc for modern Linux systems, by initstring (gitlab.com/initstring)

optional arguments:
  -h, --help       show this help message and exit
  -n, --nologging  Disable logging functionality
```


