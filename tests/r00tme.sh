#!/bin/bash

## This script creates configuration issues in systemd that lead to privilege
## escalation. If someone asked you to run this without telling you that,
## they are a jerk.
##
## Use with caution.
##
## https://gitab.com/initstring/uptux

if [ "$EUID" -ne 0 ]
  then echo "[!] Please run as root"
  exit
fi

echo "[!] This is going to make your box vulnerable to privesc. Are you sure?"
read -p "Type YES to continue: "
if [ "$REPLY" != "YES" ]; then
    echo "[+] Smart choice."
    exit
fi

echo ""

echo "Deleting any leftover test vuln unit files..."
for FILE in \
    /lib/systemd/system/uptux-vuln* \
    /usr/bin/uptux-vuln* \
    /tmp/uptux-vuln*
do rm -rf $FILE
done
echo ""

                    ########## systemd PATH Tests ##########
echo "[*] Adding some dodgy path settings..."
# Set env variables for a new vulnerable path and the current systemd path
VULNPATH=/tmp/uptux-vuln-path
CURRENTPATH=`systemctl show-environment | grep PATH | sed -E 's/PATH=(.*?)$/\1/'`

# Make the vulnerable dir and set it to world writeable
mkdir $VULNPATH
chmod 777 $VULNPATH

# Set the path (unset with `systemctl import-environment PATH`)
systemctl set-environment PATH=$VULNPATH:$CURRENTPATH


                    ########## Service Unit Tests ##########
echo "[*] Setting up some shady service units..."

# Service est case 1: writable service unit file
UNIT=/lib/systemd/system/uptux-vuln-service1.service
cat << EOF > $UNIT
There's nothing really here, just a writeable service unit.
EOF
chmod 666 $UNIT

# Service test case 2: service unit file that is a broken symlink to a writable
# parent directory
UNIT=/lib/systemd/system/uptux-vuln-service2.service
TARGET=/tmp/uptux-vuln-missing-service
touch $TARGET
ln -s $TARGET $UNIT
rm -f $TARGET

# Service test case 3: service unit file that is a symlink to a writeable file
UNIT=/lib/systemd/system/uptux-vuln-service3.service
TARGET=/lib/systemd/system/uptux-vuln-service-target
touch $TARGET
ln -s $TARGET $UNIT
chmod 666 $TARGET

# Service test case 4: service unit file with Exec statements pointing to
# writable commands. Note that commands are varied to test the regex captures.
UNIT=/lib/systemd/system/uptux-vuln-service4.service
cat << EOF > $UNIT
[Unit]
Description=Vulnerable Test Unit

[Service]
ExecStart=/usr/bin/uptux-vuln-bin1
ExecReload=/bin/bash /usr/bin/uptux-vuln-bin2
ExecStop=/bin/sh "/usr/bin/uptux-vuln-bin3 -stuff -hello"

[Install]
WantedBy=multi-user.target
EOF
touch /usr/bin/uptux-vuln-bin{1..3}
chmod 766 /usr/bin/uptux-vuln-bin{1..3}

# Service test case 5: service unit file with Exec statements pointing to missing
# commands that exist in writable parent folders.
UNIT=/lib/systemd/system/uptux-vuln-service5.service
cat << EOF > $UNIT
[Unit]
Description=Vulnerable Test Unit

[Service]
ExecStart=/tmp/uptux-vuln-missing-bin1
ExecReload=/bin/bash /tmp/uptux-vuln-missing-bin2
ExecStop=/bin/sh "/tmp/uptux-vuln-missing-bin3 -stuff -hello"

[Install]
WantedBy=multi-user.target
EOF


                     ########## Timer Unit Tests ##########
echo "[*] Setting up some shady timer units..."

# Timer test case 1: writable timer unit file
UNIT=/lib/systemd/system/uptux-vuln-timer1.timer
cat << EOF > $UNIT
There's nothing really here, just a writeable service unit.
EOF
chmod 666 $UNIT

# Service test case 2: timer unit file that is a broken symlink to a writable
# parent directory
UNIT=/lib/systemd/system/uptux-vuln-timer2.timer
TARGET=/tmp/uptux-vuln-missing-timer
touch $TARGET
ln -s $TARGET $UNIT
rm -f $TARGET

# Service test case 3: timer unit file that is a symlink to a writeable file
UNIT=/lib/systemd/system/uptux-vuln-timer3.timer
TARGET=/lib/systemd/system/uptux-vuln-timer-target
touch $TARGET
ln -s $TARGET $UNIT
chmod 666 $TARGET

# Service test case 4: timer unit file with a custom action that is a writable
# file
UNIT=/lib/systemd/system/uptux-vuln-timer4.timer
cat << EOF > $UNIT
[Unit]
Description=Example vulnerable timer

[Timer]
Unit=/usr/bin/uptux-vuln-timer1

[Install]
WantedBy=multi-user.target
EOF
touch /usr/bin/uptux-vuln-timer1
chmod 766 /usr/bin/uptux-vuln-timer1

# Service test case 5: timer unit file custom action pointing to
# missing commands that exist in writable parent folders.
UNIT=/lib/systemd/system/uptux-vuln-timer5.timer
cat << EOF > $UNIT
[Unit]
Description=Example vulnerable timer

[Timer]
Unit=/tmp/uptux-vuln-mising-timer1

[Install]
WantedBy=multi-user.target
EOF

# Timer test case 6: timer unit file with a custom action that is 
# a relative path to the current directory and is also writable
UNIT=/lib/systemd/system/uptux-vuln-timer6.timer
TARGET=uptux-vuln-timer-target.target
cat << EOF > $UNIT
[Unit]
Description=Example vulnerable timer

[Timer]
Unit=$TARGET

[Install]
WantedBy=multi-user.target
EOF
touch /lib/systemd/system/$TARGET
chmod 766 /lib/systemd/system/$TARGET


                    ########## Socket Unit Tests ##########
echo "[*] Setting up some shady socket units..."

# Socket test case 1: writable socket unit file
UNIT=/lib/systemd/system/uptux-vuln-socket1.socket
cat << EOF > $UNIT
There's nothing really here, just a writeable socket unit.
EOF
chmod 666 $UNIT

# Socket test case 2: Socket unit file with Listen statements pointing
# to writable socket files.
UNIT=/lib/systemd/system/uptux-vuln-socket2.socket
TARGET=/tmp/uptux-vuln-sock1

cat << EOF > $UNIT
[Unit]
Description=Socket activation for vulnerable stuffs

[Socket]
ListenStream=$TARGET
EOF
touch $TARGET
chmod 666 $TARGET



echo ""
echo "[+] All done, thanks!"
exit 0
