ring is a ring 0 (kernel mode) rootkit for the linux kernel from version 2 to 5+

<img src="https://upload.wikimedia.org/wikipedia/commons/d/d4/One_Ring_Blender_Render.png" height="200">

features
- [x] give a user root privileges
- [x] hide itself
- [x] hide/unhide files and directories
- [ ] hide files in /dev/, /proc/devices, and /sys/class
- [x] hide/unhide processes
- [ ] hide/unhide network connections
- [ ] hidden persistence
- [x] backconnect
- [ ] sniff ssh passwords
- [ ] vm detection

facts

- this rootkit can bypass some anti-rootkits like chkrootkit, rkhunter.
- this rootkit can give remote root shellz.
- this rootkit can hide ipv4 tcp connections for netstat.
- this rootkit can detect if the machine is a vm

Copyright (C) <a href="LICENSE">gbr</a> 2023
