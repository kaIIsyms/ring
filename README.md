ring is a ring 0 (kernel mode) rootkit for the linux kernel from version 2 to 5+

<img src="https://upload.wikimedia.org/wikipedia/commons/d/d4/One_Ring_Blender_Render.png" height="200">

features
- [x] give a user root privileges
- [x] hide itself
- [x] hide/unhide files and directories
- [x] hide files in /dev/, /proc/devices, and /sys/class
- [x] hide/unhide processes
- [x] hide/unhide network connections
- [x] hidden persistence
- [x] backconnect
- [x] sniff ssh passwords
- [x] vm detection
- [ ] dishwashing
- [ ] make a monkey speak english

facts

- this rootkit modify the CR0 register to remove the write protection bit to edit the sys_call_table and then apply the write protection to the kernel mem.
- this rootkit can remove itself from the responsible linked list.
- this rootkit can bypass some anti-rootkits like chkrootkit, rkhunter.
- this rootkit can give remote root shellz.
- this rootkit can hide tcp/udp connections for netstat.
- this rootkit can detect if the machine is a vm

Copyright (C) <a href="LICENSE">gbr</a> 2023