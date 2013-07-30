romfsck2
========

I needed to extract a RomFS image from a FOSCAM firmware upgrade, but bat-romfsck choked on it and romfsck.c was... a little lacking.

romfsck2.py handles all romfs images I could find and includes checksum validation, checks for self-referencing inodes and checks for symlinks that escape the filesystem, with an optional mode that verifies the image without extracting.

It supports both Python 2.6+ and Python 3.

Licensed under the GPLv2 as I looked at both bat-romfsck.py and romfsck.c while writing it.


Also included
=============
A binary template for 010 Editor (ROMFS.bt,) released into the public domain as it only based on romfs.txt from the kernel documentation.

A set of test images that demonstrate invalid recursive structures and symlinks that would escape the filesystem