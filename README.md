romfsck2
========

I needed to extract a RomFS image from a FOSCAM firmware upgrade, but bat-romfsck choked on it and romfsck.c was... a little lacking.

romfsck2.py handles all romfs images I could find and includes checksum validation, checks for self-referencing inodes and checks for symlinks that escape the filesystem, with an optional mode that verifies the image without extracting.

It supports both Python 2.6+ and Python 3.

Licensed under the GPLv2 as I looked at both bat-romfsck.py and romfsck.c while writing it.

Usage
=====

    romfsck2.py [OPTIONS...] romfs_file

    Options:
      -h, --help         show this help message and exit
      -x dest_directory  unpack the filesystem to this directory
      -p, --paranoid     die on checksum and recursion errors
      --no-cleanup       don't clean up the directory if extraction fails

Also included
=============
A binary template for 010 Editor (ROMFS.bt,) released into the public domain since it's only based on romfs.txt from the kernel documentation.

A set of test images that demonstrate invalid recursive structures and symlinks that would escape the filesystem