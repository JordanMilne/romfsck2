#!/usr/bin/env python
from __future__ import print_function
__author__ = 'Jordan Milne <romfsck2@saynotolinux.com>'

## romfsck2
## Copyright 2013 Jordan Milne
## Licensed under GNU GPLv2

## Reimplementation of Armijn Hemel's bat-romfsck made a bit more verbose
## about which errors it encounters, does checksums, and properly handles the
## foscam images I've seen around. It should use less memory for larger images as well.

## Resources:
## https://www.kernel.org/doc/Documentation/filesystems/romfs.txt
## fs/romfs/super.c in the kernel source tree

import os, sys, shutil, traceback, posixpath
import struct
from collections import defaultdict
from optparse import OptionParser

## Whether or not we're using python 3
PY3 = sys.version_info[0] == 3

## how many bytes to use to compute the superblock checksum
MAX_SB_CHECKSUM_BYTES = 512

MAGIC_BYTES = b"-rom1fs-"

## types of entries that can be found in a RomFS filesystem
FS_HARD_LINK = 0
FS_DIRECTORY = 1
FS_FILE = 2
FS_SYMLINK = 3
FS_BLOCK_DEV = 4
FS_CHAR_DEV = 5
FS_SOCKET = 6
FS_FIFO = 7

STR_FS_TYPES = [
    "Hard Link",
    "Directory",
    "File",
    "Symlink",
    "Block Device",
    "Character Device",
    "Socket",
    "FIFO"
]

## types of errors that can occur while reading the image
ERR_SYMLINK = "Symlink"
ERR_CHECKSUM = "Checksum"
ERR_HARDLINK = "Hard Link"
ERR_MAGIC = "Magic Bytes"
ERR_SIZE = "Size"
ERR_STRING = "String"
ERR_HEADER = "Header"
ERR_RECURSION = "Recursion"

## World readable / writable
PERM_MASK = 0o666
## World executable
EXEC_PERM_MASK = 0o111

## error types that will cause a halt to parsing
fatal_errors = {ERR_MAGIC, ERR_SIZE, ERR_HEADER}

class RomFSFileHdr(object):
    """A lightweight collection of header data to allow us to backtrack for hardlinks and such."""
    def __init__(self, addr):
        ## address of this inode
        self.addr = addr
        ## address of the next header
        self.next_hdr = -1
        ## whether this file has the x bit set
        self.executable = False
        ## type of entry (see FS_ constants)
        self.type = -1
        ## size of the file in bytes
        self.file_size = -1
        ## non-null-padded filename
        self.name = None
        ## address where the file contents begin
        self.file_start = -1
        ## RomFSFileHdr of the parent directory (none for top-level entries)
        self.parent = None
        ## Our depth in the filesystem's directory tree
        self.depth = 0
        ## Type-specific data
        self.spec_info = -1
        ## Whether or not we actually handled this entry
        self.handled = False

    def get_fs_path(self):
        """get the path relative to the beginning of the FS"""
        if self.parent is not None:
            return os.path.join(self.parent.get_fs_path(), self.name)
        return self.name


class RomFSSuperBlock(object):
    """Collection of information about the fs necessary to pass along during validation"""
    def __init__(self):
        ## The filesystem's entire size in bytes
        self.size = -1
        ## The address for the end of the superblock
        self.first_inode_addr = -1

    def is_valid_addr(self, addr):
        """Determine whether or not an inode address is valid"""

        ## inodes are always on 16 byte boundaries
        if addr % 16:
            return False
        if addr >= self.size:
            return False
        if addr < self.first_inode_addr:
            return False

        return True


class ParsingContext(object):
    def __init__(self):
        ## RomFS Superblock
        self.superblock = None
        ## File handle for the image
        self.fh = None
        ## Root directory of where to unpack files
        self.unpack_dir = None

        ## hardlinks to files we haven't unpacked yet
        ## dest addr -> (link addr, link addr...)
        self.pending_hardlinks = defaultdict(set)
        ## address -> RomFSFileHdr
        self.inodes = {}
        ## Whether or not we're currently unpacking files
        self.unpacking = False
        self.parsing = False

        ## Encoding for strings embedded in the FS
        self.str_encoding = "utf-8"

        self._errors = []

    def is_dest_recursive(self, addr, parent_inode):
        """Warn if we're being pointed to an inode that we've already visited"""

        ## Recursive dir structures aren't *prohibited* by the spec, but warn on them anyways
        ## since they're unlikely to be intentional and are impossible to fully unpack

        ## We've already seen this inode. The only (somewhat) reasonable use-case I can think of
        ## for this is directories with the same file entries, but that's best served by links
        if addr in self.inodes:
            msg = "Possibly recursive directory structure, 0x%x points to already visited 0x%x" % \
                  (parent_inode.addr, addr)
            self.gen_error(ERR_RECURSION, msg)
            return True

        return False

    def decode(self, byte_str):
        """Decode a byte string from the file to a native string using the file's locale"""
        return byte_str.decode(self.str_encoding)

    def gen_error(self, err_type, message, fatal=False):
        """Report an error, raising an exception if the type of error is fatal"""
        msg = "[%(type)s] %(message)s" % {'type': err_type, 'message': message}

        if fatal or err_type in fatal_errors:
            raise RomFSException(msg)
        ## If we're parsing, save non-fatal errors 'til we want to print them
        elif self.parsing:
            self._errors += [msg]
        else:
            print(msg, file=sys.stderr)

    def print_errors(self):
        for err in self._errors:
            print(err, file=sys.stderr)
        self._errors = []

class RomFSException(Exception):
    """Raised for fatal errors during parsing"""
    pass


def fsencode(str):
    """Wrapper for argv->bytes conversion"""
    if PY3:
        return str.encode(sys.getfilesystemencoding())
    return bytes(str)


## The RomFS checksum works as follows: the checksum of a range of bytes is calculated with its
## checksum field set to 0, then -result is stored in the checksum field. That way, correct
## subsequent checks will result in 0. It doesn't account for bytes out of order, but it catches
## most obvious things.
def verify_checksum(romfs_bytes):
    """Verify the checksum for a series of bytes, returns 0 on success"""
    total = 0
    int32 = 2 ** 32

    ## make sure we don't use a python long and we maintain 32bit int wrapping behaviour
    for i in range(0, len(romfs_bytes), 4):
        total = (total + struct.unpack('>L', romfs_bytes[i:i + 4])[0]) % int32

    return total


def ceil16(num):
    """Round up to the nearest multiple of 16"""
    return (num + 15) // 16 * 16


def get_romfs_perms(executable):
    """Get effective permissions for a file entry"""
    if executable:
        return PERM_MASK | EXEC_PERM_MASK
    return PERM_MASK


## TODO: This needs a better name...
def get_min_path_depth(romfs_path):
    """ Figure out the greatest negative change in depth a directory path would give
    for use with symlink targets. Useful for checking if a symlink target escapes
    the filesystem.
    ex: ../../foo = -2, foo = 0, foo/bar/baz = 0, foo/bar/../../../baz = -1
    """

    ## This is for relative paths *only*
    assert(not romfs_path.startswith(b"/"))

    ## The symlinks should always be unix paths
    romfs_path = posixpath.normpath(romfs_path)
    cur_depth = 0
    min_depth = 0

    components = []

    while True:
        ## get the directory on the end of the path
        romfs_path, subdir = posixpath.split(romfs_path)

        components += [subdir]
        if not romfs_path:
            break

    components.reverse()
    for subdir in components:
        if subdir == b"..":
            cur_depth -= 1
        elif subdir != b".":
            cur_depth += 1

        if cur_depth < min_depth:
            min_depth = cur_depth

    return min_depth


## Make sure all file names are within a reasonable range and are properly null-padded to
## 16 byte boundaries. All strings in a RomFS filesystem are padded to 16-byte boundaries
## and have no limit on size. We impose an arbitrary limit of 256 bytes for ease of validation.
def extract_romfs_string(fh, ctx):
    """ :param fh: file handle pointed to the start of the string
    :summary Extract a null-terminated string padded to 16-byte boundaries
    :return padded length of the text field, the text as a string
    """

    addr = fh.tell()

    ## if a file name is longer than 256 bytes, something's gone seriously wrong.
    search_bytes = fh.read(256)
    null_pos = search_bytes.find(b'\x00')

    ## no null terminator found, bail out
    if null_pos == -1:
        ctx.gen_error(ERR_STRING, "String invalid or missing null terminator at 0x%x" % addr, True)

    ## the full length of the string field
    padded_len = ceil16(null_pos)

    ## if the first null isn't on the boundary make sure all the bytes after the first
    ## null are also nulls
    if (null_pos + 1) % 16:
        if set(search_bytes[null_pos:padded_len]) != set(b'\x00'):
            ctx.gen_error(ERR_STRING, "Malformed null padding at 0x%x" % addr)

    ## Return the padded length and a usable string
    return padded_len, bytes(search_bytes[0:null_pos+1].rstrip(b'\x00'))


def read_romfs_image(romfs_file, ctx):
    """Parse a romfs filesystem from the specified file, extracting files if requested"""
    ## check the size of the file. The minimum size of a romfs filesystem
    ## is 32 bytes
    if os.stat(romfs_file).st_size < 32:
        ctx.gen_error(ERR_SIZE, "RomFS image smaller than 32 bytes")

    romfs_sb = RomFSSuperBlock()

    ctx.fh = open(romfs_file, "rb")
    ctx.fh.seek(0)

    ## read in the superblock and enough bytes to calculate the checksum
    romfs_bytes = ctx.fh.read(MAX_SB_CHECKSUM_BYTES)

    ## Verify that the file starts with the correct magic bytes
    magic_field = romfs_bytes[0:len(MAGIC_BYTES)]
    if magic_field != MAGIC_BYTES:
        msg = "Incorrect magic bytes, expected '%s', got '%s'" % (MAGIC_BYTES.decode("utf8"), magic_field.decode("utf8"))
        ctx.gen_error(ERR_MAGIC, msg)

    ## make sure the size field's value isn't greater than the file size
    romfs_sb.size = struct.unpack('>L', romfs_bytes[8:12])[0]
    if romfs_sb.size > os.stat(romfs_file).st_size:
        ctx.gen_error(ERR_SIZE, "Size field greater than image file size at 0x%x" % 4, True)

    ## check for checksum mismatches
    if verify_checksum(romfs_bytes) != 0:
        ctx.gen_error(ERR_CHECKSUM, "Checksum mismatch on superblock at 0x%x" % 12)

    ## check that the Volume label is valid
    ctx.fh.seek(16)
    vol_len, vol_label = extract_romfs_string(ctx.fh, ctx)

    print("Volume Label:", ctx.decode(vol_label))

    ## the first inode is right after the volume label
    first_addr = 16 + vol_len
    romfs_sb.first_inode_addr = first_addr

    ctx.superblock = romfs_sb

    ctx.print_errors()

    ## if there are any inodes in the FS, start reading them.
    if romfs_sb.is_valid_addr(first_addr):
        recurse_romfs_dir_inodes(first_addr, None, ctx)


def recurse_romfs_dir_inodes(addr, parent_inode, ctx):
    """Read all of the inodes for the current directory"""
    while addr:
        addr = read_romfs_inode(addr, parent_inode, ctx)


def read_romfs_inode(addr, parent_inode, ctx):
    """Read and handle an inode, returning the next address in the dir"""
    need_nl = True
    try:
        print("0x%x: " % addr, end="")

        ## Put this inode's info in the global inode dict, used for hardlink lookups
        inode = RomFSFileHdr(addr)
        ctx.inodes[addr] = inode

        inode.parent = parent_inode

        ## Keep track of our depth in the directory tree
        if inode.parent is not None:
            inode.depth = inode.parent.depth + 1

        ## Slurp in everything but the filename
        ctx.fh.seek(addr)
        inode_hdr = ctx.fh.read(16)

        ## One 32-bit uint is used for the type (3 bits) execute bit (1 bit) and the
        ## next header (upper 28 bits). Since everything in RomFS is on a 16 byte boundary,
        ## the lower 4 bits are never used for the address of the next header, so they store the
        ## type of entry and the execute bit. No other permission bits are stored.
        rwxplusheader = struct.unpack('>L', inode_hdr[0:4])[0]
        next_header = rwxplusheader & ~0b1111
        inode.type = rwxplusheader & 0b0111
        inode.executable = bool(rwxplusheader & 0b1000)

        ## The spec_info field's meaning is dependant on the type of inode this is. Refer to
        ## the romfs documentation for more info.
        inode.spec_info = struct.unpack('>L', inode_hdr[4:8])[0]
        inode.file_size = struct.unpack('>L', inode_hdr[8:12])[0]

        ## we don't need to read this specifically.
        #checksum = struct.unpack('>L', inode_hdr[12:16])[0]

        ## extract the name for the inode (file / directory name)
        ctx.fh.seek(addr + 16)
        name_len, inode.name = extract_romfs_string(ctx.fh, ctx)

        ## store the address of the start of the data section
        header_size = 16 + name_len
        inode.file_start = addr + header_size

        ## Now that we have the filename, print the rest of the info about the inode
        str_type = STR_FS_TYPES[inode.type]
        print("'" + ctx.decode(inode.get_fs_path()) + "'", "[", str_type, "]")
        need_nl = False

        ## spec_info must be zero for these inode types
        if inode.type in {FS_FIFO, FS_FILE, FS_SOCKET, FS_SYMLINK}:
            if inode.spec_info:
                ctx.gen_error(ERR_HEADER, "spec_info must be 0 for type %s at 0x%x" % (str_type, addr))

        ## The execute bit must not be set for these inode types
        if inode.type in {FS_CHAR_DEV, FS_FIFO}:
            if inode.executable:
                ctx.gen_error(ERR_HEADER, "Exec bit must be 0 for type %s at 0x%x" % (str_type, addr))

        ## Anything other than these types should not have a file size
        if inode.type not in {FS_FILE, FS_SYMLINK}:
            if inode.file_size:
                ctx.gen_error(ERR_HEADER, "File size must be 0 for type %s at 0x%x" % (str_type, addr))
        elif inode.file_start + inode.file_size > ctx.superblock.size:
            ctx.gen_error(ERR_SIZE, "File goes past end of fs at 0x%x" % addr)

        ## run the checksum of this inode (the linux driver doesn't actually run this check, but
        ## the spec mandates it.)
        ctx.fh.seek(addr)
        if verify_checksum(ctx.fh.read(header_size)):
            ctx.gen_error(ERR_CHECKSUM, "Checksum mismatch at 0x%x" % addr)
        ## Ignore . and .. entries, we don't need to create them and they often have incorrect /
        ## self-referential spec_info fields even in files generated by genromfs :/
        if inode.name not in {b".", b".."}:
            if inode.type == FS_HARD_LINK:
                handle_romfs_hard_link(inode, ctx)
            elif inode.type == FS_FILE:
                handle_romfs_file(inode, ctx)
            elif inode.type == FS_DIRECTORY:
                handle_romfs_directory(inode, ctx)
            elif inode.type == FS_SYMLINK:
                handle_romfs_symlink(inode, ctx)

        ## Check if we have any pending hard links to what we just unpacked
        if inode.addr in ctx.pending_hardlinks:
            ## Create the hard links and remove the entries in the pending list
            for hl_addr in ctx.pending_hardlinks[inode.addr]:
                deferred_romfs_hardlink(ctx.inodes[hl_addr], inode, ctx)

            del ctx.pending_hardlinks[inode.addr]

        ## Print any errors we've saved up until now
        ctx.print_errors()

        if next_header != 0:
            if ctx.superblock.is_valid_addr(next_header):
                ## Check that this entry doesn't also belong to another directory
                if ctx.is_dest_recursive(next_header, inode):
                    next_header = 0
                ctx.print_errors()
            else:
                ctx.gen_error(ERR_HEADER, "Invalid next header address: 0x%x at 0x%x" % (next_header, addr))
                next_header = 0

        return next_header

    except Exception:
        ## make sure we print a newline if we haven't yet
        if need_nl:
            print("")
        raise


def handle_romfs_hard_link(inode, ctx):
    """Create the hard link if the destination inode's been unpacked, otherwise defer 'til it is"""
    ## Self-referential hard-links, eh? Well that's impossible!
    if inode.spec_info == inode.addr:
        ctx.gen_error(ERR_HARDLINK, "Self-referential hard link at 0x%x" % inode.addr)
    elif not ctx.superblock.is_valid_addr(inode.spec_info):
        ctx.gen_error(ERR_HARDLINK, "Invalid hard link destination at 0x%x" % inode.addr)
    else:
        ## Ok, this is likely a valid hard link, create it if the destination's been unpacked
        if inode.spec_info in ctx.inodes:
            deferred_romfs_hardlink(inode, ctx.inodes[inode.spec_info], ctx)
        else:
            ## Keep this around until the destination inode's unpacked
            ctx.pending_hardlinks[inode.spec_info].add(inode.addr)


def deferred_romfs_hardlink(hl_inode, dest_inode, ctx):
    """Handle a hard link found during parsing, creating if necessary"""
    if dest_inode.type == FS_HARD_LINK:
        ctx.gen_error(ERR_HARDLINK, "Hard links to hard links not allowed at 0x%x" % hl_inode.addr)
    else:
        ## The inode we're being pointed to had errors during handling and is invalid
        if not dest_inode.handled:
            ctx.gen_error(ERR_HARDLINK, "Destination inode was invalid at 0x%x" % hl_inode.addr)
        else:
            if ctx.unpacking:
                ## Create the actual hard link
                src_path = os.path.join(ctx.unpack_dir, hl_inode.get_fs_path())
                dest_path = os.path.join(ctx.unpack_dir, dest_inode.get_fs_path())
                os.link(src_path, dest_path)
            hl_inode.handled = True


def handle_romfs_file(inode, ctx):
    """Handle a file found during parsing, creating if necessary"""
    BLOCK_SIZE = 8192
    if ctx.unpacking:
        ## Prepare the file for copying to disk
        ctx.fh.seek(inode.file_start)
        file_path = os.path.join(ctx.unpack_dir, inode.get_fs_path())
        file_fh = open(file_path, 'wb')

        bytes_left = inode.file_size
        ## Copy the file a block at a time
        while bytes_left > 0:
            to_read = min(bytes_left, BLOCK_SIZE)
            file_fh.write(ctx.fh.read(to_read))

            bytes_left -= to_read

        ## Add the correct permissions
        os.chmod(file_path, get_romfs_perms(inode.executable))
        file_fh.close()

    inode.handled = True


def handle_romfs_directory(inode, ctx):
    """Handle a directory found during parsing, creating if necessary"""

    ## Create the directory if we're unpacking to disk
    if ctx.unpacking:
        file_path = os.path.join(ctx.unpack_dir, inode.get_fs_path())
        os.mkdir(file_path, get_romfs_perms(inode.executable))

    inode.handled = True

    ## spec_info represents the first entry in the directory (if one exists)
    if inode.spec_info:
        ## We have a valid first directory entry, start parsing the contents.
        if ctx.superblock.is_valid_addr(inode.spec_info):
            if not ctx.is_dest_recursive(inode.spec_info, inode):
                recurse_romfs_dir_inodes(inode.spec_info, inode, ctx)
        else:
            ctx.gen_error(ERR_HEADER, "Invalid spec_info for dir at 0x%x" % inode.addr)


def handle_romfs_symlink(inode, ctx):
    """Handle a symlink found during parsing, creating if necessary"""
    ## Read the symlink and check if it would escape the filesystem
    ctx.fh.seek(inode.file_start)
    dest = ctx.fh.read(inode.file_size)
    dest_str = ctx.decode(dest)

    ## Check if this is an absolute path or a relative path that would leave the filesystem
    if dest.startswith(b"/") or inode.depth + get_min_path_depth(dest) < 0:
        ctx.gen_error(ERR_SYMLINK, "Warning: Symlink (%s) escapes filesystem at 0x%x" % (dest_str, inode.addr))

    ## Create the symlink if we're unpacking to disk
    if ctx.unpacking:
        sym_path = os.path.join(ctx.unpack_dir, inode.get_fs_path())

        ## Symlinks are always relative to their directory, so don't join the path.
        dest = os.path.normpath(dest)
        os.symlink(dest, sym_path)

    inode.handled = True


def del_subtree(path):
    """Remove all files and subdirs in a directory without removing the directory"""
    for root, dirs, files in os.walk(path, topdown=False):
        for f in files:
            try:
                os.unlink(os.path.join(root, f))
            except:
                print("can't remove file %s" % f, file=sys.stderr)
        for d in dirs:
            try:
                dir_path = os.path.join(root, d)
                ## Don't delete a directory's contents if it's actually a symlink!
                ## http://bugs.python.org/issue4489
                if os.path.islink(dir_path):
                    os.unlink(dir_path)
                else:
                    shutil.rmtree(dir_path)
            except:
                print("can't remove dir %s" % d, file=sys.stderr)


def main(argv):
    if sys.version_info[0] < 2 or (sys.version_info[0] == 2 and sys.version_info[1] < 6):
        print("This script requires Python version 2.6 or higher.")
        sys.exit(1)

    ctx = ParsingContext()

    romfs_file = None

    parser = OptionParser(usage="%prog [OPTIONS...] romfs_file")
    parser.add_option("-x", action="store", dest="unpack_dir",
                      help="unpack the filesystem to this directory", metavar="dest_directory")
    parser.add_option("-p", "--paranoid", action="store_true", dest="paranoid",
                      help="die on checksum and recursion errors", default=False)
    parser.add_option("--no-cleanup", action="store_true", dest="no_cleanup",
                      help="don't clean up the directory if extraction fails", default=False)
    (options, args) = parser.parse_args()

    if len(args) == 1:
        romfs_file = args[0]
    ctx.unpack_dir = options.unpack_dir

    if options.paranoid:
        fatal_errors.add(ERR_RECURSION)
        fatal_errors.add(ERR_CHECKSUM)

    ## Check that the rom file's fine
    if romfs_file is None:
        parser.print_help()
        parser.exit(2, "\nError: Path to romfs file needed\n")
    elif not os.path.exists(romfs_file):
        parser.error("romfs file does not exist")

    ## Check that the extraction directory's fine
    if ctx.unpack_dir is None:
        ctx.unpacking = False
    else:
        if not os.path.exists(ctx.unpack_dir):
            parser.error("unpack directory does not exist")
        elif os.listdir(ctx.unpack_dir):
            parser.error("unpack directory %s not empty" % ctx.unpack_dir)
        ## Everything's good, enable unpacking
        else:
            ctx.unpack_dir = fsencode(ctx.unpack_dir)
            ctx.unpacking = True

    ## Start parsing the romfs image
    try:
        ctx.parsing = True
        read_romfs_image(romfs_file, ctx)
        ctx.parsing = False

        ## Print any errors we have left in the buffer
        ctx.print_errors()
        ## We have hard links left that weren't matched to inodes, print an error
        if ctx.pending_hardlinks:
            dangling_links = ""
            ## Build a list of the dangling links
            for dest, links in ctx.pending_hardlinks.iteritems():
                str_links = "( " + ', '.join(["0x%x" % x for x in links]) + " )"
                dangling_links += "0x%x linked by %s\n" % (dest, str_links)

            ctx.gen_error(ERR_HARDLINK, "Dangling hardlinks at end of parsing %s" % dangling_links)

    except Exception as e:
        ## Print any errors we have in the context buffer
        ctx.print_errors()

        if type(e) == RomFSException:
            print("Fatal exception: %s" % e, file=sys.stderr)
        else:
            traceback.print_exc(file=sys.stderr)

        try:
            ctx.fh.close()
        except:
            pass

        ## Remove what we have so far if we were unpacking
        if ctx.unpacking and not options.no_cleanup:
            del_subtree(ctx.unpack_dir)

        sys.exit(1)

    print("\nParsing completed!")

if __name__ == "__main__":
    main(sys.argv)
