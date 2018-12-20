import logging
from Elf import *
from stopit import SignalTimeout as Timeout
from stopit.utils import TimeoutException

"""
Utilities to find all ELFs files in one given directory (default root)
A file is considered ELF if it has the 7f454c46 magic number at the beginning.
"""


def is_elf(path):
    """
    Verify whether the file specified by path is an Elf
    :param path: the path to the file to analyze
    :return: True if the file is ELF, false otherwise
    """
    with Timeout(1.0):
        try:
            file_bytes = open(path, "rb").read(4).encode('hex')
            if file_bytes == "7f454c46":
                return True
            else:
                return False
        except TimeoutException:
            logging.warning("Could not open the file"+path+" in 1s. Skipping.")
        except IOError:
            logging.error("Couldn't determine if "+path+" is ELF.")
    return False


def get_elf_list(root_dir="/"):
    """
    Produce
    :return: A list with full paths of every ELF file in the system
    """
    elf_files = []
    for root, dir, files in os.walk(root_dir):
        for f in files:
            try:
                if os.path.islink(root+"/"+f):
                    continue
                else:
                    if is_elf(root+"/"+f):
                        elf_object = Elf("%s/%s" % (root, f))
                        elf_files.append(elf_object)
            except:
                continue
    print "[+] A total of "+str(len(elf_files))+" binaries have been found and will be analyzed."
    return elf_files




