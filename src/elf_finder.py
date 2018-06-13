import logging
import os
from stopit import SignalTimeout as Timeout
from stopit import TimeoutException

"""
Utilities to find all ELFs files in one given directory (default root)
A file is considered ELF if it has the 7f454c46 magic number at the beginning.
"""

def is_elf(path):
    """

    :param path: the path to the file to analyze
    :return: True if the file is ELF, false otherwise
    """
    try:
        with Timeout(1.0) as timeout_ctx:
            try:
                bytes = open(path,"rb").read(4).encode('hex')
                if bytes == "7f454c46":
                    return True
                else:
                    return False
            except TimeoutException:
                logging.warning("Could not open the file"+path+" in 1s. Skipping.")
    except:
        logging.error("Couldn't determine if "+path+" is ELF.")

    return False

def get_elf_list(root_dir="/"):
    """
    :return: A list with full paths of every ELF file in the system
    """
    elf_files=[]
    for root,dir, files in os.walk(root_dir):
        for file in files:
            try:
                if os.path.islink(root+"/"+file):
                    continue
                else:
                    if is_elf(root+"/"+file):
                        elf_files.append(root+"/"+file)
            except:
                continue
    print "[+] A total of "+str(len(elf_files))+" binaries have been found and will be analyzed."
    return elf_files




