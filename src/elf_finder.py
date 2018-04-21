import os
from stopit import SignalTimeout as Timeout
from stopit import TimeoutException

class elf_finder:

    root_dir=""

    def __init__(self,dir):
        self.root_dir=dir

    def get_elf_list(self):
        """

        :return: A list with full paths of every ELF file in the system
        """
        elf_files=[]
        for root,dir, files in os.walk(self.root_dir):
            for file in files:
                try:
                    if os.path.islink(root+"/"+file) or os.path.getsize(root+"/"+file) > 25000000:
                        continue
                    else:
                        if self.is_elf(root+"/"+file):
                            elf_files.append(root+"/"+file)
                except:
                    continue
        return elf_files


    def is_elf(self, path):
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
                    print "[WARNING] 7fCould not open the file"+path+" in 1s. Skipping."
        except:
            print "[WARNING] Couldn't determine if "+path+" is ELF."

        return False

