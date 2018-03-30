import os
import magic

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
                if self.is_elf(root+"/"+file):
                    elf_files.append(root+"/"+file)
        return elf_files


    def is_elf(self, path):
        """

        :param path: the path to the file to analyze
        :return: True if the file is ELF, false otherwise
        """
        try:
            filetype=magic.from_file(path)
            if "ELF" in filetype:
                return True
        except:
            print "[WARNING] Couldn't determine if "+path+" is ELF: is_elf failed"

        return False
