from elftools.elf.elffile import ELFFile
import logging


class ElfAnalyzer:

    elf_file = None

    def __init__(self):
        pass

    def set_elf(self, filename):
        self.elf_file = ELFFile(open(filename))

    def is_executable(self):
        """

        :return: True if the file is of type executable, False otherwise
        """
        elf_type = self.elf_file.header['e_type']
        if elf_type == "ET_EXEC":
            return True
        return False

    def has_sections_wx(self):
        """
        :return: True if the file contains W+X sections, False otherwise.
        """
        for section in self.elf_file.iter_sections():
            name = section.name
            flags = section.header['sh_flags']
            if (flags & 0x0001) > 0 & (flags & 0x0004) > 0:
                logging.warning("The section %s is both Writeable and Executable." % name)
                return True
        return False

    def has_stack_executable(self):
        """

        :return: True if the stack segment is marked Executable, False otherwise
        """
        for segment in self.elf_file.iter_segments():
            if segment.header['p_type'] == 'PT_GNU_STACK':
                flags = segment.header['p_flags']
                if (flags & 0x0001) > 0:
                    logging.warning("The stack is marked executable.")
                    return True
                return False

    def get_functions(self):
        """

        :return: A list of functions used in the binary
        """
        dynstr_section = self.elf_file.get_section_by_name(".dynstr")
        if dynstr_section is None:
            logging.warning("The file does not contain dynamic string information.")
            return None
        functions_used = []
        hex_data = dynstr_section.data().encode('hex').replace("00", " ")
        hex_functions = hex_data.split()
        for f in hex_functions:
            functions_used.append(f.decode('hex'))
        return functions_used

    def is_stripped(self):
        """

        :return: True if the binary is stripped, False otherwise
        """
        #TODO

e = ElfAnalyzer()
e.set_elf("/home/daniele/Experiments/newhello")
print e.is_executable()
print e.has_stack_executable()
