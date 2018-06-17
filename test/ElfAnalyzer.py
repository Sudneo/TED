from elftools.elf.elffile import ELFFile
import logging


class ElfAnalyzer:
    """
    This class has some supporting functionalities to analyze ELFs file. In particular it provides the functionality
    for:
    [ X ] Detect if a ELF is of type Executable (in opposition to relocatable, None, core dump.
    [ X ] Detect if a ELF has any section marked both W and X (violates W^X principle).
    [ X ] Detect if a ELF has the stack segment marked as executable (violates DEP)
    [   ] Detect if a ELF has any data section marked as executable.
    [ X ] Detect if a ELF is stripped.
    [ X ] Detect if a ELF uses stack protector. (By verifying the presence of __stack_check_fail)
    [   ] Detect if a ELF uses unsafe functions (puts, gets, etc.)
    """
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
        has_debug_section = False
        has_symbol_table = False
        for section in self.elf_file.iter_sections():
            if "debug" in section.name:
                has_debug_section = True
                print "[+] Section %s found. Binary contains debug information." % section.name
            if section.name == ".symtab":
                has_symbol_table = True
                print "[+] Symbol table found. Binary is likely not stripped."
        return has_debug_section or has_symbol_table

    def uses_ssp(self):
        """

        :return: True if the binary contains __stack_chk_fail, function used to check canary value inserted by SSP.
        """
        functions = self.get_functions()
        if "__stack_chk_fail" in functions:
            return True
        return False

    def section_to_segment_mapping(self):
        """

        :return: A dictionary containing segment indexes and the sections mapped in that segment.
        """
        mapping = {}
        sec_to_seg = {}
        segment_idx = 0
        for segment in self.elf_file.iter_segments():
            mapping[segment_idx] = {'begin': segment.header['p_paddr'], 'end': segment.header['p_paddr'] +
                                    segment.header['p_memsz']}
            sec_to_seg [segment_idx] = {'flags': segment.header['p_flags'], 'sections': []}
            segment_idx += 1
        for section in self.elf_file.iter_sections():
            for segment in mapping.keys():
                section_begin = section.header['sh_addr']
                section_end = section.header['sh_addr'] + section.header['sh_size']
                if section_end - section_begin == 0:
                    # NULL section. Skip.
                    continue
                if mapping[segment]['begin'] <= section_begin and section_end <= mapping[segment]['end']:
                    sec_to_seg[segment]['sections'].append(section.name)
        return sec_to_seg
        # for item in sec_to_seg.keys():
        #     sections = ""
        #     for s in sec_to_seg[item]:
        #         sections += s+" "
        #     print "Segment %s : %s" % (str(item), sections)

    def hard_wx_check(self):
        """
        This functions checks for every segment if this segment is Writeable or eXecutable.
        For each writeable segment, it checks whether there is one section mapped in this segment which is eXecutable.
        For each executable segment, it checks wheterh there is one section mapped in this segment which is Writeable.
        :return: True if W^X is respected, False if it is violated.
        """
        sec_to_seg = self.section_to_segment_mapping()
        for segment in sec_to_seg.keys():
            if len(sec_to_seg[segment]['sections']) == 0:
                # Empty segment. Skip.
                continue
            seg_x = (sec_to_seg[segment]['flags'] & 0x0001) > 0
            seg_w = (sec_to_seg[segment]['flags'] & 0x0004) > 0
            if seg_x:
                print "Segment %s is executable." % str(segment)
                for section in sec_to_seg[segment]['sections']:
                    section_flags = self.elf_file.get_section_by_name(section).header['sh_flags']
                    if section_flags & 0x0001 > 0:
                        return False
                    print "\t[+] Section %s is not Writeable." % section
            elif seg_w:
                print "Segment %s is writeable." % str(segment)
                for section in sec_to_seg[segment]['sections']:
                    section_flags = self.elf_file.get_section_by_name(section).header['sh_flags']
                    if section_flags & 0x0004 > 0:
                        return False
                    print "\t[+] Section %s is not eXecutable." % section
        return True

e = ElfAnalyzer()
e.set_elf("/home/daniele/Experiments/newhello")
print e.hard_wx_check()
