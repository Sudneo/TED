import elf_finder
import elf_scan

class scan_all_elfs():
    """
    A class for scanning all the elf in the system and collecting the result

    """
    elf_finder=""
    elf_scan=""
    report_file=""

    def __init__(self,report):
        self.elf_finder=elf_finder.elf_finder("/home/daniele/Experiments")
        self.elf_scan=elf_scan.elf_scan()
        self.report_file=report
        pass

    def scan_all(self):
        report=open(self.report_file,"w")
        report.write("File,Stripped,NX,Canaries\n")
        elf_list=self.elf_finder.get_elf_list()
        for file in elf_list:
            infoFile=self.elf_scan.get_information(file)
            sections=self.elf_scan.get_sections(file)
            nx_boolean=self.has_nx(infoFile) and not self.is_stack_executable(sections) and not self.has_sections_wx(sections)
            report.write(file+","+str(self.is_stripped(infoFile))+","+str(nx_boolean)+","+str(self.has_canaries(infoFile))+"\n")

        self.elf_scan.end_scan()


    def is_stripped(self,info_report):
        return info_report['info']['stripped']

    def has_nx(self,info_report):
        return info_report['info']['nx']

    def is_stack_executable(self,section_report):
        sections=section_report['sections']
        for section in sections:
            name=section['name']
            if "stack" in name or "STACK" in name:
                return "x" in section['flags']
        return False

    def has_canaries(self, info_report):
        return info_report['info']['canary']

    def has_sections_wx(self,section_report):
        sections=section_report['sections']
        wx=False
        for section in sections:
            flags=section['flags']
            if "w" in flags and "x" in flags:
                return True
        return False

s=scan_all_elfs("./result.csv")
s.scan_all()