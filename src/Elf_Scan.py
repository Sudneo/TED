import docker
import json
from Colours import *

"""
Class used to perform all the necessary checks on an ELF.
Typical use would be 
elf_scan = ElfScan() # This creates the container
elf_scan.set_target_elf(elf_object)
elf_scan.scan()
"""


class ElfScan(object):
    # General characteristics
    name = "elf scan"
    description = "A various range of checks performed on an ELF file."
    docker_image = "sudneo/radare2"
    container_id = None
    # Scan utils
    elf = None
    information_report = None
    section_report = None
    ssp_report = None

    def __init__(self):
        self.container_id = self.start_container()
        pass

    def start_container(self):
        client = docker.DockerClient(base_url='unix:///var/run/docker.sock')
        volume = {}
        elf_dir = {'bind': "/target", 'mode': 'ro'}
        volume['/'] = elf_dir
        capabilities = [].append("ALL")
        container = client.containers.run(self.docker_image, tty=True, command="bash", privileged=True,
                                          volumes=volume, cap_add=capabilities, detach=True)
        return container

    def set_target_elf(self, elf_object):
        self.elf = elf_object

    def set_sections(self):
        exit_code, output = self.container_id.exec_run("rabin2 -Sj /target"+self.elf.full_path, stderr=False,
                                                       stdout=True)
        json_output = "{"+output.split("{", 1)[-1]
        end = json_output.rfind("}")
        out = json_output[:end+1].replace("Unsupported relocation type for imports 1", "")
        out = out.replace("Warning: Cannot initialize dynamic strings", "")
        if exit_code == 0:
            self.section_report = json.loads(json.dumps(out))
        else:
            raise RuntimeError('The command in get_sections failed')

    def set_information(self):
        exit_code, output = self.container_id.exec_run("rabin2 -Ij /target"+self.elf.full_path, stderr=False,
                                                       stdout=True)
        json_output = "{"+output.split("{", 1)[-1]
        end = json_output.rfind("}")
        out = json_output[:end+1].replace("Unsupported relocation type for imports 1", "")
        out = out.replace("Warning: Cannot initialize dynamic strings", "")
        if exit_code == 0:
            self.information_report = json.loads(json.dumps(out))
        else:
            raise RuntimeError('The command in get_info failed')

    def set_ssp(self):
        exit_code, output = self.container_id.exec_run("objdump -d /target"+self.elf.full_path)
        stack_chk = "__stack_chk_fail"
        report = {'SSSP': False}
        for line in output.split("\n"):
            if stack_chk in line:
                report['SSSP'] = True
                self.ssp_report = json.loads(json.dumps(report))
        return json.loads(json.dumps(report))

    def set_elf_stripped(self):
        if self.information_report['info']['stripped']:
            self.elf.set_stripped()

    def set_elf_noxec(self):
        if self.information_report['info']['nx']:
            self.elf.set_noexec()

    def set_elf_stack_noexec(self):
        sections = self.section_report['sections']
        for section in sections:
            name = section['name']
            if "stack" in name or "STACK" in name:
                # If stack is in any section marked exec, leave stack_noexec false
                if "x" in section['flags']:
                    return
        self.elf.set_stack_noexec()

    def set_elf_canaries(self):
        if self.information_report['info']['canary']:
            self.elf.set_canaries()

    def set_elf_wxe(self):
        sections = self.section_report['sections']
        for section in sections:
            flags = section['flags']
            if "w" in flags and "x" in flags:
                # If a section is both w and x, leave wxore false
                return
        self.elf.set_wxore()

    def set_elf_ssp(self):
        if self.ssp_report['SSSP']:
            self.elf.set_ssp()

    def scan(self):
        """
        Main method to collect all data about a single ELF
        - Is the binary stripped
        - Is the binary's stack executable
        - Is nx enforced
        - Does the binary have canaries/SSSP applied
        :return: None
        """
        print Colours.OKGREEN+"Examinating file "+self.elf.full_path+Colours.ENDC
        # Extract the information
        self.set_sections()
        self.set_ssp()
        self.set_information()
        # Set the elf attributes according to the result of the scan
        self.set_elf_stripped()
        self.set_elf_noxec()
        self.set_elf_stack_noexec()
        self.set_elf_wxe()
        self.set_elf_ssp()

    def end_scan(self):
        self.container_id.kill()
