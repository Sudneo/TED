import docker
import json
import subprocess
import os
import magic
from single_scanner import *
from elf_finder import *


class elf_scan:

    name = "elf scan"
    description = "A various range of checks performed on an ELF file."
    docker_image = "sudneo/radare2"
    container_id=None

    def __init__(self):
        self.container_id=self.start_container()
        pass

    def start_container(self):
        client = docker.DockerClient(base_url='unix:///var/run/docker.sock')
        volume = {}
        elf_dir = {}
        elf_dir['bind'] = "/target"
        elf_dir['mode'] = 'ro'
        volume['/'] = elf_dir
        container = client.containers.run(self.docker_image,tty=True, command="bash", volumes=volume , detach=True)
        return container


    def get_sections(self,filename_full_path):
        exit_code,output=self.container_id.exec_run("rabin2 -Sj /target"+filename_full_path)
        json_output="{"+output.split("{",1)[-1]
        if exit_code == 0:
            return json.loads(json.dumps(json_output))
        else:
            raise RuntimeError('The command in get_sections failed')

    def get_sections_native(self,filename_full_path):
        output=subprocess.check_output("rabin2 -Sj "+filename_full_path, shell=True)
        json_output="{"+output.split("{",1)[-1]
        return json.loads(json.dumps(json_output))


    def get_information(self,filename_full_path):
        exit_code,output=self.container_id.exec_run("rabin2 -Ij /target"+filename_full_path, shell=True)
        json_output="{"+output.split("{",1)[-1]

        if exit_code == 0:
            return json.loads(json.dumps(json_output))
        else:
            raise RuntimeError('The command in get_info failed')

    def get_information_native(self,filename_full_path):
        output=subprocess.check_output("rabin2 -Ij "+filename_full_path, shell=True)
        json_output="{"+output.split("{",1)[-1]
        return json.loads(json.dumps(json_output))


    def get_sssp(self, filename_full_path):
        exit_code,output=self.container_id.exec_run("objdump -d /target"+filename_full_path, shell=True)
        if exit_code != 0:
            raise RuntimeError('The objdump command failed')
        STACK_CHK = "__stack_chk_fail"
        report = { 'SSSP' : False}
        for line in output.split("\n"):
            if STACK_CHK in line:
                report ['SSSP'] = True
                return json.loads(json.dumps(report))
        return json.loads(json.dumps(report))

    def get_sssp_native(self, filename_full_path):
        output=subprocess.check_output("objdump -d "+filename_full_path, shell=True)
        STACK_CHK = "__stack_chk_fail"
        report = { 'SSSP' : False}
        for line in output.split("\n"):
            if STACK_CHK in line:
                report ['SSSP'] = True
                return json.loads(json.dumps(report))
        return json.loads(json.dumps(report))


    def end_scan(self):
        self.container_id.kill()


bin_list = elf_finder("/bin").get_elf_list()
c = elf_scan()
for file in bin_list:
    ss = single_scanner(c,file)
    ss.scan()

