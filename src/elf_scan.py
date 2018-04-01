import docker
import json


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
        capabilities = [].append("ALL")
        container = client.containers.run(self.docker_image,tty=True, command="bash", privileged=True,
                                          volumes=volume, cap_add=capabilities, detach=True)
        return container


    def get_sections(self,filename_full_path):
        exit_code,output=self.container_id.exec_run("rabin2 -Sj /target"+filename_full_path)
        json_output="{"+output.split("{",1)[-1]
        if exit_code == 0:
            return json.loads(json.dumps(json_output))
        else:
            raise RuntimeError('The command in get_sections failed')

    def get_information(self,filename_full_path):
        exit_code,output=self.container_id.exec_run("rabin2 -Ij /target"+filename_full_path)
        json_output="{"+output.split("{",1)[-1]

        if exit_code == 0:
            return json.loads(json.dumps(json_output))
        else:
            print json_output
            raise RuntimeError('The command in get_info failed')

    def get_sssp(self, filename_full_path):
        exit_code,output=self.container_id.exec_run("objdump -d /target"+filename_full_path)
        STACK_CHK = "__stack_chk_fail"
        report = { 'SSSP' : False}
        for line in output.split("\n"):
            if STACK_CHK in line:
                report ['SSSP'] = True
                return json.loads(json.dumps(report))
        return json.loads(json.dumps(report))


    def end_scan(self):
        self.container_id.kill()

