import docker
from src.Scan import Scan
import logging
import json


class Spectre_scan(Scan):

    """
    This class implements the vulnerability test for Spectre and meltdown.
    In order to perform this test, an external tool is used spectre-meltdown-checker.sh
    https://github.com/speed47/spectre-meltdown-checker
    The script now detects 5 different variants for Spectre
    """
    name = "Spectre and Meltdown check"
    description = "This scan verifies whether the system is vulnerable to different Spectre variants"
    docker_image = "sudneo/spectre-meltdown"

    def start_container(self):
        client = docker.DockerClient(base_url='unix:///var/run/docker.sock')
        capabilities = [].append("ALL")
        volume = {}
        dev_content = {}
        dev_content['bind'] = '/dev'
        dev_content['mode'] = 'ro'
        volume['/dev'] = dev_content
        boot_content = {}
        boot_content['bind'] = '/boot'
        boot_content['mode'] = 'ro'
        volume['/boot'] = boot_content
        container = client.containers.run(self.docker_image, privileged=True, tty=True, command="bash",
                                                  cap_add=capabilities, volumes=volume, detach=True)
        return container

    def scan(self):
        """
        Collects the output of the script.
        :return: a JSON output with the three versions of spectre and meltdown
        """
        exit_code, output = self.container_id.exec_run("bash /spectre-meltdown/spectre-meltdown-checker.sh  --no-color --batch json")
        json_output = "[" + output.split("[", 1)[-1]
        if exit_code <= 2:
            self.end_scan()
            return json.loads(json.dumps(json_output))
        else:
            self.end_scan()
            logging.ERROR("The spectre and meltdown check failed with exit code:"+str(exit_code))