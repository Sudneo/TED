import docker
import json

class spectreMeltdown_scan():


    """
    This class uses a standard script to check if the system is vulnerable to spectre or meltdown
    """

    name = "Spectre and meltdown_check"
    description = "This script verifies the vulnerability to spectre and meltdown"
    docker_image = "sudneo/spectre-meltdown"

    def __init__(self):
        pass

    def scan(self):
        """
        Collects the output of the script at https://github.com/speed47/spectre-meltdown-checker
        :return: a JSON output with the three versions of spectre and meltdown
        """
        client = docker.DockerClient(base_url='unix:///var/run/docker.sock')
        capabilities=[].append("ALL")
        volume = {}
        dev_content = {}
        dev_content['bind'] = '/dev'
        dev_content['mode'] = 'ro'
        volume['/dev'] = dev_content
        boot_content={}
        boot_content['bind'] = '/boot'
        boot_content['mode'] = 'ro'
        volume['/boot'] = boot_content
        container = client.containers.run(self.docker_image, privileged=True , cap_add=capabilities , volumes=volume , detach=True)
        json_logs = ""
        for line in container.logs(stream=True):
            json_logs = json_logs + line
        return json.loads(json.dumps(json_logs))
