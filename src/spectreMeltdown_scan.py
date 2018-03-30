import docker
import json

class spectreMeltdown_scan():


    """
    This class uses a standard script to check if the system is vulnerable to spectre or meltdown
    """

    name = "Spectre and meltdown_check"
    description = "This script verifies the vulnerability to spectre and meltdown"
    docker_image = "sudneo/spectre-meltdown"
    container_id=None

    def __init__(self):
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
        self.container_id = client.containers.run(self.docker_image, privileged=True, tty=True, command="bash",
                                                  cap_add=capabilities, volumes=volume, detach=True)

    def scan(self):
        """
        Collects the output of the script at https://github.com/speed47/spectre-meltdown-checker
        :return: a JSON output with the three versions of spectre and meltdown
        """
        exit_code, output = self.container_id.exec_run("bash /spectre-meltdown/spectre-meltdown-checker.sh --batch json")
        json_output = "[" + output.split("[", 1)[-1]
        if exit_code == 2:
            self.end_scan()
            return json.loads(json.dumps(json_output))
        else:
            self.end_scan()
            raise RuntimeError('The spectre-meltdown check failed. Exit code: '+exit_code)

    def end_scan(self):
        self.container_id.kill()