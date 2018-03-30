import docker
import json
import time
import subprocess

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
        self.container_id = client.containers.run(self.docker_image, privileged=True, command="bash", cap_add=capabilities, volumes=volume,
                                          detach=True, tty=True)

    def timeit(f):
        def timed(*args, **kw):
            ts = time.time()
            result = f(*args, **kw)
            te = time.time()

            print 'func:%r args:[%r, %r] took: %2.4f sec' % \
                  (f.__name__, args, kw, te - ts)
            return result

        return timed

    @timeit
    def scan_docker(self):
        """
        Collects the output of the script at https://github.com/speed47/spectre-meltdown-checker
        :return: a JSON output with the three versions of spectre and meltdown
        """
        exit_code,output = self.container_id.exec_run("bash /spectre-meltdown/spectre-meltdown-checker.sh --batch json")

        json_logs = ""
        for line in output:
            json_logs = json_logs + line
        return json.loads(json.dumps(json_logs))

    @timeit
    def scan_native(self):
        output=""
        try:
            output=subprocess.check_output("bash /home/daniele/Experiments/spectre-meltdown-checker.sh --batch json",stderr=subprocess.STDOUT, shell=True)
        except:
            pass
        return output


c = spectreMeltdown_scan()
for i in range(100):
    c.scan_docker()