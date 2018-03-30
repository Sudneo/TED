import docker

class nx_scan:

    """
    This class simply verify the presence of Nx or pae in the flags of the cpu.

    """

    name = "Nx_check"
    description = "This script verifies the support of the processor for the Nx bit"
    docker_image = "debian:latest"

    def __init__(self):
        pass

    def scan(self):
        """
        Checks the output of /proc/cpuinfo for the presence of pae and nx flag
        :return: a dictionary {'Nx_support' : boolean}
        """
        client = docker.DockerClient(base_url='unix:///var/run/docker.sock')
        container = client.containers.run(self.docker_image, command="cat /proc/cpuinfo", detach=True)
        logs = ""
        for line in container.logs(stream=True):
            logs = logs + line
        lines = logs.split("\n")
        flags = self.parse_logs(lines)
        cpu_flags=[]
        for flag_set in flags:
            single_flags=flag_set.split(" ")
            cpu_flags.append(single_flags)
        nxsupport=True
        for cpu in cpu_flags:
            if "nx" in cpu and "pae" in cpu:
                nxsupport = nxsupport and True
            else:
                nxsupport = False
        result={'Nx_support':nxsupport}
        return result


    def parse_logs(self,lines):
        """
        From a list of lines, returns a set containing the flags for each cpu core.
        :param lines: The list of lines output of /proc/cpuinfo
        :return: a set with each element the flags for a cpu.
        """
        output = []
        for line in lines:
            field_value = line.split(":")
            if len(field_value) > 1:
                field = field_value[0].rstrip("\t")
                value = field_value[1].lstrip(" ")
                if field=="flags":
                    output.append(value)
        return set(output)

