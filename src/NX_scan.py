import docker
from src.Scan import Scan
import logging

class NX_scan(Scan):

    """
    This class implements the verification of the nx bit support from the cpu, or the support for PAE.
    The CPU flags are directly queried and verified.
    """

    name = "NX scan"
    description = "This script verifies the support of the nx bit or PAE from the CPU"
    docker_image = "debian:latest"

    def start_container(self):
        client = docker.DockerClient(base_url='unix:///var/run/docker.sock')
        container = client.containers.run(self.docker_image, tty=True, command="bash", detach=True)
        return container

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

    def scan(self):
        exit_code, output = self.container_id.exec_run("cat /proc/cpuinfo")
        if exit_code != 0:
            self.end_scan()
            logging.ERROR("The NX scan failed.")
        else:
            lines = output.split("\n")
            flags = self.parse_logs(lines)
            cpu_flags = []
            for flag_set in flags:
                single_flags = flag_set.split(" ")
                cpu_flags.append(single_flags)
            nxsupport = True
            for cpu in cpu_flags:
                if "nx" in cpu and "pae" in cpu:
                    nxsupport = nxsupport and True
                else:
                    nxsupport = False
            result = {'Nx_support': nxsupport}
            return result
