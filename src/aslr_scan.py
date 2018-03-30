import docker



class aslr_scan:

    """
    Performs a system check with custom scripts inside a docker container.

    Attributes:
        name: ASLR_check
        description: verifies that ASLR is enables
        docker_image: fixed string for the docker image to run
    """

    name = "ASLR_check"
    description = "This script verifies that ASLR is enables as a system wide measure to protect from attacks such as ret2libc."
    docker_image = "sudneo/aslr_check"
    container_id=None


    def __init__(self):
        self.container_id = self.start_container()

    def start_container(self):
        client = docker.DockerClient(base_url='unix:///var/run/docker.sock')
        container = client.containers.run(self.docker_image,tty=True, command="bash", detach=True)
        return container

    def check_duplicates(self,addr_list):
        """
        :param addr_list: This is a list of addresses
        :return: returns True if there are duplicates inside the list, False otherwise
        """
        return len(addr_list) != len(set(addr_list))

    def soft_scan(self):
        """
        Performs the soft check for ASLR, that is verifying the output of sysctl kernel.randomize_va_space
        :return: the value 0,1 or 2
        0 means ASLR is not enabled
        1 means ASLR is partially enabled
        2 means ASLR is enabled
        3 means ASLR is enabled and further patches are applied
        """
        exit_code, output = self.container_id.exec_run("sysctl kernel.randomize_va_space")
        if exit_code == 0:
            splitted = output.split ("=")
            soft_check = {"ASLR_soft": splitted[1].rstrip("\n").lstrip(" ")}
            return soft_check
        else:
            raise RuntimeError("Error during execution of ASRL soft check")

    def hard_scan_report(self,addresses):
        """
        :param addresses: This is a dictionary with keys 'env', 'stack' and 'heap', each key has as a value a list of
        addresses
        :return: a dictionary with key 'ASLR_hard' and key 0,1 or 2
        """
        env_duplicates=self.check_duplicates(addresses['env'])
        stack_duplicates=self.check_duplicates(addresses['stack'])
        heap_duplicates=self.check_duplicates(addresses['heap'])

        if env_duplicates or stack_duplicates:
            result={ "ASLR_hard" : "0"}
        elif heap_duplicates:
            result={ "ASLR_hard" : "1"}
        else:
            result = {"ASLR_hard": "2"}
        return result

    def hard_scan(self):
        """
        Performs a harder check for ASLR. It executes a binary inside the container that prints the value of environment
        pointer, stack pointer and a heap address. It runs this 10 times and based on the result it will output:
        0 if all the values are the same for all the executions
        1 if env and stack are different but heap is the same
        2 if all of them are different
        :return: 0,1 or 2 as describe before.
        """
        addresses={}
        addresses['env']=[]
        addresses['stack']=[]
        addresses['heap']=[]
        #client = docker.DockerClient(base_url='unix:///var/run/docker.sock')
        for i in range(10):
            exit_code, output = self.container_id.exec_run("./aslr/get_addresses")
            if exit_code == 0:
                lines = output.split("\n")
                env_addr=lines[0].split("=")[1]
                stack_addr=lines[1].split("=")[1]
                heap_addr=lines[2].split("=")[1]
                addresses['env'].append(env_addr)
                addresses['stack'].append(stack_addr)
                addresses['heap'].append(heap_addr)
            else:
                raise RuntimeError ("Error during ASLR hard check")
        return self.hard_scan_report(addresses)
    def scan(self):
        """
        Wrapper function to invoke both soft and hard scan and putting it together
        :return: The combiantion of the report for the soft and the hard scan
        """
        hard_report=self.hard_scan()
        soft_report=self.soft_scan()
        list_value=[]
        list_value.append(hard_report)
        list_value.append(soft_report)
        result={'ASLR' : list_value}
        return result
