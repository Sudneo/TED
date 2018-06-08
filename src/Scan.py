from abc import abstractmethod


class Scan(object):

    """
    Abstraction of a Scan.
    This class represents the model with which standardize all the other checks/tests performed.
    The structure is simple: each scan has a name, a description, a Docker image and a container ID.

    Attributes:
         name: The name of the scan.
         description: Description of what this tests verifies
         docker_image: This is the name of the Docker image to run to execute this test
         container_id: This is the ID of the container actually spawned on the machine
    """
    name = ""
    description = ""
    docker_image = ""
    container_id = ""

    def __init__(self):
        self.container_id = self.start_container()

    @abstractmethod
    def start_container(self):
        pass

    @abstractmethod
    def scan(self):
        pass

    def end_scan(self):
        self.container_id.kill()
