import docker
import os
import csv

class Kernelpop_scan(object):


    """
    Performs a system check with kernelpop inside a docker container.

    Attributes:
        name: Kernelpop
        description: fixed description of this scan
        docker_image: fixed string for the docker image to run
    """

    name = "Kernelpop"
    description = "Kernelpop will perform a series of tests to determine if the kernel presents known vulnerabilities."
    docker_image = "sudneo/kernelpop"

    def __init__(self):
        pass


    def scan(self):
        """Performs the actual scan and returns a Json containing the result"""
        client = docker.DockerClient(base_url='unix:///var/run/docker.sock')
        os.system("mkdir -p /tmp/kernelpop")
        volume={}
        content={}
        content['bind']='/report'
        content['mode']='rw'
        volume['/tmp/kernelpop']=content
        container = client.containers.run(self.docker_image, detach=True, volumes=volume)
        logs=""
        for line in container.logs(stream=True):
            logs=logs+line
        return self.parse_report()

    def parse_report(self):
        """

        :return: a dictionary with key 'report' that contains two other dictionaries with keys 'confirmed' and 'potential'.
        Each of these dictionaries has as value a list of dictionaries with 'cve','reliability' and 'description' keys

        """
        result={}
        result['report'] = {}
        with open("/tmp/kernelpop/report.csv",'rb') as csvfile:
            reader = csv.reader(csvfile, delimiter=',', quotechar='|')
            rows=[r for r in reader]
            if rows[0][0]!= "Confirmed exploits":
                raise RuntimeError('The report file is not formatted properly')
            result['report']['confirmed'] = []
            if rows[1][0]!= "no confirmed exploits found":
                index=1
                while rows[index][0]!="Potential exploits":
                    result['report']['confirmed'].append({
                        'cve': rows[index][0],
                        'reliability' : rows[index][1],
                        'description' : rows[index][2]
                    })
                    index+=1
            else:
                index=2
            #Here rows[index][0] is Potential exploits
            potential_index=index+1
            result['report']['potential'] = []
            if rows[potential_index][0]!="no potential exploits found":
                for row in rows[potential_index:]:
                    result['report']['potential'].append({
                        'cve': row[0],
                        'reliability': row[1],
                        'description': row[2]
                    })
                    self.cleanup_files()
        return result


    def cleanup_files(self):
        """
        Delete the /tmp/kernelpop folder and consequently the report generated.
        :return:
        """
        os.system("rm -r /tmp/kernelpop")


