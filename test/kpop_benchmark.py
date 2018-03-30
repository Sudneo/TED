import docker
import os
import csv
import subprocess
import time

class kpop_benchmark(object):

    """

    """


    name = "Kernelpop"
    description = "Kernelpop will perform a series of tests to determine if the kernel presents known vulnerabilities."
    docker_image = "sudneo/kernelpop"
    container_id=None

    def __init__(self):
        self.container_id = self.start_container()

    def start_container(self):
        client = docker.DockerClient(base_url='unix:///var/run/docker.sock')
        volume = {}
        content = {}
        content['bind'] = '/report'
        content['mode'] = 'rw'
        volume['/tmp/kernelpop'] = content
        container = client.containers.run(self.docker_image,tty=True, command="bash", volumes=volume , detach=True)
        return container

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
        self.container_id.exec_run("bash entrypoint.sh")
        return self.parse_report()

    @timeit
    def scan_native(self):
        output = subprocess.check_output("python3 /home/daniele/University/thesis/src/tools/kernelpop/kernelpop.py -r report.csv", shell=True)
        os.system("mkdir -p /tmp/kernelpop/ && mv report.csv /tmp/kernelpop/")
        return self.parse_report()

    def parse_report(self):

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






c= kpop_benchmark()
for i in range(100):
    c.scan_docker()
for i in range(100):
    c.scan_native()