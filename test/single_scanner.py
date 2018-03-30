import hashlib
import json
import time


class single_scanner:


    """
    This class offers an interface to get information and reports about a single ELF file
    """

    full_path=""
    information_report=None
    section_report=None
    sssp_report=None
    elfscan=None

    def __init__(self,elf_scan, full_path):
        self.elfscan = elf_scan
        self.full_path = full_path
        self.information_report = json.loads(self.elfscan.get_information_native(full_path))
        self.section_report = json.loads(self.elfscan.get_sections_native(full_path))
        self.sssp_report = self.elfscan.get_sssp_native(full_path)

    def timeit(f):

        def timed(*args, **kw):
            ts = time.time()
            result = f(*args, **kw)
            te = time.time()

            print 'func:%r args:[%r, %r] took: %2.4f sec' % \
                  (f.__name__, args, kw, te - ts)
            return result

        return timed

    def is_stripped(self):
        return self.information_report['info']['stripped']

    def has_nx(self):
        return self.information_report['info']['nx']

    def is_stack_executable(self):
        sections = self.section_report['sections']
        for section in sections:
            name=section['name']
            if "stack" in name or "STACK" in name:
                return "x" in section['flags']
        return False

    def has_canaries(self):
        return self.information_report['info']['canary']

    def has_sections_wx(self):
        sections=self.section_report['sections']
        for section in sections:
            flags=section['flags']
            if "w" in flags and "x" in flags:
                return True
        return False

    def has_sssp(self):
        return self.sssp_report['SSSP']

    def get_hash(self):
        BUF_SIZE = 65536
        sha256 = hashlib.sha256()
        with open(self.full_path, 'rb') as f:
            while True:
                data = f.read(BUF_SIZE)
                if not data:
                    break
                sha256.update(data)
        return sha256.hexdigest()


    @timeit
    def scan(self):
        """
        Main method to collect all data about a single ELF
        - Is the binary stripped
        - Is the binary's stack executable
        - Is nx enforced
        - Does the binary have canaries/SSSP applied
        :return: a Json { 'stripped' : 'boolean' , 'NX' : [ 'Stack_executable' : boolean , 'WX' : 'boolean' , 'nx' : 'boolean']
                          'SSSP' : [ 'canaries' : 'boolean' , 'objdump_check' : boolean ]
        """
        report= {'filename' : self.full_path}
        report['hash'] = self.get_hash()
        report['stripped'] = self.is_stripped()
        non_exec_checks=[]
        stack_exec = {'stack_executable' : self.is_stack_executable()}
        wx = { 'WX_enforced' : not self.has_sections_wx() }
        nx = { 'nx' : self.has_nx()}
        non_exec_checks.append(stack_exec)
        non_exec_checks.append(wx)
        non_exec_checks.append(nx)
        report ['NoExec' ] = non_exec_checks
        canaries_checks = []
        canaries_reported = {'canaries' : self.has_canaries()}
        sssp = {'sssp' : self.has_sssp()}
        canaries_checks.append(canaries_reported)
        canaries_checks.append(sssp)
        report ['canaries' ] = canaries_checks
        report_json = json.loads(json.dumps(report))
        return report_json


