import os
import hashlib
"""
This class implements the abstraction for an Elf file
"""


class Elf(object):
    # General characteristics
    full_path = None
    name = None
    hash = None
    # Security features
    stripped = False
    canaries = False
    noexec = False
    stack_noexec = False
    stack_smashing_protector = False
    writeable_xor_executable = False
    antivirus_alert = False
    # ELF properties
    score = 0

    def __init__(self, full_path):
        self.full_path = full_path
        self.name = os.path.basename(full_path)
        self.hash = self.get_hash()

    def get_hash(self):
        """
        Computes the hash of the Elf
        :return: the has of the Elf
        """
        buf_size = 65536
        sha256 = hashlib.sha256()
        with open(self.full_path, 'rb') as f:
            while True:
                data = f.read(buf_size)
                if not data:
                    break
                sha256.update(data)
        return sha256.hexdigest()

    def set_stripped(self):
        self.stripped = True

    def set_canaries(self):
        self.canaries = True

    def set_noexec(self):
        self.noexec = True

    def set_stack_noexec(self):
        self.stack_noexec = True

    def set_ssp(self):
        self.stack_smashing_protector = True

    def set_wxore(self):
        self.writeable_xor_executable = True

    def set_antivirus_alert(self):
        self.antivirus_alert = True

    def compute_risk_score(self):
        pass

    def get_risk_score(self):
        return self.score
