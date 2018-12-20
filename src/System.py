"""
This class abstracts the concept of the system, including the characteristics that Ted takes into consideration.
"""


class System(object):
    # General characteristics
    Elf_number = 0
    # ASLR properties
    Aslr_enabled = False
    Aslr_level = 0
    # Kernelpop - Kernel exploits properties
    Potential_exploits = []
    Confirmed_exploits = []
    Potential_exploits_number = 0
    Confirmed_exploits_number = 0
    # NX support
    Nx_supported = False
    # Speculative execution vulnerabilities
    Spectre_v1_vulnerable = False
    Spectre_v2_vulnerable = False
    Meltdown_vulnerable = False
    Spectre_v4_vulnerable = False
    Spectre_v5_vulnerable = False
    Foreshadow_sgx_vulnerable = False
    Foreshadow_ng_os_vulnerable = False
    Foreshadow_ng_vmm_vulnerable = False
