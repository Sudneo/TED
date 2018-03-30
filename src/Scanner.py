"""
-------System wide-------
[X]Kernelpop scan. Check if kernel is exploitable
[X]ASLR verification scan. Check if ASLR is enabled and to what extent
[X]Spectre/Meltdown script. Check if the system is vulnerable to the spectre/meltdown stuff
[X]NX. Check if the NX bit is supported by the processor
------- ELF wide -------
[X]SSSP applied (?). Check if the binary is compiled with canaries.
[ ]AAAS. Check if system library addresses start with x00
[X]Stripped. Check if the binary is stripped.
[X]Nx/W+X. Check if the stack is executable, check if there are sections both writable and executable.
[ ]Check if I can attach with ptrace?
[ ]Check if I can attach with gdb?
"""

class Scanner(object):

    """
    A scan that will be performed on the system



    Attributes:
        description: A string summarizing what the scan does
        name: A string representing the name of the scan
        docker_image: The string representing the Docker image to run
        TBD.

    """
