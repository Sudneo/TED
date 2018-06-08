import argparse
import logging
import src.elf_finder as elf_finder
from src.Kernelpop_scan import *
from src.nx_scan import *
from src.spectreMeltdown_scan import *
from src.aslr_scan import *
from src.single_elf_scanner import *
from src.elf_scan import *
from src.output_parser import *


def get_args():
    parser = argparse.ArgumentParser(description="TED is a tool that uses Docker containers in order to perform"
                                                 " a set of security checks both on the whole system and on every "
                                                 "ELF file present on the system.")
    output_format_group=parser.add_mutually_exclusive_group()
    output_format_group.add_argument('-Oj', '--output-json', dest="filejson", nargs='?', const="ted_result.json"
                                     , help="Saves the output in json format.\nDefault to ted_result.json")
    output_format_group.add_argument('-Oc', '--output-csv', dest="filecsv", nargs='?', const="ted_result.csv",
                                     help="Saves the output in csv format.\n "
                                          "Default to ted_result.csv")
    scan_type_group=parser.add_mutually_exclusive_group(required=True)
    scan_type_group.add_argument('-f', '--full-scan', dest="fullscan", action='store_true',
                                 help="Performs a full scan of the system and"
                                      " of all the ELFs in it.")
    scan_type_group.add_argument('-e', '--elf-scan', dest="elfscan", action='store_true',
                                 help='Skips the system checks and scans all'
                                      ' the ELFs in the system')
    scan_type_group.add_argument('-t', '--target-elf', dest="targetscan", nargs=1,
                                 help="Performs all the checks on a single ELF file")
    parser.add_argument('-p', '--path', dest="path", nargs="?",default="/", const="/",
                        help="The path in which to look for ELFs. Default /\n")

    return parser.parse_args()

def get_scan_type():
    """

    :return: a tuple scan_type, target_file. Scan type can be 'full', 'elf' or 'single'.
             tatget_file is None except in case of 'single' scan.
    """
    args = get_args()
    scan_type = "full"
    target_file = None
    if args.elfscan:
        scan_type = "elf"
    elif args.targetscan is not None:
        scan_type = "single"
        target_file = args.targetscan[0]
    return scan_type, target_file


def get_report_file():
    """

    :return: a tuple file_type, file_name. file_type can be 'json' or 'csv'.
    """
    args = get_args()
    file_type = "json"
    if args.filejson is None:
        file_type = "csv"
        return file_type, args.filecsv
    else:
        return file_type, args.filejson


def get_path_to_scan():
    """

    :return: The path in which to look for ELFs file.
    """
    args = get_args()
    return args.path


def get_kernelpop_scan():
    kernelpop = Kernelpop_scan()
    report = kernelpop.scan()
    kernelpop.cleanup_files()
    return report


def get_nx_support_scan():
    nx_support = nx_scan()
    report = nx_support.scan()
    return report


def get_spectre_meltdown_scan():
    spectre_meltdown = spectreMeltdown_scan()
    report = spectre_meltdown.scan()
    return report


def get_aslr_scan():
    aslr = aslr_scan()
    report = aslr.scan()
    return report


def get_all_elfs():
    all_elfs = elf_finder.get_elf_list(get_path_to_scan())
    return all_elfs


def get_elf_report(elf_scan, full_path):
    elf_scanner = single_elf_scanner(elf_scan, full_path)
    report = elf_scanner.scan()
    return report


def print_report(report,output_file,output_format):
    with open(output_file, "w") as file:
        if output_format == "json":
            json.dump(report, file, sort_keys=True, indent=4)
        elif output_format == "csv":
            lines = report
            for line in lines:
                file.write(line)


def scan():
    """
    Main method of the class. It performs all the necessary scans.
    :return:
    """

    #The default is a full scan of system+all ELFs
    scan_system = True
    scan_elfs = True
    scan_single_elf = False
    scan_type, target_file = get_scan_type()
    output_type, output_file = get_report_file()
    kernelpop_report = None
    nx_support_report = None
    spectre_meltdown_report = None
    aslr_report = None
    if scan_type == "elf":
        scan_system = False
    elif scan_type == "single":
        scan_system = False
        scan_elfs = False
        scan_single_elf = True

    if scan_system:
        #Perform system wide checks.
        print "Checking if the kernel is vulnerable to known exploits."
        kernelpop_report = get_kernelpop_scan()
        print "Checking if the CPU supports the nx bit on memory pages."
        nx_support_report = get_nx_support_scan()
        print "Checking system vulnerability to spectre and meltdown."
        spectre_meltdown_report = json.loads(get_spectre_meltdown_scan())
        print "Checking if ASLR is enabled and to what extent."
        aslr_report = get_aslr_scan()
    elf_reports = []
    if scan_elfs:
        print "Checking all ELFs in "+get_path_to_scan()+"."
        elf_scanner = elf_scan()
        elfs = get_all_elfs()
        for filename in elfs:
            report = get_elf_report(elf_scanner, filename)
            elf_reports.append(report)
        elf_scanner.end_scan()
    elif scan_single_elf:
        print "Checking file "+target_file+"."
        elf_scanner = elf_scan()
        report = get_elf_report(elf_scanner, target_file)
        elf_reports.append(report)
        elf_scanner.end_scan()
    output_p = output_parser(scan_type, output_type, output_file, kernelpop_report, nx_support_report,
                             spectre_meltdown_report, aslr_report,elf_reports)
    output_p.print_report()
    print "Finished.\n Please check the report file "+output_file


scan()