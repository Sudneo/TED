import json
from datetime import datetime
import scorer


class output_parser:
    kernelpop_report = None
    spectre_meltdown_report = None
    nx_support_report = None
    aslr_report = None
    elf_reports = []
    output_format = ""
    output_file = ""
    scan_type = ""

    def __init__(self, scan_type, output_format, filename, kp_report, nx_report, spec_report, aslr_report, elf_reports):

        if scan_type != "full" and scan_type != "elf" and scan_type != "single":
            raise RuntimeError("Scan type not recognized")
        if output_format != "json" and output_format != "csv":
            raise RuntimeError("Output format not recognized")
        if len(filename) == 0:
            raise RuntimeError("Output file name not valid")
        if scan_type == "full" and (
                        kp_report is None or nx_report is None or spec_report is None or aslr_report is None):
            raise RuntimeError("Some reports are not available for a full scan")

        self.kernelpop_report = kp_report
        self.spectre_meltdown_report = spec_report
        self.nx_support_report = nx_report
        self.aslr_report = aslr_report
        self.elf_reports = elf_reports
        self.output_format = output_format
        self.output_file = filename
        self.scan_type = scan_type

    def parse_kernelpop_report(self):
        kernelpop_score = scorer.get_kernelpop_score(self.kernelpop_report)
        confirmed_exploits = self.kernelpop_report['report']['confirmed']
        potential_exploits = self.kernelpop_report['report']['potential']
        if self.output_format == "json":
            kp_report = {'Description': 'This check uses kernelpop tool to determine whether the running kernel'
                                        'is vulnerable to known exploits. In order to do so, a database with '
                                        'exploit is maintained. For more info check https://github.com/spencerdodd/kernelpop',
                         'Score': kernelpop_score
                         }
            if len(confirmed_exploits) > 0:
                kp_report['confirmed'] = confirmed_exploits
            else:
                kp_report['confirmed'] = ["No confirmed exploits"]
            if len(potential_exploits) > 0:
                kp_report['potential'] = potential_exploits
            else:
                kp_report['potential'] = ["No potential exploits"]
            return kp_report
        elif self.output_format == "csv":
            kp_report_lines = []
            header = "CVE,Reliability,description\n"
            kp_report_lines.append(header)
            if len(confirmed_exploits) > 0:
                for exploit in confirmed_exploits:
                    line = exploit['cve'] + "," + exploit['reliability'] + "," + exploit['description'] + "\n"
                    kp_report_lines.append(line)
            else:
                kp_report_lines.append("No confirmed exploits")
            if len(potential_exploits) > 0:
                for exploit in potential_exploits:
                    line = exploit['cve'] + "," + exploit['reliability'] + "," + exploit['description'] + "\n"
                    kp_report_lines.append(line)
            else:
                kp_report_lines.append("No potential exploits\n")
            return kp_report_lines

    def parse_spectre_report(self):
        spectre_score = scorer.get_spectre_score(self.spectre_meltdown_report)
        spectre_variant_one = self.spectre_meltdown_report[0]
        spectre_variant_two = self.spectre_meltdown_report[1]
        spectre_variant_three = self.spectre_meltdown_report[2]
        if self.output_format == "json":
            spectre_report = {'Description': 'This test uses a third party script to check if the system is'
                                             'vulnerable to three variants of the Spectre and Meltdown attacks.'
                                             'The script can be found at https://github.com/speed47/spectre-meltdown-checker',
                              'Score': spectre_score
                              }
            spectre_report['Variant 1'] = {'vulnerable': spectre_variant_one['VULNERABLE'],
                                           'cve': spectre_variant_one['CVE']}
            if spectre_variant_one['VULNERABLE']:
                spectre_report['Variant 1']['action'] = spectre_variant_one['INFOS']
            else:
                spectre_report['Variant 1']['action'] = "No actions needed." + spectre_variant_one['INFOS']

            spectre_report['Variant 2'] = {'vulnerable': spectre_variant_two['VULNERABLE'],
                                           'cve': spectre_variant_two['CVE']}
            if spectre_variant_one['VULNERABLE']:
                spectre_report['Variant 2']['action'] = spectre_variant_two['INFOS']
            else:
                spectre_report['Variant 2']['action'] = "No actions needed." + spectre_variant_two['INFOS']

            spectre_report['Variant 3'] = {'vulnerable': spectre_variant_three['VULNERABLE'],
                                           'cve': spectre_variant_three['CVE']}
            if spectre_variant_one['VULNERABLE']:
                spectre_report['Variant 3']['action'] = spectre_variant_three['INFOS']
            else:
                spectre_report['Variant 3']['action'] = "No actions needed." + spectre_variant_three['INFOS']
            return spectre_report
        elif self.output_format == "csv":
            spectre_report_lines = []
            header = "Variant,vulnerable,cve,action\n"
            v1_line = "Variant 1," + str(spectre_variant_one['VULNERABLE']) + "," + spectre_variant_one['CVE'] + "," + \
                      spectre_variant_one['INFOS'] + "\n"
            v2_line = "Variant 2," + str(spectre_variant_two['VULNERABLE']) + "," + spectre_variant_two['CVE'] + "," + \
                      spectre_variant_two['INFOS'] + "\n"
            v3_line = "Variant 3," + str(spectre_variant_three['VULNERABLE']) + "," + spectre_variant_three[
                'CVE'] + "," + spectre_variant_three['INFOS'] + "\n"
            spectre_report_lines.append(header)
            spectre_report_lines.append(v1_line)
            spectre_report_lines.append(v2_line)
            spectre_report_lines.append(v3_line)
            return spectre_report_lines

    def parse_nx_support_report(self):
        nx_score = scorer.get_nx_support_score(self.nx_support_report)
        if self.output_format == "json":
            nx_report = {'Description': 'This simple check verifies only that the CPU supports the nx bit.'
                                        'If this is true, it means that all the executable should also flag '
                                        'the memory segments that do not contain code as non-executable.'
                                        'All modern (64bit) CPUs should support the nx-bit, which allows the Operating '
                                        'systems to flag memory pages as Non-Exec by setting this bit to 1.'
                                        'For 32bit machines, this bit is available only if processor supports PAE.',
                         'Score': nx_score
                         }
            nx_report['nx_supported'] = self.nx_support_report['Nx_support']
            return nx_report
        elif self.output_format == "csv":
            nx_support_lines = []
            nx_support_lines.append("Nx supported by CPU," + str(self.nx_support_report['Nx_support']) + "\n")
            return nx_support_lines

    def parse_aslr_report(self):
        aslr_score = scorer.get_aslr_score(self.aslr_report)
        aslr_dict = {'0': "ASLR is completely disabled. The system is severely at risk.",
                     '1': "ASLR is enabled,but it is not applied to data segments (heap, for example)",
                     '2': "ASLR is enabled and applied also for data segment.",
                     '3': "ASLR is enabled and further patches are applied to randomize also mmap addresses",
                     '4': "ASLR is enabled and advanced patches are applied to improve the mmap randomization."}
        aslr_hard = self.aslr_report['ASLR'][0]['ASLR_hard']
        aslr_soft = self.aslr_report['ASLR'][1]['ASLR_soft']
        if self.output_format == "json":
            aslr_report = {'Description': 'This check verifies that ASLR is in place and also to what extent.'
                                          'The check itself is made in two ways, here called soft and hard.'
                                          'The soft check queries the kernel parameter randomize_va_space via'
                                          'the sysctl command. The hard check instead runs a simple binary that'
                                          'prints out the address of the stack pointer, the address of the system'
                                          'environmental variables and the address returned by a malloc call.'
                                          'This operation is done 10 times and then it is verified whether there are'
                                          'duplicates in the addresses returned.',
                           'Score': aslr_score
                           }

            aslr_report['ASLR_soft_check'] = aslr_dict[aslr_soft]
            aslr_report['ASLR_soft_value'] = aslr_soft
            aslr_report['ASLR_hard_value'] = aslr_hard
            aslr_report['ASLR_hard_check'] = aslr_dict[aslr_hard]
            return aslr_report
        elif self.output_format == "csv":
            aslr_lines = []
            header = "ASLR check,description\n"
            hard_line = "ASLR hard check," + aslr_dict[aslr_hard] + "\n"
            soft_line = "ASLR soft check," + aslr_dict[aslr_soft] + "\n"
            aslr_lines.append(header)
            aslr_lines.append(hard_line)
            aslr_lines.append(soft_line)
            return aslr_lines

        return self.aslr_report

    def parse_elfs_report(self):

        # self.elf_reports is a list of reports for every elf
        if self.output_format == "json":
            global_report = {'Description': 'A set of checks is made on each ELF file. '
                                            'The check includes three main areas: '
                                            '1)NoExec, which consists of three independent tests to verify that the sections'
                                            'of each ELF that do not contain code are NOT flagged as executable.'
                                            'The first test checks if the stack is marked as executable.'
                                            'The second test checks that there are no sections in the whole ELF which are'
                                            'marked both Writable and eXecutable (W^X).'
                                            'The third test checks that rabin2 output on the elf includes the nx flag.'
                                            'rabin2 checks that the GNU_STACK section is not executable, similarly to what'
                                            'is done in the first test.'
                                            '2)Stripped. This test simply verifies if the ELF has been stripped.'
                                            '3)Stack smashing protector. This test is composed of two subtests:'
                                            'The first test checks the output of rabin2 and verifies that the canaries '
                                            'flag is present.'
                                            'The second test uses objdump to disassemble the ELF and verifies that'
                                            'the code contains a call to stack_chk_fail.'}
            if len(self.elf_reports) == 0:
                return global_report
            for elf_report in self.elf_reports:
                noexec_score, stripped_score, canaries_score = scorer.get_elf_score(elf_report)
                elf_score = noexec_score + stripped_score + canaries_score
                single_report = {}
                single_report['sha256'] = elf_report['hash']
                single_report['NoExec'] = {'Stack_executable': elf_report['NoExec'][0]['stack_executable'],
                                           'W^X enforced': elf_report['NoExec'][1]['WX_enforced'],
                                           'nx_flag': elf_report['NoExec'][2]['nx'], 'Score': noexec_score}
                single_report['Stripped'] = {'Binary stripped': elf_report['stripped'], 'Score': stripped_score}
                single_report['Stack_Smashing_Protector'] = {'canaries': elf_report['canaries'][0]['canaries'],
                                                             'stack_chk_fail': elf_report['canaries'][1]['sssp'],
                                                             'Score': canaries_score}
                single_report['ELF score'] = str(elf_score) + "/60"
                global_report[elf_report['filename']] = single_report
            return global_report
        elif self.output_format == "csv":
            elfs_lines = []
            header = "Filename,SHA256,Score(/60),Stack Executable,W^X enforced,NX flag,stripped,canaries,stack_chk_fail\n"
            elfs_lines.append(header)
            if len(self.elf_reports) == 0:
                return elfs_lines
            for elf_report in self.elf_reports:
                noexec_score, stripped_score, canaries_score = scorer.get_elf_score(elf_report)
                elf_score = noexec_score + stripped_score + canaries_score
                line = elf_report['filename'] + "," + elf_report['hash'] + "," + str(elf_score) + "," + str(
                    elf_report['NoExec'][0]['stack_executable']) + "," + str(
                    elf_report['NoExec'][1]['WX_enforced']) + "," + str(elf_report['NoExec'][2]['nx']) + "," + str(
                    elf_report['stripped']) + "," + str(elf_report['canaries'][0]['canaries']) + "," + str(
                    elf_report['canaries'][1]['sssp']) + "\n"
                elfs_lines.append(line)
            return elfs_lines

    def generate_json_report(self):
        ted_report = {'time': str(datetime.now()), 'type': self.scan_type}
        if self.scan_type == "full":
            ted_report['System checks'] = {}
            kpop = self.parse_kernelpop_report()
            spectre = self.parse_spectre_report()
            nx_support = self.parse_nx_support_report()
            aslr = self.parse_aslr_report()
            system_score = kpop['Score'] + spectre['Score'] + nx_support['Score'] + aslr['Score']
            ted_report['System checks']['Kernelpop'] = kpop
            ted_report['System checks']['Spectre_meltdown'] = spectre
            ted_report['System checks']['Nx_support'] = nx_support
            ted_report['System checks']['ASLR'] = aslr
            ted_report['System checks']['System score'] = str(system_score) + "/100"
        ted_report['ELFs'] = self.parse_elfs_report()
        return ted_report

    def generate_csv_report(self):
        lines = []
        if self.scan_type == "full":
            lines.append("Kernelpop result\n")
            lines = lines + self.parse_kernelpop_report()
            lines.append("Spectre and meltdown result\n")
            lines += self.parse_spectre_report()
            lines.append("NX bit support result\n")
            lines += self.parse_nx_support_report()
            lines.append("ASLR result\n")
            lines += self.parse_aslr_report()

        lines.append("ELFs check result\n")
        lines += self.parse_elfs_report()
        return lines

    def print_report(self):
        with open(self.output_file, "w") as file:
            if self.output_format == "json":
                json.dump(self.generate_json_report(), file, sort_keys=True, indent=4)
            elif self.output_format == "csv":
                lines = self.generate_csv_report()
                for line in lines:
                    file.write(line)
