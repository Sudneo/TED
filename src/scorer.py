def get_kernelpop_score(kernelpop_report):
    confirmed = kernelpop_report['report']['confirmed']
    potential = kernelpop_report['report']['potential']
    score = len(confirmed) * 10 + len(potential) * 5
    if score > 30:
        score = 30
    return score


def get_spectre_score(spectre_report):
    spectre_variant_one = spectre_report[0]
    spectre_variant_two = spectre_report[1]
    spectre_variant_three = spectre_report[2]
    score = 0
    if spectre_variant_one['VULNERABLE']:
        score += 10
    if spectre_variant_two['VULNERABLE']:
        score += 10
    if spectre_variant_three['VULNERABLE']:
        score += 10
    return score


def get_aslr_score(aslr_report):
    aslr_hard = int(aslr_report['ASLR'][0]['ASLR_hard'])
    aslr_soft = int(aslr_report['ASLR'][1]['ASLR_soft'])
    value = aslr_soft
    score = 0
    if aslr_hard != aslr_soft:
        # If they are different, score the highest
        if aslr_hard < aslr_soft:
            value = aslr_hard
    if value == 0:
        score = 20
    if value == 1:
        score = 15
    if value == 2:
        score = 5
    if value > 3:
        score = 0
    return score


def get_nx_support_score(nx_report):
    score = 0
    if nx_report['Nx_support']:
        return score
    else:
        score = 20
        return score


def get_elf_score(elf_report):
    score_noexec = 0
    score_canaries = 0
    score_stripped = 0
    stack_exec = elf_report['NoExec'][0]['stack_executable']
    wx = elf_report['NoExec'][1]['WX_enforced']
    nx = elf_report['NoExec'][2]['nx']
    if stack_exec:
        score_noexec += 10
    if not nx:
        score_noexec += 10
    if not wx:
        score_noexec += 10
    stripped = elf_report['stripped']
    if not stripped:
        score_stripped += 10
    canaries = elf_report['canaries'][0]['canaries']
    ssp = elf_report['canaries'][1]['sssp']
    if not canaries:
        score_canaries += 10
    if not ssp:
        score_canaries += 10
    return score_noexec, score_stripped, score_canaries
