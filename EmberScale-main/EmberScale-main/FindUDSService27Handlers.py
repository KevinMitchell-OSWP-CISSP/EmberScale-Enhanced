# -*- coding: utf-8 -*-
# @category Automotive Analysis
# @toolbar

from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.model.symbol import SourceType

UDS_SECURITY_IDS = [0x27, 0x2701, 0x2702, 0x2703, 0x2704]

def is_powerpc_branch_instruction(instr):
    try:
        return instr.getMnemonicString().lower().startswith("b") and instr.getFlowType().isConditional()
    except:
        return False

def is_powerpc_cmp_instruction(instr):
    try:
        return instr.getMnemonicString().lower().startswith("cmp")
    except:
        return False

def has_uds_27_constant(instr):
    try:
        for i in range(instr.getNumOperands()):
            val = instr.getScalar(i)
            if val and val.getValue() in UDS_SECURITY_IDS:
                return True
    except:
        pass
    return False

def search_security_access_handlers():
    monitor = ConsoleTaskMonitor()
    listing = currentProgram.getListing()
    funcs = currentProgram.getFunctionManager().getFunctions(True)
    tagged = []

    print("Searching PowerPC binary for possible UDS 0x27 SecurityAccess handlers...")

    for func in funcs:
        monitor.checkCanceled()
        try:
            inst_iter = listing.getInstructions(func.getBody(), True)
            has_cmp_27 = False
            has_branch = False

            while inst_iter.hasNext():
                inst = inst_iter.next()

                if is_powerpc_cmp_instruction(inst) and has_uds_27_constant(inst):
                    has_cmp_27 = True
                elif is_powerpc_branch_instruction(inst):
                    has_branch = True

                if has_cmp_27 and has_branch:
                    comment = func.getComment()
                    if not comment or "SecurityAccess" not in comment:
                        func.setComment("Possible UDS SecurityAccess (0x27) handler — cmp + branch logic detected")
                    try:
                        func.setName("possible_security_access_{}".format(func.getEntryPoint()), SourceType.USER_DEFINED)
                    except:
                        pass
                    tagged.append(func)
                    break

        except:
            continue

    return tagged

def main():
    results = search_security_access_handlers()

    print("\n=== Potential PowerPC UDS 0x27 Handlers ===")
    if results:
        for func in results:
            print("- {} @ {}".format(func.getName(), func.getEntryPoint()))
        print("Tagged {} functions with comments.".format(len(results)))
    else:
        print("No likely handlers found. Consider checking manually around seed/key routines or CAN RX dispatch logic.")

if __name__ == "__main__":
    main()
