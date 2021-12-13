from sys import flags
import idc
import idautils

# get prev_instruction and next_instruction addresses, `prev_head` is not the same as `prev_addr`.
ea = idc.here()
curr_line = idc.generate_disasm_line(ea, flags = 0)
prev_ea = idc.prev_head(ea)
prev_line = idc.generate_disasm_line(prev_ea, flags = 0)
next_ea = idc.next_head(ea)
next_line = idc.generate_disasm_line(next_ea, flags = 0)
print("prev: {:<10} {} ".format(hex(prev_ea), prev_line))
print("curr: {:<10} {} ".format(hex(ea), curr_line))
print("next: {:<10} {} ".format(hex(next_ea), next_line))

# find the simple indirect function call
for func in idautils.Functions():
    flags = idc.get_func_flags(func)
    # ingore the lib function and thunk function
    if flags & idc.FUNC_LIB or flags & idc.FUNC_THUNK:
        continue
    dism_addrs = idautils.FuncItems(func)
    for insn_addr in dism_addrs:
        mnem = idc.print_insn_mnem(insn_addr)
        if mnem == "call" or mnem == "jmp":
            op = idc.get_operand_type(insn_addr, 0)
            if op == idc.o_reg:
                print("Indirect function call:", hex(insn_addr), idc.generate_disasm_line(insn_addr, flags = 0))

