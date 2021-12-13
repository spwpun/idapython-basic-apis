from ida_ida import INF_MAX_EA, INF_MIN_EA
import idc
import idaapi

# get current cursor of address
curr_ea = idc.get_screen_ea()
curr_ea_0 = idc.here()
print("curr_ea by get_screen_ea(): ", hex(curr_ea))
print("curr_ea by here():          ", hex(curr_ea_0))

# get the min ea and the max ea with new api.
min_ea = idc.get_inf_attr(INF_MIN_EA)
max_ea = idc.get_inf_attr(INF_MAX_EA)
print("min_ea: {}, max_ea: {}".format(hex(min_ea), hex(max_ea)))

# get the element of the disassembly output line.
disasm_line = idc.generate_disasm_line(curr_ea, flags = 0)
mnem = idc.print_insn_mnem(curr_ea)
first_op = idc.print_operand(curr_ea, 0)
second_op = idc.print_operand(curr_ea, 1)
print("disasm_line: {:<10}\nmnem:        {:<10}\nfirst_op:    {:<10}\nsecond_op:   {}"\
    .format(disasm_line, mnem, first_op, second_op))
