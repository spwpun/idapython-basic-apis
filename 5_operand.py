from ida_ua import insn_t
import idautils
import idaapi
import idc

# create a Python dictionary that contains all the displacements as keys and each key will have a list of the addresses
displace = {}
print_displace = False
min_ea = idc.get_inf_attr(idc.INF_MIN_EA)
max_ea = idc.get_inf_attr(idc.INF_MAX_EA)

for func in idautils.Functions():
    flags = idc.get_func_flags(func)
    if flags & idc.FUNC_THUNK or flags & idc.FUNC_LIB:
        continue

    dism_addrs = idautils.FuncItems(func)
    for curr_addr in dism_addrs:
        op = None
        index = None
        insn = insn_t()
        # another way to get the operand
        idaapi.decode_insn(insn, curr_addr)
        # here the Op1 is op_t class
        if insn.Op1.type == idc.o_displ:
            op = 1
        if insn.Op2.type == idc.o_displ:
            op = 2
        # make the memory reference to offset, maybe to mannaul set the base to a larger value be better
        if insn.Op1.type == idc.o_imm:
            if min_ea < insn.Op1.value < max_ea:
                idc.op_plain_offset(curr_addr, 0, 0)
                print("op_plain_offset here()", hex(curr_addr))
        if insn.Op2.type == idc.o_imm:
            if min_ea < insn.Op2.value < max_ea:
                idc.op_plain_offset(curr_addr, 1, 0)
                print("op_plain_offset here()", hex(curr_addr))
        if op == None:
            continue
        
        # This is a quick way to determine if the register bp , ebp or rbp is present in the operand.
        if "bp" in idc.print_operand(curr_addr, 0) or \
            "bp" in idc.print_operand(curr_addr, 1):
            if op == 1:
                index = (~(int(insn.Op1.addr) - 1) & 0xFFFFFFFF)
            else:
                index = (~(int(insn.Op2.addr) - 1) & 0xFFFFFFFF)
        else:
            if op == 1:
                index = int(insn.Op1.addr)
            else:
                index = int(insn.Op2.addr)
            if index:
                if index not in displace.keys():
                    displace[index] = []
                else:
                    displace[index].append(curr_addr)

if print_displace:
    print("Key                 :   Value  ")
    for key, value in displace.items():
        print("{:<20}".format(hex(key)), end=":")
        for v in value:
            print(hex(v) + " ", end="")
        print("")    


