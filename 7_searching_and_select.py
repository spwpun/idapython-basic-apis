from sys import flags
from ida_idp import reg_access_t
import idc
import idaapi
import idautils
import ida_search
import ida_bytes

# searching
min_ea = idc.here()
max_ea = idc.get_inf_attr(idc.INF_MAX_EA)
pattern = "\x55\x8B\xEC"

# matched_addr = ida_search.find_binary(min_ea, max_ea, pattern, idc.SEARCH_DOWN, 16)
# if matched_addr != idc.BADADDR:
#     print(hex(matched_addr), idc.generate_disasm_line(matched_addr, flags = 0))

print("---------find_code------------")
matched_addr = ida_search.find_code(min_ea, idc.SEARCH_DOWN)
if matched_addr != idc.BADADDR:
    print(hex(matched_addr), idc.generate_disasm_line(matched_addr, flags = 0))

print("---------find_data------------")
matched_addr = ida_search.find_data(min_ea, idc.SEARCH_DOWN)
if matched_addr != idc.BADADDR:
    print(hex(matched_addr), idc.generate_disasm_line(matched_addr, flags = 0))

print("---------find_defined---------")
matched_addr = ida_search.find_defined(min_ea, idc.SEARCH_DOWN)
if matched_addr != idc.BADADDR:
    print(hex(matched_addr), idc.generate_disasm_line(matched_addr, flags = 0))

print("---------find_error-----------")
matched_addr = ida_search.find_error(min_ea, idc.SEARCH_DOWN)
if matched_addr != idc.BADADDR:
    # print(hex(matched_addr), idc.generate_disasm_line(matched_addr, flags = 0))
    for adr in matched_addr:
        print(hex(adr))

print("---------find_imm-------------")
matched_addr = ida_search.find_imm(min_ea, idc.SEARCH_DOWN, 0xE0)
if matched_addr != idc.BADADDR:
    # print(hex(matched_addr), idc.generate_disasm_line(matched_addr, flags = 0))
    for adr in matched_addr:
        if min_ea < adr < max_ea:
            print(hex(adr), idc.generate_disasm_line(adr, flags = 0))

print("---------find_text------------") # find text in all, comments、code、data
matched_addr = ida_search.find_text(min_ea, 0, 0, r"dhcp", idc.SEARCH_DOWN | idc.SEARCH_CASE | idc.SEARCH_REGEX)
if matched_addr != idc.BADADDR:
    print(hex(matched_addr), idc.generate_disasm_line(matched_addr, flags = 0))
    print(idc.get_cmt(matched_addr, 0))
    print(idc.get_name(matched_addr, 0))

print("---------find_binary------------")
matched_addr = ida_search.find_binary(min_ea, max_ea, "41 54", 16, idc.SEARCH_DOWN)
if matched_addr != idc.BADADDR:
    print(hex(matched_addr), idc.generate_disasm_line(matched_addr, flags = 0))

print("---------find_reg_access------")
outinfo = reg_access_t()
matched_addr = ida_search.find_reg_access(outinfo, min_ea, max_ea, "rax", idc.SEARCH_DOWN)
if matched_addr != idc.BADADDR:
    print(hex(matched_addr), idc.generate_disasm_line(matched_addr, flags = 0))
print("Out:", outinfo.range)

# selecting
start = idc.read_selection_start()
end = idc.read_selection_end()
print("Selection:",hex(start), hex(end))