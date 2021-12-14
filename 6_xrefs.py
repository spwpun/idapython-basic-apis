from sys import flags
import idc
import idaapi
import idautils

# locate the func address by name
func_addr = idc.get_name_ea_simple("dhcp_discover")

print(hex(func_addr), idc.generate_disasm_line(func_addr, flags = 0))
print("-----CodeRefsTo--------")
for addr in idautils.CodeRefsTo(func_addr, 0):
    print(hex(addr), idc.generate_disasm_line(addr, flags = 0))
print("------CodeRefsFrom--------")
for addr in idautils.CodeRefsFrom(func_addr, 0):
    print(hex(addr), idc.generate_disasm_line(addr, flags = 0))

print("-----DataRefsTo---------")
data_ea = 0x000055550003B686
print(hex(data_ea), idc.generate_disasm_line(data_ea, flags = 0))
for addr in idautils.DataRefsTo(data_ea):
    print(hex(addr), idc.generate_disasm_line(addr, flags = 0))
print("-----DataRefsFrom---------")
for addr in idautils.DataRefsFrom(0x55550000ccc7):
    print(hex(addr), idc.generate_disasm_line(addr, flags = 0))

print("------XrefsTo-------")
for xref in idautils.XrefsTo(func_addr, 0):
    print(idautils.XrefTypeName(xref.type), hex(xref.frm), hex(xref.to))
    print(idc.generate_disasm_line(xref.frm, flags = 0))
    print(idc.generate_disasm_line(xref.to, flags = 0))

print("------XrefsFrom--------")
for addr in idautils.XrefsFrom(func_addr, 0):
    print(idautils.XrefTypeName(xref.type), hex(xref.frm), hex(xref.to))
    print(idc.generate_disasm_line(xref.frm, flags = 0))
    print(idc.generate_disasm_line(xref.to, flags = 0))