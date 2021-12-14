import idc
import idaapi
import idautils


# accessing raw data
ea = idc.here()
print(hex(idc.get_wide_byte(ea)))
print(hex(idc.get_wide_word(ea)))
print(hex(idc.get_wide_dword(ea)))
print(hex(idc.get_qword(ea)))

print(idc.get_bytes(ea, 10))


# Patching
idc.patch_byte(ea, 0x90)
idc.patch_word(ea, 0x90f6)

