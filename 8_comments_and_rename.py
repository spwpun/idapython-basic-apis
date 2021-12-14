import idc
import idautils
import idaapi


# add comments
ea = idc.here()
idc.set_cmt(ea, "regular comment", 0)
idc.set_cmt(ea, "repeat comment", 1)

# get comments
print("Regular:",idc.get_cmt(ea, 0))
print("Repeat:",idc.get_cmt(ea, 1))

# add func cmt
idc.set_func_cmt(ea, "func cmt test", 1)

# get func cmt
print("func repeat cmt:", idc.get_func_cmt(ea, 1))


# rename
idc.set_name(ea, "test name", idc.SN_NOCHECK)

# get name from a liner address
print("Name:", idc.get_name(ea, 0))
