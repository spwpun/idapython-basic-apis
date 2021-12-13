import idc
import ida_funcs
import idautils

# iterate the all named functions, Functions return the iterate object of all functions, each item is the function start ea.
for func_start_ea in idautils.Functions():
    print(hex(func_start_ea), idc.get_func_name(func_start_ea))

# get the boundaries of a func, get_func api returns a class of func_t.
curr_ea = idc.here()
func = ida_funcs.get_func(curr_ea)
curr_func_name = idc.get_func_name(curr_ea)
func_start_ea = func.start_ea
func_end_ea = func.end_ea
print("Func name:",curr_func_name," Start: 0x%x, End: 0x%x."%(func_start_ea, func_end_ea))

# access surrounding functions, this two apis also return the start address of the specific func.
prev_func = idc.get_prev_func(curr_ea)
next_func = idc.get_next_func(curr_ea)
print("Prev func: %s 0x%x"%(idc.get_func_name(prev_func), prev_func))
print("Next func: %s 0x%x"%(idc.get_func_name(next_func), next_func))

# iterate the items in a function.
for func_ea in idautils.FuncItems(func_start_ea):
    line = idc.generate_disasm_line(func_ea, flags = 0)
    print(hex(func_ea), line)

# get the function flags to identify what type of the function.
func_flags = idc.get_func_flags(curr_ea)
if func_flags & ida_funcs.FUNC_FAR:
    print(curr_func_name, "FUNC_FAR")
if func_flags & ida_funcs.FUNC_BOTTOMBP:
    print(curr_func_name, "FUNC_BOTTOMBP")
if func_flags & ida_funcs.FUNC_FRAME:
    print(curr_func_name, "FUNC_FRAME")
if func_flags & ida_funcs.FUNC_FUZZY_SP:
    print(curr_func_name, "FUNC_FUZZY_SP")
if func_flags & ida_funcs.FUNC_HIDDEN:
    print(curr_func_name, "FUNC_HIDDEN")
if func_flags & ida_funcs.FUNC_LIB:
    print(curr_func_name, "FUNC_LIB")
if func_flags & ida_funcs.FUNC_LUMINA:
    print(curr_func_name, "FUNC_LUMINA")
if func_flags & ida_funcs.FUNC_NORET:
    print(curr_func_name, "FUNC_NORET")
if func_flags & ida_funcs.FUNC_NORET_PENDING:
    print(curr_func_name, "FUNC_NORET_PENDING")
if func_flags & ida_funcs.FUNC_PROLOG_OK:
    print(curr_func_name, "FUNC_PROLOG_OK")
if func_flags & ida_funcs.FUNC_PURGED_OK:
    print(curr_func_name, "FUNC_PURGED_OK")
if func_flags & ida_funcs.FUNC_SP_READY:
    print(curr_func_name, "FUNC_SP_READY")
if func_flags & ida_funcs.FUNC_TAIL:
    print(curr_func_name, "FUNC_TAIL")
if func_flags & ida_funcs.FUNC_THUNK:
    print(curr_func_name, "FUNC_THUNK")
if func_flags & ida_funcs.FUNC_USERFAR:
    print(curr_func_name, "FUNC_USERFAR")
if func_flags & ida_funcs.FUNC_STATICDEF:
    print(curr_func_name, "FUNC_STATICDEF")
