import ida_segment
import idc
import idautils

# seg_obj is a object of type segment_t.
seg_obj = ida_segment.getseg(0x96d1)
seg_name = ida_segment.get_segm_name(seg_obj)


print("seg_name:", seg_name)
print("seg_start_ea: {0}\nseg_end_ea: {1}".format(hex(seg_obj.start_ea), hex(seg_obj.end_ea)))
next_seg = ida_segment.get_next_seg(seg_obj.start_ea)
print("Next segment of {0}: {1}".format(seg_name, ida_segment.get_segm_name(next_seg)))

# idautils return an iterator type object, Each item in the list is a segment’s start address.
for seg_ea in idautils.Segments():
    print("{:<14} {:<8} {:<8}"\
        .format(idc.get_segm_name(seg_ea),\
            hex(idc.get_segm_start(seg_ea)),\
            hex(idc.get_segm_end(seg_ea))
            ))