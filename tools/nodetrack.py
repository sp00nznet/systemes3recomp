"""Track the register holding &node[i] through the poll function and report
every offset it is used at, and whether the value is then dereferenced."""
import pefile
import capstone
from capstone.x86 import X86_OP_MEM, X86_OP_REG

pe = pefile.PE(r'G:\recomp\arcade\systemes3\_bp\swarc.exe', fast_load=True)
base = pe.OPTIONAL_HEADER.ImageBase
img = pe.get_memory_mapped_image()
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
md.detail = True

START, END = 0x1409e0700, 0x1409e2529
code = img[START - base:END - base]

# the node pointer lands in rax at the call, then is moved somewhere
tainted = set()
loaded_from = {}          # reg -> offset it was loaded from the node
uses = {}                 # offset -> set of mnemonics/sizes
derefs = {}               # offset -> True if the loaded value is dereferenced

for ins in md.disasm(code, START):
    if ins.mnemonic == 'call':
        if ins.op_str.endswith('140003800'):
            tainted = {'rax'}
        else:
            # Any other call clobbers the volatiles; keeping taint across one
            # is what made a C++ `this` look like a node record.
            tainted -= {'rax', 'rcx', 'rdx', 'r8', 'r9', 'r10', 'r11'}
        loaded_from.clear()
        continue
    if not tainted:
        continue
    r = [ins.reg_name(x) for x in ins.regs_read]
    w = [ins.reg_name(x) for x in ins.regs_write]

    # propagate the node pointer through plain moves
    if ins.mnemonic == 'mov' and len(ins.operands) == 2:
        d, s = ins.operands
        if d.type == X86_OP_REG and s.type == X86_OP_REG:
            if ins.reg_name(s.reg) in tainted:
                tainted.add(ins.reg_name(d.reg))
                continue
            if ins.reg_name(d.reg) in tainted:
                tainted.discard(ins.reg_name(d.reg))

    for op in ins.operands:
        if op.type != X86_OP_MEM or not op.mem.base:
            continue
        b = ins.reg_name(op.mem.base)
        if b in tainted:
            off = op.mem.disp
            uses.setdefault(off, set()).add('%s/%d' % (ins.mnemonic, op.size))
            # if this load's destination is later used as a base, it is a pointer
            if ins.mnemonic in ('mov', 'movzx', 'movsxd') and \
                    ins.operands[0].type == X86_OP_REG:
                loaded_from[ins.reg_name(ins.operands[0].reg)] = off
        elif b in loaded_from:
            derefs[loaded_from[b]] = True

print('node record fields touched in %#x..%#x:' % (START, END))
for off in sorted(uses):
    print('  +%-6s %-28s %s' % (hex(off), ','.join(sorted(uses[off])),
                                'POINTER (dereferenced)' if derefs.get(off) else ''))
