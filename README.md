# ZenUtils

Collection of tools to create, dump and manipulate Zen microcode updates. Currently supported are Zen1 and Zen2 microcode variants, and basic instructions: arithmetic, logic, shift, load, store, conditional microcode branch. See [zen_base.yaml](arch/zen_base.yaml) for field descriptions, operations and flags.

```nasm
mov reg1, 0x4242
add reg1, reg3, 0x42
xor.zcZCnd reg1, reg3, 0x42
jz.z 0x1fc0
mov msr2:[reg15], reg14
mov.b reg14, ls:[reg15 + reg14 + 0x20]
```

## Tools

### Assembler
Usage:
```
$ python asm.py --arch Zen2 "add reg1, reg3, 0x42"

; 0x382F9C108C080042 0011100000101111100111000001000010001100000010000000000001000010
```

Inspect fields:
```
$ python asm.py --arch Zen2 "add reg1, reg3, 0x42" -i

; 0x382F9C108C080042 0011100000101111100111000001000010001100000010000000000001000010
; imm16       :   66                                                 0000000001000010
; imm_signed  :    0                                                0
; imm_mode    :    1                                             1
; rt          :    0                                       00000
; rs          :    3                                  00011
; rd          :    1                             00001
; rmod        :    1                            1
; read_zf     :    0                           0
; read_cf     :    0                          0
; write_zf    :    0                         0
; write_cf    :    0                        0
; native_flags:    0                       0
; size_flags  :    7                    111
; load        :    0                   0
; store       :    0                  0
; operation   :   95          01011111
; exec_unit   :    7   111
```

Python usage:
```python
from arch.registry import Registry
from asm import assemble_single

zen2_spec = Registry().get('Zen2')
word = assemble_single(zen2_spec, "add reg1, reg3, 0x42", label_addrs = {})
print(f"0x{word:016X}")

```

### Macro Assembler
The macro assembler converts microcode assembly files to microcode updates binaries. It supports labels and takes care of placing instructions and quads as needed. Use the `-d` flag to get text-based debug output instead.

> Note
> The microcode updates must be signed (f.i., with Zentool) before they are accepted by Zen CPUs.

For examples see the `samples` folder. Usage:

```
$ python masm.py samples/strlen.s -o cpu00870F10_strlen_shld.bin

; Packages used: 3 of 64

$ zentool resign cpu00870F10_strlen_shld.bin
```

### Disassembler
Usage:

```
$ python disasm.py --arch Zen2 0x382F9C108C080042

add reg1, reg3, 0x42
```

Inspect fields:

```
$ python disasm.py --arch Zen2 0x382F9C108C080042 -i

; 0x382F9C108C080042 0011100000101111100111000001000010001100000010000000000001000010
; imm16       :   66                                                 0000000001000010
; imm_signed  :    0                                                0
; imm_mode    :    1                                             1
; rt          :    0                                       00000
; rs          :    3                                  00011
; rd          :    1                             00001
; rmod        :    1                            1
; read_zf     :    0                           0
; read_cf     :    0                          0
; write_zf    :    0                         0
; write_cf    :    0                        0
; native_flags:    0                       0
; size_flags  :    7                    111
; load        :    0                   0
; store       :    0                  0
; operation   :   95          01011111
; exec_unit   :    7   111
add reg1, reg3, 0x42
```

Disassemble a whole binary microcode update file:
```
$ python disasm.py --arch Zen2 -u cpu00870F10_strlen_shld.bin

; Header
.date 0x07112025
.revision 0x08701040
.format 0x8004
...

; Match Register
.match_reg 0 0x00000420
.match_reg 1 0x00000000
.match_reg 2 0x00000000
...

; Instruction Packages
; Slot 0 @ 0x1fc0 (0x38501c1782000000 0x387f9c1000000000 0x387f9c1000000000 0x387f9c1000000000 0x00000001)
mov reg15, rax
nop
nop
nop
.sw_continue

; Slot 1 @ 0x1fc1 (0x286f20173c009800 0x38581c9039c00000 0x20021c2000081fc2 0x382f9c17bc080001 0x00121fc1)
mov.b reg14, ls:[reg15]
and.Z reg0, reg14, reg14
jz.z 0x1fc2
add reg15, reg15, 0x1
.sw_branch 0x1fc1 ; (immediately)

; Slot 2 @ 0x1fc2 (0x38281c19be000000 0x387f9c1000000000 0x387f9c1000000000 0x387f9c1000000000 0x03100082)
sub rbx, reg15, rax
nop
nop
nop
.sw_complete ; (immediately)
...
```

lifter miasm ir:
```
$ python3 lifter.py
=== Zen Microcode Lifter v2.0 ===
Based on full Zen architecture specification

Architecture initialized:
  Registers: 37 total
  Segments: 6
  PC: PC

--- Decoding: add.n reg1, reg3, reg7 ---
Decoding instruction: add.n reg1, reg3, reg7
✓ Decoded as: add.n reg1, reg3, reg7

--- Decoding: add reg0, reg0, reg0 ---
Decoding instruction: add reg0, reg0, reg0
✓ Decoded as: add reg0, reg0, reg0

--- Decoding: add reg1, reg3, 0x42 ---
Decoding instruction: add reg1, reg3, 0x42
✓ Decoded as: add reg1, reg3, 66

--- Decoding: add.n reg1, reg3, 0x42 ---
Decoding instruction: add.n reg1, reg3, 0x42
✓ Decoded as: add.n reg1, reg3, 66

--- Decoding: xor.zcZCnd reg1, reg3, 0x42 ---
Decoding instruction: xor.zcZCnd reg1, reg3, 0x42
✓ Decoded as: xor.zcZCnd reg1, reg3, 66

--- Decoding: jz.z 0x1fc0 ---
Decoding instruction: jz.z 0x1fc0
✓ Decoded as: jz.z 8128

--- Decoding: jge 0x1fe2 ---
Decoding instruction: jge 0x1fe2
✓ Decoded as: jge 8162

--- Decoding: mov r13, cpuid:[r12] ---
Decoding instruction: mov r13, cpuid:[r12]
✓ Decoded as: mov r13, cpuid:[r12]

--- Decoding: mov msr2:[reg15], reg14 ---
Decoding instruction: mov msr2:[reg15], reg14
✓ Decoded as: mov msr2:[reg15], reg14

--- Decoding: mov.b reg14, ls:[reg15 + reg14 + 0x20] ---
Decoding instruction: mov.b reg14, ls:[reg15 + reg14 + 0x20]
✓ Decoded as: mov.b reg14, ls:[reg15 + reg14]

--- Decoding: mov reg1, reg7 ---
Decoding instruction: mov reg1, reg7
✓ Decoded as: mov reg1, reg7

--- Decoding: mov reg1, 0x4242 ---
Decoding instruction: mov reg1, 0x4242
✓ Decoded as: mov reg1, 16962

Successfully decoded 12 instructions
IRAZen initialized with IRDst: PC

=== Processing regop instruction: add.n at 0x0 ===
Processing instruction: add.n
Arithmetic sizes: dst=64, src1=64, src2=64
Generated 2 expressions
  0: REG1 = REG3 + REG7
  1: PC = 0x8
✓ Created IR block for add.n

=== Processing regop instruction: add at 0x8 ===
Processing instruction: add
Arithmetic sizes: dst=64, src1=64, src2=64
Generated 2 expressions
  0: REG0 = REG0 + REG0
  1: PC = 0x10
✓ Created IR block for add

=== Processing regop instruction: add at 0x10 ===
Processing instruction: add
Arithmetic sizes: dst=64, src1=64, src2=64
Generated 2 expressions
  0: REG1 = REG3 + 0x42
  1: PC = 0x18
✓ Created IR block for add

=== Processing regop instruction: add.n at 0x18 ===
Processing instruction: add.n
Arithmetic sizes: dst=64, src1=64, src2=64
Generated 2 expressions
  0: REG1 = REG3 + 0x42
  1: PC = 0x20
✓ Created IR block for add.n

=== Processing regop instruction: xor.zcZCnd at 0x20 ===
Processing instruction: xor.zcZCnd
Logic sizes: dst=32, src1=32, src2=32
Generated 4 expressions
  0: REG1 = REG3 ^ 0x42
  1: NCF = 0x0
  2: NZF = (REG3 ^ 0x42) == 0x0
  3: PC = 0x28
✓ Created IR block for xor.zcZCnd

=== Processing brop instruction: jz.z at 0x28 ===
Processing instruction: jz.z
Generated 0 expressions
✗ No IR expressions generated

=== Processing brop instruction: jge at 0x30 ===
Processing instruction: jge
Generated 0 expressions
✗ No IR expressions generated

=== Processing regop instruction: mov at 0x38 ===
Processing instruction: mov
Generated 1 expressions
  0: PC = 0x40
✓ Created IR block for mov

=== Processing regop instruction: mov at 0x40 ===
Processing instruction: mov
Generated 1 expressions
  0: PC = 0x48
✓ Created IR block for mov

=== Processing regop instruction: mov.b at 0x48 ===
Processing instruction: mov.b
Generated 1 expressions
  0: PC = 0x50
✓ Created IR block for mov.b

=== Processing regop instruction: mov at 0x50 ===
Processing instruction: mov
MOV sizes: dst=64, src=64
Generated 2 expressions
  0: REG1 = REG7
  1: PC = 0x58
✓ Created IR block for mov

=== Processing regop instruction: mov at 0x58 ===
Processing instruction: mov
MOV sizes: dst=64, src=64
Generated 2 expressions
  0: REG1 = 0x4242
  1: PC = 0x60
✓ Created IR block for mov

==================================================
Generated Zen Microcode IR
==================================================

Block at loc_key_0:
  AssignBlock 0:
    REG1
    PC

Block at loc_key_8:
  AssignBlock 0:
    REG0
    PC

Block at loc_key_16:
  AssignBlock 0:
    REG1
    PC

Block at loc_key_24:
  AssignBlock 0:
    REG1
    PC

Block at loc_key_32:
  AssignBlock 0:
    REG1
    NCF
    NZF
    PC

Block at loc_key_56:
  AssignBlock 0:
    PC

Block at loc_key_64:
  AssignBlock 0:
    PC

Block at loc_key_72:
  AssignBlock 0:
    PC

Block at loc_key_80:
  AssignBlock 0:
    REG1
    PC

Block at loc_key_88:
  AssignBlock 0:
    REG1
    PC

==================================================
SUMMARY
==================================================
✓ Instructions processed: 12
✓ IR blocks created: 10
✓ Total IR assignments: 10
✓ Lifter completed successfully!
```

```
============================================================
ZEN MICROCODE SECURITY ANALYZER v6.0
Universal IR Analysis - Assignment Reconstruction
============================================================


Architecture initialized:
  Registers: 43 total
  Segments: 6
  PC: PC

=== PROCESSING 34 MICROCODE EXAMPLES ===

--- Decoding [1/34]: add.n reg1, reg3, reg7 ---
Decoding instruction: add.n reg1, reg3, reg7
✓ Decoded as: add.n reg1, reg3, reg7

--- Decoding [2/34]: mov r13, cpuid:[r12] ---
Decoding instruction: mov r13, cpuid:[r12]
✓ Decoded as: mov r13, cpuid:[r12]

--- Decoding [3/34]: mov msr2:[reg15], reg14 ---
Decoding instruction: mov msr2:[reg15], reg14
✓ Decoded as: mov msr2:[reg15], reg14

--- Decoding [4/34]: jz.z 0x1fc0 ---
Decoding instruction: jz.z 0x1fc0
✓ Decoded as: jz.z 8128

--- Decoding [5/34]: mov.b reg14, ls:[reg15 + reg14 + 0x20] ---
Decoding instruction: mov.b reg14, ls:[reg15 + reg14 + 0x20]
✓ Decoded as: mov.b reg14, ls:[reg15 + reg14 + 32]

--- Decoding [6/34]: mov reg8, ls:[reg12 + 0x10] ---
Decoding instruction: mov reg8, ls:[reg12 + 0x10]
✓ Decoded as: mov reg8, ls:[reg12 + 16]

--- Decoding [7/34]: mov msr1:[reg8], reg8 ---
Decoding instruction: mov msr1:[reg8], reg8
✓ Decoded as: mov msr1:[reg8], reg8

--- Decoding [8/34]: mov reg9, ls:[reg15 + reg14 + 0x100] ---
Decoding instruction: mov reg9, ls:[reg15 + reg14 + 0x100]
✓ Decoded as: mov reg9, ls:[reg15 + reg14 + 256]

--- Decoding [9/34]: mov msr2:[reg9 + 0x8], reg9 ---
Decoding instruction: mov msr2:[reg9 + 0x8], reg9
✓ Decoded as: mov msr2:[reg9 + 8], reg9

--- Decoding [10/34]: mov reg10, ls:[reg12] ---
Decoding instruction: mov reg10, ls:[reg12]
✓ Decoded as: mov reg10, ls:[reg12]

--- Decoding [11/34]: mov msr2:[reg10], reg10 ---
Decoding instruction: mov msr2:[reg10], reg10
✓ Decoded as: mov msr2:[reg10], reg10

--- Decoding [12/34]: mov reg11, ls:[reg13 + 0x20] ---
Decoding instruction: mov reg11, ls:[reg13 + 0x20]
✓ Decoded as: mov reg11, ls:[reg13 + 32]

--- Decoding [13/34]: xor reg11, reg11, reg7 ---
Decoding instruction: xor reg11, reg11, reg7
✓ Decoded as: xor reg11, reg11, reg7

--- Decoding [14/34]: mov msr1:[reg15], reg11 ---
Decoding instruction: mov msr1:[reg15], reg11
✓ Decoded as: mov msr1:[reg15], reg11

--- Decoding [15/34]: mov reg12, ls:[reg14 + reg15 + 0x40] ---
Decoding instruction: mov reg12, ls:[reg14 + reg15 + 0x40]
✓ Decoded as: mov reg12, ls:[reg14 + reg15 + 64]

--- Decoding [16/34]: mov reg13, ls:[reg15 + 0x60] ---
Decoding instruction: mov reg13, ls:[reg15 + 0x60]
✓ Decoded as: mov reg13, ls:[reg15 + 96]

--- Decoding [17/34]: xor reg12, reg12, reg13 ---
Decoding instruction: xor reg12, reg12, reg13
✓ Decoded as: xor reg12, reg12, reg13

--- Decoding [18/34]: xor reg12, reg12, 0x42 ---
Decoding instruction: xor reg12, reg12, 0x42
✓ Decoded as: xor reg12, reg12, 66

--- Decoding [19/34]: mov msr2:[reg12], reg12 ---
Decoding instruction: mov msr2:[reg12], reg12
✓ Decoded as: mov msr2:[reg12], reg12

--- Decoding [20/34]: mov reg14, ls:[rax + rbx] ---
Decoding instruction: mov reg14, ls:[rax + rbx]
✓ Decoded as: mov reg14, ls:[rax + rbx]

--- Decoding [21/34]: xor reg14, reg14, rcx ---
Decoding instruction: xor reg14, reg14, rcx
✓ Decoded as: xor reg14, reg14, rcx

--- Decoding [22/34]: mov msr2:[reg14], reg14 ---
Decoding instruction: mov msr2:[reg14], reg14
✓ Decoded as: mov msr2:[reg14], reg14

--- Decoding [23/34]: mov reg15, msr1:[reg10] ---
Decoding instruction: mov reg15, msr1:[reg10]
✓ Decoded as: mov reg15, msr1:[reg10]

--- Decoding [24/34]: mov vs:[reg15], reg15 ---
Decoding instruction: mov vs:[reg15], reg15
✓ Decoded as: mov vs:[reg15], reg15

--- Decoding [25/34]: mov reg0, cpuid:[reg11] ---
Decoding instruction: mov reg0, cpuid:[reg11]
✓ Decoded as: mov reg0, cpuid:[reg11]

--- Decoding [26/34]: mov reg1, msr1:[reg12] ---
Decoding instruction: mov reg1, msr1:[reg12]
✓ Decoded as: mov reg1, msr1:[reg12]

--- Decoding [27/34]: xor reg0, reg0, reg1 ---
Decoding instruction: xor reg0, reg0, reg1
✓ Decoded as: xor reg0, reg0, reg1

--- Decoding [28/34]: mov ls:[rax], reg0 ---
Decoding instruction: mov ls:[rax], reg0
✓ Decoded as: mov ls:[rax], reg0

--- Decoding [29/34]: mov reg2, ucode:[reg13] ---
Decoding instruction: mov reg2, ucode:[reg13]
✓ Decoded as: mov reg2, ucode:[reg13]

--- Decoding [30/34]: xor reg2, reg2, reg11 ---
Decoding instruction: xor reg2, reg2, reg11
✓ Decoded as: xor reg2, reg2, reg11

--- Decoding [31/34]: mov ucode:[reg2], reg2 ---
Decoding instruction: mov ucode:[reg2], reg2
✓ Decoded as: mov ucode:[reg2], reg2

--- Decoding [32/34]: mov reg3, ls:[reg14 + reg15] ---
Decoding instruction: mov reg3, ls:[reg14 + reg15]
✓ Decoded as: mov reg3, ls:[reg14 + reg15]

--- Decoding [33/34]: add reg3, reg3, 0x1000 ---
Decoding instruction: add reg3, reg3, 0x1000
✓ Decoded as: add reg3, reg3, 4096

--- Decoding [34/34]: mov msr2:[reg3], reg3 ---
Decoding instruction: mov msr2:[reg3], reg3
✓ Decoded as: mov msr2:[reg3], reg3

Successfully decoded 34 instructions
IRAZen initialized with IRDst: PC

=== Processing regop instruction: add.n at 0x0 ===
Processing instruction: add.n
Instruction type: regop
Processing RegOp: add with 3 operands
Generated 2 expressions
  0: REG1 = REG3 + REG7
  1: PC = 0x8
✓ Created IR block for add.n

=== Processing ldop instruction: mov at 0x8 ===
Processing instruction: mov
Instruction type: ldop
Processing LdOp with 2 operands
Built segmented memory: CPUID:[R12] -> @64[CPUID + R12]
Load operation: R13 = @64[CPUID + R12]
Generated 2 expressions
  0: R13 = @64[CPUID + R12]
  1: PC = 0x10
✓ Created IR block for mov

=== Processing stop instruction: mov at 0x10 ===
Processing instruction: mov
Instruction type: stop
Processing StOp with 2 operands
Built segmented memory: MSR2:[REG15] -> @64[MSR2 + REG15]
Store operation: @64[MSR2 + REG15] = REG14
Generated 2 expressions
  0: @64[MSR2 + REG15] = REG14
  1: PC = 0x18
✓ Created IR block for mov

=== Processing brop instruction: jz.z at 0x18 ===
Processing instruction: jz.z
Instruction type: brop
Processing BrOp: jz with 1 operands
Generated 1 expressions
  0: PC = 0x20
✓ Created IR block for jz.z

=== Processing ldop instruction: mov.b at 0x20 ===
Processing instruction: mov.b
Instruction type: ldop
Processing LdOp with 2 operands
Built segmented memory: LS:[REG15 + REG14 + 0x20] -> @8[LS + REG15 + REG14 + 0x20]
Load operation: REG14 = @8[LS + REG15 + REG14 + 0x20]
Generated 2 expressions
  0: REG14 = @8[LS + REG15 + REG14 + 0x20]
  1: PC = 0x28
✓ Created IR block for mov.b

=== Processing ldop instruction: mov at 0x28 ===
Processing instruction: mov
Instruction type: ldop
Processing LdOp with 2 operands
Built segmented memory: LS:[REG12 + 0x10] -> @64[LS + REG12 + 0x10]
Load operation: REG8 = @64[LS + REG12 + 0x10]
Generated 2 expressions
  0: REG8 = @64[LS + REG12 + 0x10]
  1: PC = 0x30
✓ Created IR block for mov

=== Processing stop instruction: mov at 0x30 ===
Processing instruction: mov
Instruction type: stop
Processing StOp with 2 operands
Built segmented memory: MSR1:[REG8] -> @64[MSR1 + REG8]
Store operation: @64[MSR1 + REG8] = REG8
Generated 2 expressions
  0: @64[MSR1 + REG8] = REG8
  1: PC = 0x38
✓ Created IR block for mov

=== Processing ldop instruction: mov at 0x38 ===
Processing instruction: mov
Instruction type: ldop
Processing LdOp with 2 operands
Built segmented memory: LS:[REG15 + REG14 + 0x100] -> @64[LS + REG15 + REG14 + 0x100]
Load operation: REG9 = @64[LS + REG15 + REG14 + 0x100]
Generated 2 expressions
  0: REG9 = @64[LS + REG15 + REG14 + 0x100]
  1: PC = 0x40
✓ Created IR block for mov

=== Processing stop instruction: mov at 0x40 ===
Processing instruction: mov
Instruction type: stop
Processing StOp with 2 operands
Built segmented memory: MSR2:[REG9 + 0x8] -> @64[MSR2 + REG9 + 0x8]
Store operation: @64[MSR2 + REG9 + 0x8] = REG9
Generated 2 expressions
  0: @64[MSR2 + REG9 + 0x8] = REG9
  1: PC = 0x48
✓ Created IR block for mov

=== Processing ldop instruction: mov at 0x48 ===
Processing instruction: mov
Instruction type: ldop
Processing LdOp with 2 operands
Built segmented memory: LS:[REG12] -> @64[LS + REG12]
Load operation: REG10 = @64[LS + REG12]
Generated 2 expressions
  0: REG10 = @64[LS + REG12]
  1: PC = 0x50
✓ Created IR block for mov

=== Processing stop instruction: mov at 0x50 ===
Processing instruction: mov
Instruction type: stop
Processing StOp with 2 operands
Built segmented memory: MSR2:[REG10] -> @64[MSR2 + REG10]
Store operation: @64[MSR2 + REG10] = REG10
Generated 2 expressions
  0: @64[MSR2 + REG10] = REG10
  1: PC = 0x58
✓ Created IR block for mov

=== Processing ldop instruction: mov at 0x58 ===
Processing instruction: mov
Instruction type: ldop
Processing LdOp with 2 operands
Built segmented memory: LS:[REG13 + 0x20] -> @64[LS + REG13 + 0x20]
Load operation: REG11 = @64[LS + REG13 + 0x20]
Generated 2 expressions
  0: REG11 = @64[LS + REG13 + 0x20]
  1: PC = 0x60
✓ Created IR block for mov

=== Processing regop instruction: xor at 0x60 ===
Processing instruction: xor
Instruction type: regop
Processing RegOp: xor with 3 operands
Generated 2 expressions
  0: REG11 = REG11 ^ REG7
  1: PC = 0x68
✓ Created IR block for xor

=== Processing stop instruction: mov at 0x68 ===
Processing instruction: mov
Instruction type: stop
Processing StOp with 2 operands
Built segmented memory: MSR1:[REG15] -> @64[MSR1 + REG15]
Store operation: @64[MSR1 + REG15] = REG11
Generated 2 expressions
  0: @64[MSR1 + REG15] = REG11
  1: PC = 0x70
✓ Created IR block for mov

=== Processing ldop instruction: mov at 0x70 ===
Processing instruction: mov
Instruction type: ldop
Processing LdOp with 2 operands
Built segmented memory: LS:[REG14 + REG15 + 0x40] -> @64[LS + REG14 + REG15 + 0x40]
Load operation: REG12 = @64[LS + REG14 + REG15 + 0x40]
Generated 2 expressions
  0: REG12 = @64[LS + REG14 + REG15 + 0x40]
  1: PC = 0x78
✓ Created IR block for mov

=== Processing ldop instruction: mov at 0x78 ===
Processing instruction: mov
Instruction type: ldop
Processing LdOp with 2 operands
Built segmented memory: LS:[REG15 + 0x60] -> @64[LS + REG15 + 0x60]
Load operation: REG13 = @64[LS + REG15 + 0x60]
Generated 2 expressions
  0: REG13 = @64[LS + REG15 + 0x60]
  1: PC = 0x80
✓ Created IR block for mov

=== Processing regop instruction: xor at 0x80 ===
Processing instruction: xor
Instruction type: regop
Processing RegOp: xor with 3 operands
Generated 2 expressions
  0: REG12 = REG12 ^ REG13
  1: PC = 0x88
✓ Created IR block for xor

=== Processing regop instruction: xor at 0x88 ===
Processing instruction: xor
Instruction type: regop
Processing RegOp: xor with 3 operands
Generated 2 expressions
  0: REG12 = REG12 ^ 0x42
  1: PC = 0x90
✓ Created IR block for xor

=== Processing stop instruction: mov at 0x90 ===
Processing instruction: mov
Instruction type: stop
Processing StOp with 2 operands
Built segmented memory: MSR2:[REG12] -> @64[MSR2 + REG12]
Store operation: @64[MSR2 + REG12] = REG12
Generated 2 expressions
  0: @64[MSR2 + REG12] = REG12
  1: PC = 0x98
✓ Created IR block for mov

=== Processing ldop instruction: mov at 0x98 ===
Processing instruction: mov
Instruction type: ldop
Processing LdOp with 2 operands
Built segmented memory: LS:[RAX + RBX] -> @64[LS + RAX + RBX]
Load operation: REG14 = @64[LS + RAX + RBX]
Generated 2 expressions
  0: REG14 = @64[LS + RAX + RBX]
  1: PC = 0xA0
✓ Created IR block for mov

=== Processing regop instruction: xor at 0xa0 ===
Processing instruction: xor
Instruction type: regop
Processing RegOp: xor with 3 operands
Generated 2 expressions
  0: REG14 = REG14 ^ RCX
  1: PC = 0xA8
✓ Created IR block for xor

=== Processing stop instruction: mov at 0xa8 ===
Processing instruction: mov
Instruction type: stop
Processing StOp with 2 operands
Built segmented memory: MSR2:[REG14] -> @64[MSR2 + REG14]
Store operation: @64[MSR2 + REG14] = REG14
Generated 2 expressions
  0: @64[MSR2 + REG14] = REG14
  1: PC = 0xB0
✓ Created IR block for mov

=== Processing ldop instruction: mov at 0xb0 ===
Processing instruction: mov
Instruction type: ldop
Processing LdOp with 2 operands
Built segmented memory: MSR1:[REG10] -> @64[MSR1 + REG10]
Load operation: REG15 = @64[MSR1 + REG10]
Generated 2 expressions
  0: REG15 = @64[MSR1 + REG10]
  1: PC = 0xB8
✓ Created IR block for mov

=== Processing stop instruction: mov at 0xb8 ===
Processing instruction: mov
Instruction type: stop
Processing StOp with 2 operands
Built segmented memory: VS:[REG15] -> @64[VS + REG15]
Store operation: @64[VS + REG15] = REG15
Generated 2 expressions
  0: @64[VS + REG15] = REG15
  1: PC = 0xC0
✓ Created IR block for mov

=== Processing ldop instruction: mov at 0xc0 ===
Processing instruction: mov
Instruction type: ldop
Processing LdOp with 2 operands
Built segmented memory: CPUID:[REG11] -> @64[CPUID + REG11]
Load operation: REG0 = @64[CPUID + REG11]
Generated 2 expressions
  0: REG0 = @64[CPUID + REG11]
  1: PC = 0xC8
✓ Created IR block for mov

=== Processing ldop instruction: mov at 0xc8 ===
Processing instruction: mov
Instruction type: ldop
Processing LdOp with 2 operands
Built segmented memory: MSR1:[REG12] -> @64[MSR1 + REG12]
Load operation: REG1 = @64[MSR1 + REG12]
Generated 2 expressions
  0: REG1 = @64[MSR1 + REG12]
  1: PC = 0xD0
✓ Created IR block for mov

=== Processing regop instruction: xor at 0xd0 ===
Processing instruction: xor
Instruction type: regop
Processing RegOp: xor with 3 operands
Generated 2 expressions
  0: REG0 = REG0 ^ REG1
  1: PC = 0xD8
✓ Created IR block for xor

=== Processing stop instruction: mov at 0xd8 ===
Processing instruction: mov
Instruction type: stop
Processing StOp with 2 operands
Built segmented memory: LS:[RAX] -> @64[LS + RAX]
Store operation: @64[LS + RAX] = REG0
Generated 2 expressions
  0: @64[LS + RAX] = REG0
  1: PC = 0xE0
✓ Created IR block for mov

=== Processing ldop instruction: mov at 0xe0 ===
Processing instruction: mov
Instruction type: ldop
Processing LdOp with 2 operands
Built segmented memory: UCODE:[REG13] -> @64[UCODE + REG13]
Load operation: REG2 = @64[UCODE + REG13]
Generated 2 expressions
  0: REG2 = @64[UCODE + REG13]
  1: PC = 0xE8
✓ Created IR block for mov

=== Processing regop instruction: xor at 0xe8 ===
Processing instruction: xor
Instruction type: regop
Processing RegOp: xor with 3 operands
Generated 2 expressions
  0: REG2 = REG2 ^ REG11
  1: PC = 0xF0
✓ Created IR block for xor

=== Processing stop instruction: mov at 0xf0 ===
Processing instruction: mov
Instruction type: stop
Processing StOp with 2 operands
Built segmented memory: UCODE:[REG2] -> @64[UCODE + REG2]
Store operation: @64[UCODE + REG2] = REG2
Generated 2 expressions
  0: @64[UCODE + REG2] = REG2
  1: PC = 0xF8
✓ Created IR block for mov

=== Processing ldop instruction: mov at 0xf8 ===
Processing instruction: mov
Instruction type: ldop
Processing LdOp with 2 operands
Built segmented memory: LS:[REG14 + REG15] -> @64[LS + REG14 + REG15]
Load operation: REG3 = @64[LS + REG14 + REG15]
Generated 2 expressions
  0: REG3 = @64[LS + REG14 + REG15]
  1: PC = 0x100
✓ Created IR block for mov

=== Processing regop instruction: add at 0x100 ===
Processing instruction: add
Instruction type: regop
Processing RegOp: add with 3 operands
Generated 2 expressions
  0: REG3 = REG3 + 0x1000
  1: PC = 0x108
✓ Created IR block for add

=== Processing stop instruction: mov at 0x108 ===
Processing instruction: mov
Instruction type: stop
Processing StOp with 2 operands
Built segmented memory: MSR2:[REG3] -> @64[MSR2 + REG3]
Store operation: @64[MSR2 + REG3] = REG3
Generated 2 expressions
  0: @64[MSR2 + REG3] = REG3
  1: PC = 0x110
✓ Created IR block for mov

=== SAMPLE IR BLOCKS ===
Generated 34 IR blocks
   Initialized 30 taint sources
🔍 Universal Security Analyzer initialized:
   Privileged segments: {'MSR2', 'MSR1', 'CPUID', 'UCODE'}
   User segments: {'LS', 'STACK', 'VS'}
   Taint sources initialized: 30

🚀 Starting universal security analysis with assignment reconstruction...
🔧 Reconstructing assignments from IR blocks...
  Processing block loc_key_0...
    Reconstructed 1 assignments
      REG1 = REG3 + REG7
  Processing block loc_key_8...
    Reconstructed 1 assignments
      R13 = @64[CPUID + R12]
  Processing block loc_key_16...
    Reconstructed 1 assignments
      @64[MSR2 + REG15] = REG14
  Processing block loc_key_24...
    No assignments reconstructed
  Processing block loc_key_32...
    Reconstructed 1 assignments
      REG14 = @8[LS + REG15 + REG14 + 0x20]
  Processing block loc_key_40...
    Reconstructed 1 assignments
      REG8 = @64[LS + REG12 + 0x10]
  Processing block loc_key_48...
    Reconstructed 1 assignments
      @64[MSR1 + REG8] = REG8
  Processing block loc_key_56...
    Reconstructed 1 assignments
      REG9 = @64[LS + REG15 + REG14 + 0x100]
  Processing block loc_key_64...
    Reconstructed 1 assignments
      @64[MSR2 + REG9 + 0x8] = REG9
  Processing block loc_key_72...
    Reconstructed 1 assignments
      REG10 = @64[LS + REG12]
  Processing block loc_key_80...
    Reconstructed 1 assignments
      @64[MSR2 + REG10] = REG10
  Processing block loc_key_88...
    Reconstructed 1 assignments
      REG11 = @64[LS + REG13 + 0x20]
  Processing block loc_key_96...
    Reconstructed 1 assignments
      REG11 = REG11 ^ REG7
  Processing block loc_key_104...
    Reconstructed 1 assignments
      @64[MSR1 + REG15] = REG11
  Processing block loc_key_112...
    No assignments reconstructed
  Processing block loc_key_120...
    No assignments reconstructed
  Processing block loc_key_128...
    No assignments reconstructed
  Processing block loc_key_136...
    No assignments reconstructed
  Processing block loc_key_144...
    Reconstructed 1 assignments
      @64[MSR2 + REG12] = REG12
  Processing block loc_key_152...
    No assignments reconstructed
  Processing block loc_key_160...
    No assignments reconstructed
  Processing block loc_key_168...
    Reconstructed 1 assignments
      @64[MSR2 + REG14] = REG14
  Processing block loc_key_176...
    Reconstructed 1 assignments
      REG15 = @64[MSR1 + REG10]
  Processing block loc_key_184...
    Reconstructed 1 assignments
      @64[VS + REG15] = REG15
  Processing block loc_key_192...
    Reconstructed 1 assignments
      REG0 = @64[CPUID + REG11]
  Processing block loc_key_200...
    Reconstructed 1 assignments
      REG1 = @64[MSR1 + REG12]
  Processing block loc_key_208...
    Reconstructed 1 assignments
      REG0 = REG0 ^ REG1
  Processing block loc_key_216...
    Reconstructed 1 assignments
      @64[LS + RAX] = REG0
  Processing block loc_key_224...
    Reconstructed 1 assignments
      REG2 = @64[UCODE + REG13]
  Processing block loc_key_232...
    Reconstructed 1 assignments
      REG2 = REG2 ^ REG11
  Processing block loc_key_240...
    Reconstructed 1 assignments
      @64[UCODE + REG2] = REG2
  Processing block loc_key_248...
    Reconstructed 1 assignments
      REG3 = @64[LS + REG14 + REG15]
  Processing block loc_key_256...
    Reconstructed 1 assignments
      REG3 = REG3 + 0x1000
  Processing block loc_key_264...
    Reconstructed 1 assignments
      @64[MSR2 + REG3] = REG3
🧬 Performing taint analysis on 27 assignments
   Marking R13 as tainted due to privileged read from CPUID
   Marking REG15 as tainted due to privileged read from MSR1
   Marking REG0 as tainted due to privileged read from CPUID
   Marking REG1 as tainted due to privileged read from MSR1
   Marking REG2 as tainted due to privileged read from UCODE
   Iteration 1: 30 -> 41 tainted expressions
   Marking R13 as tainted due to privileged read from CPUID
   Marking REG15 as tainted due to privileged read from MSR1
   Marking REG0 as tainted due to privileged read from CPUID
   Marking REG1 as tainted due to privileged read from MSR1
   Marking REG2 as tainted due to privileged read from UCODE
   Iteration 2: 41 -> 41 tainted expressions
   Final tainted expressions: 41

🔍 Analyzing block loc_key_0:
  Found 1 assignments in block:
    0: REG1 = REG3 + REG7
         DST tainted: True, SRC tainted: True
         Marking REG1 as tainted
  🔍 Running detector: buffer_overflow
      🔍 Buffer overflow detector
          🚨 FOUND: Tainted arithmetic +
    ✅ Found 1 vulnerabilities!
      - Tainted arithmetic operation: +
  🔍 Running detector: privilege_escalation
      🔍 Privilege escalation detector
    ❌ No vulnerabilities found
  🔍 Running detector: information_leak
      🔍 Information leak detector
    ❌ No vulnerabilities found
  🔍 Running detector: microcode_injection
      🔍 Microcode injection detector
    ❌ No vulnerabilities found

🔍 Analyzing block loc_key_8:
  Found 1 assignments in block:
    0: R13 = @64[CPUID + R12]
         DST tainted: True, SRC tainted: True
         Marking R13 as tainted
  🔍 Running detector: buffer_overflow
      🔍 Buffer overflow detector
    ❌ No vulnerabilities found
  🔍 Running detector: privilege_escalation
      🔍 Privilege escalation detector
    ❌ No vulnerabilities found
  🔍 Running detector: information_leak
      🔍 Information leak detector
          🚨 FOUND: Information leak from CPUID
    ✅ Found 1 vulnerabilities!
      - Read from privileged segment CPUID
  🔍 Running detector: microcode_injection
      🔍 Microcode injection detector
    ❌ No vulnerabilities found

🔍 Analyzing block loc_key_16:
  Found 1 assignments in block:
    0: @64[MSR2 + REG15] = REG14
         DST tainted: True, SRC tainted: True
         Marking @64[MSR2 + REG15] as tainted
  🔍 Running detector: buffer_overflow
      🔍 Buffer overflow detector
          🚨 FOUND: Tainted memory write
    ✅ Found 1 vulnerabilities!
      - Write to tainted memory address
  🔍 Running detector: privilege_escalation
      🔍 Privilege escalation detector
          🚨 FOUND: Privilege escalation to MSR2
    ✅ Found 1 vulnerabilities!
      - Write to privileged segment MSR2 with tainted data
  🔍 Running detector: information_leak
      🔍 Information leak detector
    ❌ No vulnerabilities found
  🔍 Running detector: microcode_injection
      🔍 Microcode injection detector
    ❌ No vulnerabilities found

🔍 Analyzing block loc_key_24:
  No assignments found in block
  🔍 Running detector: buffer_overflow
      🔍 Buffer overflow detector
    ❌ No vulnerabilities found
  🔍 Running detector: privilege_escalation
      🔍 Privilege escalation detector
    ❌ No vulnerabilities found
  🔍 Running detector: information_leak
      🔍 Information leak detector
    ❌ No vulnerabilities found
  🔍 Running detector: microcode_injection
      🔍 Microcode injection detector
    ❌ No vulnerabilities found

🔍 Analyzing block loc_key_32:
  Found 1 assignments in block:
    0: REG14 = @8[LS + REG15 + REG14 + 0x20]
         DST tainted: True, SRC tainted: True
         Marking REG14 as tainted
  🔍 Running detector: buffer_overflow
      🔍 Buffer overflow detector
    ❌ No vulnerabilities found
  🔍 Running detector: privilege_escalation
      🔍 Privilege escalation detector
    ❌ No vulnerabilities found
  🔍 Running detector: information_leak
      🔍 Information leak detector
    ❌ No vulnerabilities found
  🔍 Running detector: microcode_injection
      🔍 Microcode injection detector
    ❌ No vulnerabilities found

🔍 Analyzing block loc_key_40:
  Found 1 assignments in block:
    0: REG8 = @64[LS + REG12 + 0x10]
         DST tainted: True, SRC tainted: True
         Marking REG8 as tainted
  🔍 Running detector: buffer_overflow
      🔍 Buffer overflow detector
    ❌ No vulnerabilities found
  🔍 Running detector: privilege_escalation
      🔍 Privilege escalation detector
    ❌ No vulnerabilities found
  🔍 Running detector: information_leak
      🔍 Information leak detector
    ❌ No vulnerabilities found
  🔍 Running detector: microcode_injection
      🔍 Microcode injection detector
    ❌ No vulnerabilities found

🔍 Analyzing block loc_key_48:
  Found 1 assignments in block:
    0: @64[MSR1 + REG8] = REG8
         DST tainted: True, SRC tainted: True
         Marking @64[MSR1 + REG8] as tainted
  🔍 Running detector: buffer_overflow
      🔍 Buffer overflow detector
          🚨 FOUND: Tainted memory write
    ✅ Found 1 vulnerabilities!
      - Write to tainted memory address
  🔍 Running detector: privilege_escalation
      🔍 Privilege escalation detector
          🚨 FOUND: Privilege escalation to MSR1
    ✅ Found 1 vulnerabilities!
      - Write to privileged segment MSR1 with tainted data
  🔍 Running detector: information_leak
      🔍 Information leak detector
    ❌ No vulnerabilities found
  🔍 Running detector: microcode_injection
      🔍 Microcode injection detector
    ❌ No vulnerabilities found

🔍 Analyzing block loc_key_56:
  Found 1 assignments in block:
    0: REG9 = @64[LS + REG15 + REG14 + 0x100]
         DST tainted: True, SRC tainted: True
         Marking REG9 as tainted
  🔍 Running detector: buffer_overflow
      🔍 Buffer overflow detector
    ❌ No vulnerabilities found
  🔍 Running detector: privilege_escalation
      🔍 Privilege escalation detector
    ❌ No vulnerabilities found
  🔍 Running detector: information_leak
      🔍 Information leak detector
    ❌ No vulnerabilities found
  🔍 Running detector: microcode_injection
      🔍 Microcode injection detector
    ❌ No vulnerabilities found

🔍 Analyzing block loc_key_64:
  Found 1 assignments in block:
    0: @64[MSR2 + REG9 + 0x8] = REG9
         DST tainted: True, SRC tainted: True
         Marking @64[MSR2 + REG9 + 0x8] as tainted
  🔍 Running detector: buffer_overflow
      🔍 Buffer overflow detector
          🚨 FOUND: Tainted memory write
    ✅ Found 1 vulnerabilities!
      - Write to tainted memory address
  🔍 Running detector: privilege_escalation
      🔍 Privilege escalation detector
          🚨 FOUND: Privilege escalation to MSR2
    ✅ Found 1 vulnerabilities!
      - Write to privileged segment MSR2 with tainted data
  🔍 Running detector: information_leak
      🔍 Information leak detector
    ❌ No vulnerabilities found
  🔍 Running detector: microcode_injection
      🔍 Microcode injection detector
    ❌ No vulnerabilities found

🔍 Analyzing block loc_key_72:
  Found 1 assignments in block:
    0: REG10 = @64[LS + REG12]
         DST tainted: True, SRC tainted: True
         Marking REG10 as tainted
  🔍 Running detector: buffer_overflow
      🔍 Buffer overflow detector
    ❌ No vulnerabilities found
  🔍 Running detector: privilege_escalation
      🔍 Privilege escalation detector
    ❌ No vulnerabilities found
  🔍 Running detector: information_leak
      🔍 Information leak detector
    ❌ No vulnerabilities found
  🔍 Running detector: microcode_injection
      🔍 Microcode injection detector
    ❌ No vulnerabilities found

🔍 Analyzing block loc_key_80:
  Found 1 assignments in block:
    0: @64[MSR2 + REG10] = REG10
         DST tainted: True, SRC tainted: True
         Marking @64[MSR2 + REG10] as tainted
  🔍 Running detector: buffer_overflow
      🔍 Buffer overflow detector
          🚨 FOUND: Tainted memory write
    ✅ Found 1 vulnerabilities!
      - Write to tainted memory address
  🔍 Running detector: privilege_escalation
      🔍 Privilege escalation detector
          🚨 FOUND: Privilege escalation to MSR2
    ✅ Found 1 vulnerabilities!
      - Write to privileged segment MSR2 with tainted data
  🔍 Running detector: information_leak
      🔍 Information leak detector
    ❌ No vulnerabilities found
  🔍 Running detector: microcode_injection
      🔍 Microcode injection detector
    ❌ No vulnerabilities found

🔍 Analyzing block loc_key_88:
  Found 1 assignments in block:
    0: REG11 = @64[LS + REG13 + 0x20]
         DST tainted: True, SRC tainted: True
         Marking REG11 as tainted
  🔍 Running detector: buffer_overflow
      🔍 Buffer overflow detector
    ❌ No vulnerabilities found
  🔍 Running detector: privilege_escalation
      🔍 Privilege escalation detector
    ❌ No vulnerabilities found
  🔍 Running detector: information_leak
      🔍 Information leak detector
    ❌ No vulnerabilities found
  🔍 Running detector: microcode_injection
      🔍 Microcode injection detector
    ❌ No vulnerabilities found

🔍 Analyzing block loc_key_96:
  Found 1 assignments in block:
    0: REG11 = REG11 ^ REG7
         DST tainted: True, SRC tainted: True
         Marking REG11 as tainted
  🔍 Running detector: buffer_overflow
      🔍 Buffer overflow detector
          🚨 FOUND: Tainted arithmetic ^
    ✅ Found 1 vulnerabilities!
      - Tainted arithmetic operation: ^
  🔍 Running detector: privilege_escalation
      🔍 Privilege escalation detector
    ❌ No vulnerabilities found
  🔍 Running detector: information_leak
      🔍 Information leak detector
    ❌ No vulnerabilities found
  🔍 Running detector: microcode_injection
      🔍 Microcode injection detector
    ❌ No vulnerabilities found

🔍 Analyzing block loc_key_104:
  Found 1 assignments in block:
    0: @64[MSR1 + REG15] = REG11
         DST tainted: True, SRC tainted: True
         Marking @64[MSR1 + REG15] as tainted
  🔍 Running detector: buffer_overflow
      🔍 Buffer overflow detector
          🚨 FOUND: Tainted memory write
    ✅ Found 1 vulnerabilities!
      - Write to tainted memory address
  🔍 Running detector: privilege_escalation
      🔍 Privilege escalation detector
          🚨 FOUND: Privilege escalation to MSR1
    ✅ Found 1 vulnerabilities!
      - Write to privileged segment MSR1 with tainted data
  🔍 Running detector: information_leak
      🔍 Information leak detector
    ❌ No vulnerabilities found
  🔍 Running detector: microcode_injection
      🔍 Microcode injection detector
    ❌ No vulnerabilities found

🔍 Analyzing block loc_key_112:
  No assignments found in block
  🔍 Running detector: buffer_overflow
      🔍 Buffer overflow detector
    ❌ No vulnerabilities found
  🔍 Running detector: privilege_escalation
      🔍 Privilege escalation detector
    ❌ No vulnerabilities found
  🔍 Running detector: information_leak
      🔍 Information leak detector
    ❌ No vulnerabilities found
  🔍 Running detector: microcode_injection
      🔍 Microcode injection detector
    ❌ No vulnerabilities found

🔍 Analyzing block loc_key_120:
  No assignments found in block
  🔍 Running detector: buffer_overflow
      🔍 Buffer overflow detector
    ❌ No vulnerabilities found
  🔍 Running detector: privilege_escalation
      🔍 Privilege escalation detector
    ❌ No vulnerabilities found
  🔍 Running detector: information_leak
      🔍 Information leak detector
    ❌ No vulnerabilities found
  🔍 Running detector: microcode_injection
      🔍 Microcode injection detector
    ❌ No vulnerabilities found

🔍 Analyzing block loc_key_128:
  No assignments found in block
  🔍 Running detector: buffer_overflow
      🔍 Buffer overflow detector
    ❌ No vulnerabilities found
  🔍 Running detector: privilege_escalation
      🔍 Privilege escalation detector
    ❌ No vulnerabilities found
  🔍 Running detector: information_leak
      🔍 Information leak detector
    ❌ No vulnerabilities found
  🔍 Running detector: microcode_injection
      🔍 Microcode injection detector
    ❌ No vulnerabilities found

🔍 Analyzing block loc_key_136:
  No assignments found in block
  🔍 Running detector: buffer_overflow
      🔍 Buffer overflow detector
    ❌ No vulnerabilities found
  🔍 Running detector: privilege_escalation
      🔍 Privilege escalation detector
    ❌ No vulnerabilities found
  🔍 Running detector: information_leak
      🔍 Information leak detector
    ❌ No vulnerabilities found
  🔍 Running detector: microcode_injection
      🔍 Microcode injection detector
    ❌ No vulnerabilities found

🔍 Analyzing block loc_key_144:
  Found 1 assignments in block:
    0: @64[MSR2 + REG12] = REG12
         DST tainted: True, SRC tainted: True
         Marking @64[MSR2 + REG12] as tainted
  🔍 Running detector: buffer_overflow
      🔍 Buffer overflow detector
          🚨 FOUND: Tainted memory write
    ✅ Found 1 vulnerabilities!
      - Write to tainted memory address
  🔍 Running detector: privilege_escalation
      🔍 Privilege escalation detector
          🚨 FOUND: Privilege escalation to MSR2
    ✅ Found 1 vulnerabilities!
      - Write to privileged segment MSR2 with tainted data
  🔍 Running detector: information_leak
      🔍 Information leak detector
    ❌ No vulnerabilities found
  🔍 Running detector: microcode_injection
      🔍 Microcode injection detector
    ❌ No vulnerabilities found

🔍 Analyzing block loc_key_152:
  No assignments found in block
  🔍 Running detector: buffer_overflow
      🔍 Buffer overflow detector
    ❌ No vulnerabilities found
  🔍 Running detector: privilege_escalation
      🔍 Privilege escalation detector
    ❌ No vulnerabilities found
  🔍 Running detector: information_leak
      🔍 Information leak detector
    ❌ No vulnerabilities found
  🔍 Running detector: microcode_injection
      🔍 Microcode injection detector
    ❌ No vulnerabilities found

🔍 Analyzing block loc_key_160:
  No assignments found in block
  🔍 Running detector: buffer_overflow
      🔍 Buffer overflow detector
    ❌ No vulnerabilities found
  🔍 Running detector: privilege_escalation
      🔍 Privilege escalation detector
    ❌ No vulnerabilities found
  🔍 Running detector: information_leak
      🔍 Information leak detector
    ❌ No vulnerabilities found
  🔍 Running detector: microcode_injection
      🔍 Microcode injection detector
    ❌ No vulnerabilities found

🔍 Analyzing block loc_key_168:
  Found 1 assignments in block:
    0: @64[MSR2 + REG14] = REG14
         DST tainted: True, SRC tainted: True
         Marking @64[MSR2 + REG14] as tainted
  🔍 Running detector: buffer_overflow
      🔍 Buffer overflow detector
          🚨 FOUND: Tainted memory write
    ✅ Found 1 vulnerabilities!
      - Write to tainted memory address
  🔍 Running detector: privilege_escalation
      🔍 Privilege escalation detector
          🚨 FOUND: Privilege escalation to MSR2
    ✅ Found 1 vulnerabilities!
      - Write to privileged segment MSR2 with tainted data
  🔍 Running detector: information_leak
      🔍 Information leak detector
    ❌ No vulnerabilities found
  🔍 Running detector: microcode_injection
      🔍 Microcode injection detector
    ❌ No vulnerabilities found

🔍 Analyzing block loc_key_176:
  Found 1 assignments in block:
    0: REG15 = @64[MSR1 + REG10]
         DST tainted: True, SRC tainted: True
         Marking REG15 as tainted
  🔍 Running detector: buffer_overflow
      🔍 Buffer overflow detector
    ❌ No vulnerabilities found
  🔍 Running detector: privilege_escalation
      🔍 Privilege escalation detector
    ❌ No vulnerabilities found
  🔍 Running detector: information_leak
      🔍 Information leak detector
          🚨 FOUND: Information leak from MSR1
    ✅ Found 1 vulnerabilities!
      - Read from privileged segment MSR1
  🔍 Running detector: microcode_injection
      🔍 Microcode injection detector
    ❌ No vulnerabilities found

🔍 Analyzing block loc_key_184:
  Found 1 assignments in block:
    0: @64[VS + REG15] = REG15
         DST tainted: True, SRC tainted: True
         Marking @64[VS + REG15] as tainted
  🔍 Running detector: buffer_overflow
      🔍 Buffer overflow detector
          🚨 FOUND: Tainted memory write
    ✅ Found 1 vulnerabilities!
      - Write to tainted memory address
  🔍 Running detector: privilege_escalation
      🔍 Privilege escalation detector
    ❌ No vulnerabilities found
  🔍 Running detector: information_leak
      🔍 Information leak detector
          🚨 FOUND: Tainted data to user segment VS
    ✅ Found 1 vulnerabilities!
      - Tainted data written to user segment VS
  🔍 Running detector: microcode_injection
      🔍 Microcode injection detector
    ❌ No vulnerabilities found

🔍 Analyzing block loc_key_192:
  Found 1 assignments in block:
    0: REG0 = @64[CPUID + REG11]
         DST tainted: True, SRC tainted: True
         Marking REG0 as tainted
  🔍 Running detector: buffer_overflow
      🔍 Buffer overflow detector
    ❌ No vulnerabilities found
  🔍 Running detector: privilege_escalation
      🔍 Privilege escalation detector
    ❌ No vulnerabilities found
  🔍 Running detector: information_leak
      🔍 Information leak detector
          🚨 FOUND: Information leak from CPUID
    ✅ Found 1 vulnerabilities!
      - Read from privileged segment CPUID
  🔍 Running detector: microcode_injection
      🔍 Microcode injection detector
    ❌ No vulnerabilities found

🔍 Analyzing block loc_key_200:
  Found 1 assignments in block:
    0: REG1 = @64[MSR1 + REG12]
         DST tainted: True, SRC tainted: True
         Marking REG1 as tainted
  🔍 Running detector: buffer_overflow
      🔍 Buffer overflow detector
    ❌ No vulnerabilities found
  🔍 Running detector: privilege_escalation
      🔍 Privilege escalation detector
    ❌ No vulnerabilities found
  🔍 Running detector: information_leak
      🔍 Information leak detector
          🚨 FOUND: Information leak from MSR1
    ✅ Found 1 vulnerabilities!
      - Read from privileged segment MSR1
  🔍 Running detector: microcode_injection
      🔍 Microcode injection detector
    ❌ No vulnerabilities found

🔍 Analyzing block loc_key_208:
  Found 1 assignments in block:
    0: REG0 = REG0 ^ REG1
         DST tainted: True, SRC tainted: True
         Marking REG0 as tainted
  🔍 Running detector: buffer_overflow
      🔍 Buffer overflow detector
          🚨 FOUND: Tainted arithmetic ^
    ✅ Found 1 vulnerabilities!
      - Tainted arithmetic operation: ^
  🔍 Running detector: privilege_escalation
      🔍 Privilege escalation detector
    ❌ No vulnerabilities found
  🔍 Running detector: information_leak
      🔍 Information leak detector
    ❌ No vulnerabilities found
  🔍 Running detector: microcode_injection
      🔍 Microcode injection detector
    ❌ No vulnerabilities found

🔍 Analyzing block loc_key_216:
  Found 1 assignments in block:
    0: @64[LS + RAX] = REG0
         DST tainted: True, SRC tainted: True
         Marking @64[LS + RAX] as tainted
  🔍 Running detector: buffer_overflow
      🔍 Buffer overflow detector
          🚨 FOUND: Tainted memory write
    ✅ Found 1 vulnerabilities!
      - Write to tainted memory address
  🔍 Running detector: privilege_escalation
      🔍 Privilege escalation detector
    ❌ No vulnerabilities found
  🔍 Running detector: information_leak
      🔍 Information leak detector
          🚨 FOUND: Tainted data to user segment LS
    ✅ Found 1 vulnerabilities!
      - Tainted data written to user segment LS
  🔍 Running detector: microcode_injection
      🔍 Microcode injection detector
    ❌ No vulnerabilities found

🔍 Analyzing block loc_key_224:
  Found 1 assignments in block:
    0: REG2 = @64[UCODE + REG13]
         DST tainted: True, SRC tainted: True
         Marking REG2 as tainted
  🔍 Running detector: buffer_overflow
      🔍 Buffer overflow detector
    ❌ No vulnerabilities found
  🔍 Running detector: privilege_escalation
      🔍 Privilege escalation detector
    ❌ No vulnerabilities found
  🔍 Running detector: information_leak
      🔍 Information leak detector
          🚨 FOUND: Information leak from UCODE
    ✅ Found 1 vulnerabilities!
      - Read from privileged segment UCODE
  🔍 Running detector: microcode_injection
      🔍 Microcode injection detector
    ❌ No vulnerabilities found

🔍 Analyzing block loc_key_232:
  Found 1 assignments in block:
    0: REG2 = REG2 ^ REG11
         DST tainted: True, SRC tainted: True
         Marking REG2 as tainted
  🔍 Running detector: buffer_overflow
      🔍 Buffer overflow detector
          🚨 FOUND: Tainted arithmetic ^
    ✅ Found 1 vulnerabilities!
      - Tainted arithmetic operation: ^
  🔍 Running detector: privilege_escalation
      🔍 Privilege escalation detector
    ❌ No vulnerabilities found
  🔍 Running detector: information_leak
      🔍 Information leak detector
    ❌ No vulnerabilities found
  🔍 Running detector: microcode_injection
      🔍 Microcode injection detector
    ❌ No vulnerabilities found

🔍 Analyzing block loc_key_240:
  Found 1 assignments in block:
    0: @64[UCODE + REG2] = REG2
         DST tainted: True, SRC tainted: True
         Marking @64[UCODE + REG2] as tainted
  🔍 Running detector: buffer_overflow
      🔍 Buffer overflow detector
          🚨 FOUND: Tainted memory write
    ✅ Found 1 vulnerabilities!
      - Write to tainted memory address
  🔍 Running detector: privilege_escalation
      🔍 Privilege escalation detector
          🚨 FOUND: Privilege escalation to UCODE
    ✅ Found 1 vulnerabilities!
      - Write to privileged segment UCODE with tainted data
  🔍 Running detector: information_leak
      🔍 Information leak detector
    ❌ No vulnerabilities found
  🔍 Running detector: microcode_injection
      🔍 Microcode injection detector
          🚨 CRITICAL: Microcode injection detected!
    ✅ Found 1 vulnerabilities!
      - Write to microcode segment UCODE

🔍 Analyzing block loc_key_248:
  Found 1 assignments in block:
    0: REG3 = @64[LS + REG14 + REG15]
         DST tainted: True, SRC tainted: True
         Marking REG3 as tainted
  🔍 Running detector: buffer_overflow
      🔍 Buffer overflow detector
    ❌ No vulnerabilities found
  🔍 Running detector: privilege_escalation
      🔍 Privilege escalation detector
    ❌ No vulnerabilities found
  🔍 Running detector: information_leak
      🔍 Information leak detector
    ❌ No vulnerabilities found
  🔍 Running detector: microcode_injection
      🔍 Microcode injection detector
    ❌ No vulnerabilities found

🔍 Analyzing block loc_key_256:
  Found 1 assignments in block:
    0: REG3 = REG3 + 0x1000
         DST tainted: True, SRC tainted: True
         Marking REG3 as tainted
  🔍 Running detector: buffer_overflow
      🔍 Buffer overflow detector
          🚨 FOUND: Tainted arithmetic +
    ✅ Found 1 vulnerabilities!
      - Tainted arithmetic operation: +
  🔍 Running detector: privilege_escalation
      🔍 Privilege escalation detector
    ❌ No vulnerabilities found
  🔍 Running detector: information_leak
      🔍 Information leak detector
    ❌ No vulnerabilities found
  🔍 Running detector: microcode_injection
      🔍 Microcode injection detector
    ❌ No vulnerabilities found

🔍 Analyzing block loc_key_264:
  Found 1 assignments in block:
    0: @64[MSR2 + REG3] = REG3
         DST tainted: True, SRC tainted: True
         Marking @64[MSR2 + REG3] as tainted
  🔍 Running detector: buffer_overflow
      🔍 Buffer overflow detector
          🚨 FOUND: Tainted memory write
    ✅ Found 1 vulnerabilities!
      - Write to tainted memory address
  🔍 Running detector: privilege_escalation
      🔍 Privilege escalation detector
          🚨 FOUND: Privilege escalation to MSR2
    ✅ Found 1 vulnerabilities!
      - Write to privileged segment MSR2 with tainted data
  🔍 Running detector: information_leak
      🔍 Information leak detector
    ❌ No vulnerabilities found
  🔍 Running detector: microcode_injection
      🔍 Microcode injection detector
    ❌ No vulnerabilities found

============================================================
ZEN MICROCODE SECURITY ANALYSIS REPORT
Universal IR Analysis with Assignment Reconstruction
============================================================
Analysis completed at: 2025-07-29 19:03:45
Total vulnerabilities found: 33
Assignments reconstructed: 27
Tainted expressions tracked: 41

VULNERABILITY STATISTICS:
------------------------------
  privilege_escalation: 9
  microcode_injection: 1
  buffer_overflow: 16
  information_leak: 7

SEVERITY BREAKDOWN:
--------------------
  CRITICAL: 10
  HIGH: 10
  MEDIUM: 13

ASSIGNMENT RECONSTRUCTION SUMMARY:
-----------------------------------
  Total assignments: 27
  Tainted expressions: 41

DETAILED FINDINGS:
--------------------

1. PRIVILEGE_ESCALATION [CRITICAL]
   Location: 0x10
   Description: Write to privileged segment MSR2 with tainted data
   Details:
     segment: MSR2
     src: REG14
     tainted: True
     risk: Potential privilege escalation through microcode
     memory_expr: @64[MSR2 + REG15]
     assignment: @64[MSR2 + REG15] = REG14

2. PRIVILEGE_ESCALATION [CRITICAL]
   Location: 0x30
   Description: Write to privileged segment MSR1 with tainted data
   Details:
     segment: MSR1
     src: REG8
     tainted: True
     risk: Potential privilege escalation through microcode
     memory_expr: @64[MSR1 + REG8]
     assignment: @64[MSR1 + REG8] = REG8

3. PRIVILEGE_ESCALATION [CRITICAL]
   Location: 0x40
   Description: Write to privileged segment MSR2 with tainted data
   Details:
     segment: MSR2
     src: REG9
     tainted: True
     risk: Potential privilege escalation through microcode
     memory_expr: @64[MSR2 + REG9 + 0x8]
     assignment: @64[MSR2 + REG9 + 0x8] = REG9

4. PRIVILEGE_ESCALATION [CRITICAL]
   Location: 0x50
   Description: Write to privileged segment MSR2 with tainted data
   Details:
     segment: MSR2
     src: REG10
     tainted: True
     risk: Potential privilege escalation through microcode
     memory_expr: @64[MSR2 + REG10]
     assignment: @64[MSR2 + REG10] = REG10

5. PRIVILEGE_ESCALATION [CRITICAL]
   Location: 0x68
   Description: Write to privileged segment MSR1 with tainted data
   Details:
     segment: MSR1
     src: REG11
     tainted: True
     risk: Potential privilege escalation through microcode
     memory_expr: @64[MSR1 + REG15]
     assignment: @64[MSR1 + REG15] = REG11

6. PRIVILEGE_ESCALATION [CRITICAL]
   Location: 0x90
   Description: Write to privileged segment MSR2 with tainted data
   Details:
     segment: MSR2
     src: REG12
     tainted: True
     risk: Potential privilege escalation through microcode
     memory_expr: @64[MSR2 + REG12]
     assignment: @64[MSR2 + REG12] = REG12

7. PRIVILEGE_ESCALATION [CRITICAL]
   Location: 0xa8
   Description: Write to privileged segment MSR2 with tainted data
   Details:
     segment: MSR2
     src: REG14
     tainted: True
     risk: Potential privilege escalation through microcode
     memory_expr: @64[MSR2 + REG14]
     assignment: @64[MSR2 + REG14] = REG14

8. PRIVILEGE_ESCALATION [CRITICAL]
   Location: 0xf0
   Description: Write to privileged segment UCODE with tainted data
   Details:
     segment: UCODE
     src: REG2
     tainted: True
     risk: MICROCODE INJECTION - Complete system compromise possible
     memory_expr: @64[UCODE + REG2]
     assignment: @64[UCODE + REG2] = REG2

9. MICROCODE_INJECTION [CRITICAL]
   Location: 0xf0
   Description: Write to microcode segment UCODE
   Details:
     segment: UCODE
     src: REG2
     tainted: True
     risk: CRITICAL: Microcode injection allows complete system compromise
     memory_expr: @64[UCODE + REG2]
     assignment: @64[UCODE + REG2] = REG2
     proof_of_concept: Attacker can modify microcode: @64[UCODE + REG2] = REG2
   PoC: mov ucode:[controlled_addr], malicious_microcode

10. PRIVILEGE_ESCALATION [CRITICAL]
   Location: 0x108
   Description: Write to privileged segment MSR2 with tainted data
   Details:
     segment: MSR2
     src: REG3
     tainted: True
     risk: Potential privilege escalation through microcode
     memory_expr: @64[MSR2 + REG3]
     assignment: @64[MSR2 + REG3] = REG3

11. BUFFER_OVERFLOW [HIGH]
   Location: 0x0
   Description: Tainted arithmetic operation: +
   Details:
     dst: REG1
     operation: +
     src: REG3 + REG7
     risk: Potential integer overflow leading to buffer overflow
     assignment: REG1 = REG3 + REG7

12. INFORMATION_LEAK [HIGH]
   Location: 0x8
   Description: Read from privileged segment CPUID
   Details:
     segment: CPUID
     dst: R13
     src: @64[CPUID + R12]
     risk: Potential information disclosure from privileged context
     assignment: R13 = @64[CPUID + R12]

13. BUFFER_OVERFLOW [HIGH]
   Location: 0x60
   Description: Tainted arithmetic operation: ^
   Details:
     dst: REG11
     operation: ^
     src: REG11 ^ REG7
     risk: Potential integer overflow leading to buffer overflow
     assignment: REG11 = REG11 ^ REG7

14. INFORMATION_LEAK [HIGH]
   Location: 0xb0
   Description: Read from privileged segment MSR1
   Details:
     segment: MSR1
     dst: REG15
     src: @64[MSR1 + REG10]
     risk: Potential information disclosure from privileged context
     assignment: REG15 = @64[MSR1 + REG10]

15. INFORMATION_LEAK [HIGH]
   Location: 0xc0
   Description: Read from privileged segment CPUID
   Details:
     segment: CPUID
     dst: REG0
     src: @64[CPUID + REG11]
     risk: Potential information disclosure from privileged context
     assignment: REG0 = @64[CPUID + REG11]

16. INFORMATION_LEAK [HIGH]
   Location: 0xc8
   Description: Read from privileged segment MSR1
   Details:
     segment: MSR1
     dst: REG1
     src: @64[MSR1 + REG12]
     risk: Potential information disclosure from privileged context
     assignment: REG1 = @64[MSR1 + REG12]

17. BUFFER_OVERFLOW [HIGH]
   Location: 0xd0
   Description: Tainted arithmetic operation: ^
   Details:
     dst: REG0
     operation: ^
     src: REG0 ^ REG1
     risk: Potential integer overflow leading to buffer overflow
     assignment: REG0 = REG0 ^ REG1

18. INFORMATION_LEAK [HIGH]
   Location: 0xe0
   Description: Read from privileged segment UCODE
   Details:
     segment: UCODE
     dst: REG2
     src: @64[UCODE + REG13]
     risk: Potential information disclosure from privileged context
     assignment: REG2 = @64[UCODE + REG13]

19. BUFFER_OVERFLOW [HIGH]
   Location: 0xe8
   Description: Tainted arithmetic operation: ^
   Details:
     dst: REG2
     operation: ^
     src: REG2 ^ REG11
     risk: Potential integer overflow leading to buffer overflow
     assignment: REG2 = REG2 ^ REG11

20. BUFFER_OVERFLOW [HIGH]
   Location: 0x100
   Description: Tainted arithmetic operation: +
   Details:
     dst: REG3
     operation: +
     src: REG3 + 0x1000
     risk: Potential integer overflow leading to buffer overflow
     assignment: REG3 = REG3 + 0x1000

21. BUFFER_OVERFLOW [MEDIUM]
   Location: 0x10
   Description: Write to tainted memory address
   Details:
     dst: @64[MSR2 + REG15]
     ptr: MSR2 + REG15
     src: REG14
     risk: Potential buffer overflow through controlled addressing
     assignment: @64[MSR2 + REG15] = REG14

22. BUFFER_OVERFLOW [MEDIUM]
   Location: 0x30
   Description: Write to tainted memory address
   Details:
     dst: @64[MSR1 + REG8]
     ptr: MSR1 + REG8
     src: REG8
     risk: Potential buffer overflow through controlled addressing
     assignment: @64[MSR1 + REG8] = REG8

23. BUFFER_OVERFLOW [MEDIUM]
   Location: 0x40
   Description: Write to tainted memory address
   Details:
     dst: @64[MSR2 + REG9 + 0x8]
     ptr: MSR2 + REG9 + 0x8
     src: REG9
     risk: Potential buffer overflow through controlled addressing
     assignment: @64[MSR2 + REG9 + 0x8] = REG9

24. BUFFER_OVERFLOW [MEDIUM]
   Location: 0x50
   Description: Write to tainted memory address
   Details:
     dst: @64[MSR2 + REG10]
     ptr: MSR2 + REG10
     src: REG10
     risk: Potential buffer overflow through controlled addressing
     assignment: @64[MSR2 + REG10] = REG10

25. BUFFER_OVERFLOW [MEDIUM]
   Location: 0x68
   Description: Write to tainted memory address
   Details:
     dst: @64[MSR1 + REG15]
     ptr: MSR1 + REG15
     src: REG11
     risk: Potential buffer overflow through controlled addressing
     assignment: @64[MSR1 + REG15] = REG11

26. BUFFER_OVERFLOW [MEDIUM]
   Location: 0x90
   Description: Write to tainted memory address
   Details:
     dst: @64[MSR2 + REG12]
     ptr: MSR2 + REG12
     src: REG12
     risk: Potential buffer overflow through controlled addressing
     assignment: @64[MSR2 + REG12] = REG12

27. BUFFER_OVERFLOW [MEDIUM]
   Location: 0xa8
   Description: Write to tainted memory address
   Details:
     dst: @64[MSR2 + REG14]
     ptr: MSR2 + REG14
     src: REG14
     risk: Potential buffer overflow through controlled addressing
     assignment: @64[MSR2 + REG14] = REG14

28. BUFFER_OVERFLOW [MEDIUM]
   Location: 0xb8
   Description: Write to tainted memory address
   Details:
     dst: @64[VS + REG15]
     ptr: VS + REG15
     src: REG15
     risk: Potential buffer overflow through controlled addressing
     assignment: @64[VS + REG15] = REG15

29. INFORMATION_LEAK [MEDIUM]
   Location: 0xb8
   Description: Tainted data written to user segment VS
   Details:
     segment: VS
     dst: @64[VS + REG15]
     src: REG15
     risk: Potential data exfiltration to user space
     assignment: @64[VS + REG15] = REG15

30. BUFFER_OVERFLOW [MEDIUM]
   Location: 0xd8
   Description: Write to tainted memory address
   Details:
     dst: @64[LS + RAX]
     ptr: LS + RAX
     src: REG0
     risk: Potential buffer overflow through controlled addressing
     assignment: @64[LS + RAX] = REG0

31. INFORMATION_LEAK [MEDIUM]
   Location: 0xd8
   Description: Tainted data written to user segment LS
   Details:
     segment: LS
     dst: @64[LS + RAX]
     src: REG0
     risk: Potential data exfiltration to user space
     assignment: @64[LS + RAX] = REG0

32. BUFFER_OVERFLOW [MEDIUM]
   Location: 0xf0
   Description: Write to tainted memory address
   Details:
     dst: @64[UCODE + REG2]
     ptr: UCODE + REG2
     src: REG2
     risk: Potential buffer overflow through controlled addressing
     assignment: @64[UCODE + REG2] = REG2

33. BUFFER_OVERFLOW [MEDIUM]
   Location: 0x108
   Description: Write to tainted memory address
   Details:
     dst: @64[MSR2 + REG3]
     ptr: MSR2 + REG3
     src: REG3
     risk: Potential buffer overflow through controlled addressing
     assignment: @64[MSR2 + REG3] = REG3

========================================
EXECUTIVE SUMMARY
========================================
Total vulnerabilities: 33
🔴 Critical: 10
🟠 High: 10
🟡 Medium: 13
🔧 Assignments reconstructed: 27
🧬 Tainted expressions: 41

⚠️  SECURITY VULNERABILITIES DETECTED!
🎯 Universal analyzer successfully found vulnerabilities!

🔍 VULNERABILITY BREAKDOWN BY TYPE:
   • privilege_escalation: 9
   • microcode_injection: 1
   • buffer_overflow: 16
   • information_leak: 7

📋 CRITICAL RECOMMENDATIONS:
   🚨 IMMEDIATELY address 10 critical vulnerabilities
   🚨 These may allow complete system compromise
   🔥 URGENT: 1 microcode injection vulnerabilities found!
   🔥 These allow arbitrary microcode execution - patch immediately!
   ⚠️  Prioritize 10 high-severity issues
   🔒 Implement microcode privilege separation
   🛡️  Add segment access control validation
   🔍 Audit all inter-segment data flows
   ⚡ Consider microcode code signing
   🚫 Disable UCODE segment writes if not needed
   🧬 Implement runtime taint tracking

============================================================
UNIVERSAL MICROCODE SECURITY ANALYSIS COMPLETE
============================================================
```

## Ack
- [Zentool](https://github.com/google/security-research/tree/master/pocs/cpus/entrysign/zentool)
- [AngryUEFI](https://github.com/AngryUEFI/AngryUEFI), [AngryCAT](https://github.com/AngryUEFI/AngryCAT)
