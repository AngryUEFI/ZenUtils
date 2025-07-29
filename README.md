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

## Ack
- [Zentool](https://github.com/google/security-research/tree/master/pocs/cpus/entrysign/zentool)
- [AngryUEFI](https://github.com/AngryUEFI/AngryUEFI), [AngryCAT](https://github.com/AngryUEFI/AngryCAT)
