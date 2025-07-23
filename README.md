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

## Ack
- [Zentool](https://github.com/google/security-research/tree/master/pocs/cpus/entrysign/zentool)
- [AngryUEFI](https://github.com/AngryUEFI/AngryUEFI), [AngryCAT](https://github.com/AngryUEFI/AngryCAT)
