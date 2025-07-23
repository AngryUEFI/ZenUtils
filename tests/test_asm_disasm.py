import pytest
from arch.registry import Registry, ArchSpec
from asm import assemble_single
from disasm import disassemble_single

data = [
    (0x382F9E108CE00000, "add.n reg1, reg3, reg7"),
    (0x382F9C1000000000, "add reg0, reg0, reg0"),
    (0x382F9C108C080042, "add reg1, reg3, 0x42"),
    (0x382F9E108C080042, "add.n reg1, reg3, 0x42"),
    (0x385A8FF08C080042, "xor.zcZCnd reg1, reg3, 0x42"),
    (0x20021C2000081FC0, "jz.z 0x1fc0"),
    (0x20049C0000081FE2, "jge 0x1fe2"),
    (0x286F3C1EF0008400, "mov r13, cpuid:[r12]"),
    (0x18505C073C07B000, "mov msr2:[reg15], reg14"),
    (0x286F20173DC09820, "mov.b reg14, ls:[reg15 + reg14 + 0x20]"),
    (0x38501C1080E00000, "mov reg1, reg7"),
    (0x38501C1080084242, "mov reg1, 0x4242")
]

def test_assemble_single():
    reg = Registry()
    zen2 = reg.get('Zen2')

    for expected, assembly in data:
        assert assemble_single(zen2, assembly) == expected

def test_disassemble_single():
    reg = Registry()
    zen2 = reg.get('Zen2')

    for word, expected in data:
        assert disassemble_single(zen2, word) == expected
