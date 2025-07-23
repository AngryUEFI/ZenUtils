.arch Zen2
.date 0x07112025
.revision 0x08701040
.format 0x8004
.cpuid 0x00008710

; implements rbx = strlen(rax)

.match_reg 0, 0x420
mov    reg15, rax

loop:
mov.b    reg14, ls:[reg15]
and.Z    reg0, reg14, reg14
jz.z     0x1fc2                 ; Todo: add support for labels in instructions
add      reg15, reg15, 1
.sw_branch loop

end:
sub rbx, reg15, rax
.sw_complete