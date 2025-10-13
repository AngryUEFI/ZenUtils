.arch Zen1
.date 0x10102025
.revision 0x0800820E
.format 0x8004
.cpuid 0x00008082

; implements rbx = strlen(rax)

.match_reg 0, 0xc98
mov    reg15, rax

loop:
mov.b    reg14, ls:[reg15]
and.Z    reg0, reg14, reg14
jz.z     end
add      reg15, reg15, 1
.sw_branch loop

end:
sub rbx, reg15, rax
.sw_complete