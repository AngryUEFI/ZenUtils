; call_fcos_mem.asm
; Invokes the FCOS load/store microcode patch and returns the value written by it.

        bits 64
        default rel

section .text
global _start

_start:
        ; Setup Subleq program in result buffer memory.
        mov     rdi, [rax]
        ; Instr 0: subleq 0, 8, 0
        mov     qword [rdi+0], 24
        mov     qword [rdi+8], 8
        mov     qword [rdi+16], 0
        ; Instr 1: subleq 0, 8, 0
        mov     qword [rdi+24], 16
        mov     qword [rdi+32], 8
        mov     qword [rdi+40], 0
        ; Instr 2: subleq 0,0,0xFFFFFFFFFFFFFFFF (to halt)
        mov     qword [rdi+48], 488
        mov     qword [rdi+56], 496
        mov     qword [rdi+64], -1

        ; Setup Subleq data in result buffer memory.
        mov     qword [rdi+520], 40      ; 8 = 40
        mov     qword [rdi+528], 5       ; 16 = 5
        mov     qword [rdi+536], 10      ; 24 = 10

        ; The CoreContext pointer is in rax. The microcode patch will use this.
        ; We don't need to do anything with it here, just preserve it across the fcos call.
        push    rax

        ; Trigger the microcode patch.
        fninit
        fcos

        pop     rax

        ; The microcode writes to the result buffer. The pointer to that buffer
        ; is the first field in CoreContext (pointed to by rax).
        mov     rdi, [rax]      ; rdi = result buffer pointer

        ; The microcode wrote 0x1337 to offset 0 and the CoreContext* to offset 8.
        ; Let's return the value from offset 0.
        mov     rax, [rdi+0]

        ret