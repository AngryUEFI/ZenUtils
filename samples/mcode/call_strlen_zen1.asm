; call_strlen.asm
; Uses the strlen microcode patch (hooked on FCOS) to compute the length of str_input.
; Contract: RBX <- strlen(RAX)

        bits 64
        default rel

section .text
global _start

_start:
        ; Preserve CoreContext* and locate result buffer.
        mov     r10, rax
        mov     rdi, [r10]

        ; Prepare inputs for the microcode patch.
        lea     rax, [rel str_input]
        xor     rbx, rbx

        fninit                  ; ensure x87 is in a known state
        fcos                    ; patched microcode overwrites RBX with strlen(RAX)

        ; Write the computed length to the result buffer.
        mov     [rdi], rbx

        xor     eax, eax        ; AngryUEFI expects RAX cleared on return
        ret

section .data
str_input:
        db "hello world omg it workiedd", 0
