.arch Zen1
.date 0x10102025
.revision 0x08008211
.format 0x8004
.cpuid 0x00008082

.match_reg 0, 0xc98

; Subleq Register Layout:
; reg0: Zero Register
; r8: mem_a/op_a
; r9: mem_b
; r10: op_b
; r11: jmp_c
; r12: halt_check
; reg9: program_counter
; reg10: base address of data memory (result buffer + 512 bytes)

; Get the result buffer address from CoreContext (passed in rax)
mov rbx, ls:[rax+reg0+0] ; Dereference CoreContext->ResultBuffer into rbx, rbx now holds the address

mov reg9, rbx           ; Initialise program counter to start of result buffer, where program will exist
add reg10, reg9, 512    ; reg10 = [rax + 512] , start of result data buffer

mov r8, reg0            ; Clear op_a/mem_a
mov r9, reg0            ; Clear mem_b
mov r10, reg0           ; Clear op_b
mov r11, reg0           ; Clear jmp_c
mov r12, reg0           ; Clear halt check register
sub r12, reg0, 1        ; r12 = -1
mov r13, reg0           ; time stamp register, starts from 0

; Start of Subleq Loop
SUBLEQ_LOOP:
    ; Increment time stamp
    add r13, r13, 1
    ; Load operands from memory into registers
    ; Load op_a
    mov r8, ls:[reg9+reg0+0]
    ; Load op_b
    mov r10, ls:[reg9+reg0+8]
    ; Load mem_a
    mov r8, ls:[reg10+r8]
    ; Load mem_b
    mov r9, ls:[reg10+r10]

    ; Load jmp_c
    mov r11, ls:[reg9+reg0+16]

    ; Perform subleq operation
    ; mem_b = mem_b - mem_a
    sub.CZ r9, r9, r8

    ; Store the result back to memory
    mov ls:[reg10+r10], r9

    ; If mem_b <= 0, jump to BRANCH_TAKEN
    jbe.cz  BRANCH_TAKEN

    ; If mem_b > 0, increment program counter to next instruction (3 * 8 bytes)
    add reg9, reg9, 24
    ; Repeat the loop
    .sw_branch SUBLEQ_LOOP

; Subleq branch is taken
BRANCH_TAKEN:
    ; Check for halt condition
    ; Halt if branch is taken and jmp_c is -1
    sub.Z reg0, r11, r12
    ; If jmp_c == -1, halt the program
    je.z END_SUBLEQ_LOOP

    ; Set data pointer to jmp_c
    ; r11 (jmp_c) is the slot offset
    ; Add slot offset to base address
    add reg9, rbx, r11

    ; next loop iteration
    .sw_branch SUBLEQ_LOOP

END_SUBLEQ_LOOP:
    ; Cleanup and exit
    ; Clear op_a/mem_a
    mov r8, reg0
    ; Clear mem_b
    mov r9, reg0
    ; Clear op_b
    mov r10, reg0
    ; Clear jmp_c
    mov r11, reg0

    ; Return 1 in result buffer + 504 (last variable) to indicate success
    mov.q r12, 1
    mov ls:[reg10+504], r12
    ; Clear halt check register
    mov r12, reg0

    mov ls:[reg10+496], r13  ; Store time stamp in result buffer + 496
    .sw_complete
