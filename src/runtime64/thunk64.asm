; thunk64.asm - call a real Win64 function with the guest's arguments.
;
; The guest is a Win64 PE and the host is Win64, so the calling convention on
; both sides is the same one: RCX, RDX, R8, R9 then the stack, floats in
; XMM0-3, return in RAX or XMM0, 32 bytes of shadow space above the return
; address. That means an import does not have to be reimplemented - it can be
; forwarded to the real DLL, which is already on this machine.
;
; This copies the guest's stack arguments onto the host stack rather than
; switching RSP to the guest stack. Switching would be fewer instructions, but
; it hands a callee inside kernel32 a stack this process did not allocate as a
; stack - no guard page, no thread stack limits in the TEB matching it - and the
; failure mode is a stack probe in a large frame walking off the end of the
; guest allocation. Copying keeps every native callee on a real thread stack.
;
; The frame struct has an explicit layout that the C side asserts against,
; rather than the CPU struct: hardcoding CPU offsets in assembly means a field
; added to the struct silently changes what this reads.

OPTION CASEMAP:NONE

; HLEFRAME layout - see thunk64.h, which static_asserts every offset.
F_FN      EQU   0
F_RCX     EQU   8
F_RDX     EQU  16
F_R8      EQU  24
F_R9      EQU  32
F_STACK   EQU  40          ; address of the guest's 5th-argument slot
F_NSTACK  EQU  48          ; how many qwords to copy from there
F_X0      EQU  64
F_X1      EQU  80
F_X2      EQU  96
F_X3      EQU 112
F_RAXOUT  EQU 128
F_XMMOUT  EQU 144

.CODE

; void hle_invoke(HLEFRAME *f)     ; rcx = f
PUBLIC hle_invoke
hle_invoke PROC
        push    rbx
        push    rsi
        push    rdi
        push    rbp
        mov     rbp, rsp                ; a fixed anchor to unwind to
        mov     rbx, rcx                ; rbx = frame, survives the call

        ; ---- make room: 32 bytes of shadow space plus the copied arguments,
        ; ---- then force RSP to a 16-byte boundary. The ABI requires RSP to be
        ; ---- 16-aligned at the CALL, so the callee sees RSP+8 aligned.
        mov     rax, QWORD PTR [rbx + F_NSTACK]
        lea     rax, [rax*8 + 32]
        add     rax, 15
        and     rax, -16
        sub     rsp, rax
        and     rsp, -16

        ; ---- copy the stack arguments above the shadow space ----
        mov     rcx, QWORD PTR [rbx + F_NSTACK]
        test    rcx, rcx
        jz      copied
        mov     rsi, QWORD PTR [rbx + F_STACK]
        xor     rdx, rdx
copy_loop:
        mov     rax, QWORD PTR [rsi + rdx*8]
        mov     QWORD PTR [rsp + 32 + rdx*8], rax
        inc     rdx
        cmp     rdx, rcx
        jb      copy_loop
copied:

        ; ---- the register arguments. Integer and float both: a variadic
        ; ---- callee reads a float argument from BOTH the GPR and the XMM, and
        ; ---- printf("%f") is exactly that case.
        movups  xmm0, XMMWORD PTR [rbx + F_X0]
        movups  xmm1, XMMWORD PTR [rbx + F_X1]
        movups  xmm2, XMMWORD PTR [rbx + F_X2]
        movups  xmm3, XMMWORD PTR [rbx + F_X3]
        mov     rdx, QWORD PTR [rbx + F_RDX]
        mov     r8,  QWORD PTR [rbx + F_R8]
        mov     r9,  QWORD PTR [rbx + F_R9]
        mov     rax, QWORD PTR [rbx + F_FN]
        mov     rcx, QWORD PTR [rbx + F_RCX]

        call    rax

        ; ---- results ----
        mov     QWORD PTR [rbx + F_RAXOUT], rax
        movups  XMMWORD PTR [rbx + F_XMMOUT], xmm0

        mov     rsp, rbp
        pop     rbp
        pop     rdi
        pop     rsi
        pop     rbx
        ret
hle_invoke ENDP

END
