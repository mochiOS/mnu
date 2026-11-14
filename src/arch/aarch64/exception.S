// One 128-byte slot per source/kind, on the architectural 2-KiB boundary.
// SP0 entries switch to the trusted EL1 stack before touching any memory.
.section .text.vectors, "ax"
.balign 2048
.global mnu_aarch64_vectors
mnu_aarch64_vectors:
.macro vector origin, kind
    .if \origin == 0
    msr spsel, #1
    .endif
    sub sp, sp, #{frame_size}
    stp x0, x1, [sp, #0]
    mov x0, #\origin
    mov x1, #\kind
    b .Lexception_save
    .balign 128
.endm
vector 0, 0
vector 0, 1
vector 0, 2
vector 0, 3
vector 1, 0
vector 1, 1
vector 1, 2
vector 1, 3
vector 2, 0
vector 2, 1
vector 2, 2
vector 2, 3
vector 3, 0
vector 3, 1
vector 3, 2
vector 3, 3
.size mnu_aarch64_vectors, . - mnu_aarch64_vectors

.Lexception_save:
    stp x2, x3, [sp, #16]
    stp x4, x5, [sp, #32]
    stp x6, x7, [sp, #48]
    stp x8, x9, [sp, #64]
    stp x10, x11, [sp, #80]
    stp x12, x13, [sp, #96]
    stp x14, x15, [sp, #112]
    stp x16, x17, [sp, #128]
    stp x18, x19, [sp, #144]
    stp x20, x21, [sp, #160]
    stp x22, x23, [sp, #176]
    stp x24, x25, [sp, #192]
    stp x26, x27, [sp, #208]
    stp x28, x29, [sp, #224]
    str x30, [sp, #240]
    str x0, [sp, #{origin}]
    str x1, [sp, #{kind}]
    mrs x0, sp_el0
    str x0, [sp, #{user_sp}]
    mrs x0, elr_el1
    mrs x1, spsr_el1
    stp x0, x1, [sp, #{pc}]
    mrs x0, esr_el1
    mrs x1, far_el1
    stp x0, x1, [sp, #{esr}]
    mrs x0, fpcr
    mrs x1, fpsr
    stp x0, x1, [sp, #{fpcr}]
    stp q0, q1, [sp, #{simd} + 0]
    stp q2, q3, [sp, #{simd} + 32]
    stp q4, q5, [sp, #{simd} + 64]
    stp q6, q7, [sp, #{simd} + 96]
    stp q8, q9, [sp, #{simd} + 128]
    stp q10, q11, [sp, #{simd} + 160]
    stp q12, q13, [sp, #{simd} + 192]
    stp q14, q15, [sp, #{simd} + 224]
    stp q16, q17, [sp, #{simd} + 256]
    stp q18, q19, [sp, #{simd} + 288]
    stp q20, q21, [sp, #{simd} + 320]
    stp q22, q23, [sp, #{simd} + 352]
    stp q24, q25, [sp, #{simd} + 384]
    stp q26, q27, [sp, #{simd} + 416]
    stp q28, q29, [sp, #{simd} + 448]
    stp q30, q31, [sp, #{simd} + 480]
    mov x0, sp
    bl mnu_aarch64_exception_entry
    // The dispatcher may have enabled IRQs. Close the return window before
    // programming ELR/SPSR; a nested exception must not overwrite those values.
    msr daifset, #15
    cbnz x0, .Lexception_halt
    ldr x0, [sp, #{user_sp}]
    msr sp_el0, x0
    ldp x0, x1, [sp, #{pc}]
    msr elr_el1, x0
    msr spsr_el1, x1
    ldp x0, x1, [sp, #{fpcr}]
    msr fpcr, x0
    msr fpsr, x1
    ldp q0, q1, [sp, #{simd} + 0]
    ldp q2, q3, [sp, #{simd} + 32]
    ldp q4, q5, [sp, #{simd} + 64]
    ldp q6, q7, [sp, #{simd} + 96]
    ldp q8, q9, [sp, #{simd} + 128]
    ldp q10, q11, [sp, #{simd} + 160]
    ldp q12, q13, [sp, #{simd} + 192]
    ldp q14, q15, [sp, #{simd} + 224]
    ldp q16, q17, [sp, #{simd} + 256]
    ldp q18, q19, [sp, #{simd} + 288]
    ldp q20, q21, [sp, #{simd} + 320]
    ldp q22, q23, [sp, #{simd} + 352]
    ldp q24, q25, [sp, #{simd} + 384]
    ldp q26, q27, [sp, #{simd} + 416]
    ldp q28, q29, [sp, #{simd} + 448]
    ldp q30, q31, [sp, #{simd} + 480]
    ldp x0, x1, [sp, #0]
    ldp x2, x3, [sp, #16]
    ldp x4, x5, [sp, #32]
    ldp x6, x7, [sp, #48]
    ldp x8, x9, [sp, #64]
    ldp x10, x11, [sp, #80]
    ldp x12, x13, [sp, #96]
    ldp x14, x15, [sp, #112]
    ldp x16, x17, [sp, #128]
    ldp x18, x19, [sp, #144]
    ldp x20, x21, [sp, #160]
    ldp x22, x23, [sp, #176]
    ldp x24, x25, [sp, #192]
    ldp x26, x27, [sp, #208]
    ldp x28, x29, [sp, #224]
    ldr x30, [sp, #240]
    add sp, sp, #{frame_size}
    eret
.Lexception_halt:
    wfi
    b .Lexception_halt
