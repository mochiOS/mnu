ENTRY(_start)
SECTIONS {
    . = 0x40080000;
    .text : {
        __text_start = .;
        KEEP(*(.text.entry)) *(.text.vectors) *(.text .text.*)
        . = ALIGN(4096);
        __text_end = .;
    }
    .user_text : ALIGN(4096) {
        __user_text_start = .;
        KEEP(*(.user.text))
        . = ALIGN(4096);
        __user_text_end = .;
    }
    .rodata : ALIGN(4096) {
        __rodata_start = .;
        *(.rodata .rodata.*)
        . = ALIGN(4096);
        __rodata_end = .;
    }
    .data : ALIGN(4096) {
        __data_start = .;
        *(.data .data.*)
        . = ALIGN(4096);
        __data_end = .;
    }
    .bss (NOLOAD) : ALIGN(4096) {
        __bss_start = .;
        *(.bss .bss.*) *(COMMON)
        . = ALIGN(4096);
        __user_stack_start = .;
        *(.user.stack)
        . = ALIGN(4096);
        __user_stack_end = .;
        __bss_end = .;
        . += 65536;
        __stack_top = .;
    }
    /DISCARD/ : { *(.eh_frame*) *(.note*) }
}
