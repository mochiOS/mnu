ENTRY(domain_entry)

SECTIONS
{
    . = 0x10000;

    .text : ALIGN(4096)
    {
        __text_start = .;
        KEEP(*(.text.domain_entry))
        *(.text .text.*)
        __text_end = .;
    }

    .rodata : ALIGN(4096)
    {
        *(.rodata .rodata.*)
    }

    .data : ALIGN(4096)
    {
        *(.data .data.*)
    }

    .bss : ALIGN(4096)
    {
        *(.bss .bss.*)
        *(COMMON)
    }

    /DISCARD/ :
    {
        *(.eh_frame .eh_frame_hdr)
        *(.comment)
    }
}
