/* Freestanding ELF fixture, linked by real Clang/LLD for the target CPU. */
unsigned long values[2] = {0x11, 0x22};
unsigned long *pointer = values + 1;
static unsigned long local_value = 0x33;
unsigned long *local_pointer = &local_value;
__thread unsigned long tls_value = 0x44;

unsigned long probe_entry(void) {
    return *pointer + *local_pointer + tls_value;
}
