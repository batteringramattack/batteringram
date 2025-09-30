#define BUFSIZE 4096*29
char __attribute__((aligned(0x1000))) buffer[BUFSIZE];

static void flush(void *p)
{
	  asm volatile("clflush 0(%0)\n" : : "c"(p) : "rax");
	  asm volatile("mfence\n");
}

void are_flush_buffer( void )
{
    for (int i = 0; i < BUFSIZE; i += 64) {
        flush(&buffer[i]);
    }
}

void *are_get_buffer_addr( void )
{
  return &buffer;
}

void are_initialize_buffer( void )
{
    for (int i = 0; i < BUFSIZE; ++i) {
        buffer[i] = i%256;
    }

    // Flush the written value to DRAM so it is visible from the alias
    are_flush_buffer();
}

void are_write_to_buffer(char c)
{
    for (int i = 0; i < BUFSIZE; ++i) {
        buffer[i] = c;
    }
    are_flush_buffer();
}

void are_print_buffer( void )
{
    custom_hexdump(buffer, sizeof(buffer));
}
