char __attribute__((aligned(0x1000))) buffer[4096];
char __attribute__((aligned(0x1000))) captured[4096];


static void flush(void *p)
{
	  asm volatile("clflush 0(%0)\n" : : "c"(p) : "rax");
	  asm volatile("mfence\n");
}

void *get_buffer_addr( void )
{
  return &buffer;
}

void flush_buffer( void )
{
    for (int i = 0; i < 4096; i += 64) {
        flush(&buffer[i]);
    }
}

void initialize_buffer( void )
{
    for (int i = 0; i < 4096; ++i) {
        buffer[i] = i%256;
    }

    // Flush the written value to DRAM so it is visible from the alias
    flush_buffer();
}

void capture_buffer( void )
{
    // This requires buffer to be flushed from the cache.
    // Note, we cannot flush buffer here because at this point the interposer
    // is active.
    for (int i = 0; i < 4096; ++i) {
        captured[i] = buffer[i];
    }
}

void replay_buffer( void )
{
    for (int i = 0; i < 4096; ++i) {
        buffer[i] = captured[i];
    }

    // Ensure the replayed content is written to DRAM
    flush_buffer();
}
