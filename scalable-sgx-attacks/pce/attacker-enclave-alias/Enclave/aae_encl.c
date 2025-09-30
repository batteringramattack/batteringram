#define BUFSIZE 4096*29
char __attribute__((aligned(0x1000))) buffer[BUFSIZE];
char __attribute__((aligned(0x1000))) captured[BUFSIZE];


static void flush(void *p)
{
	  asm volatile("clflush 0(%0)\n" : : "c"(p) : "rax");
	  asm volatile("mfence\n");
}

void *aae_get_buffer_addr( void )
{
  return &buffer[0];
}

void aae_flush_buffer( void )
{
    for (int i = 0; i < BUFSIZE; i += 64) {
        flush(&buffer[i]);
    }
}

void aae_initialize_buffer( void )
{
    for (int i = 0; i < BUFSIZE; ++i) {
        buffer[i] = i%256;
    }

    // Flush the written value to DRAM so it is visible from the alias
    aae_flush_buffer();
}

void aae_capture_buffer( void )
{
    // This requires buffer to be flushed from the cache.
    // Note, we cannot flush buffer here because at this point the interposer
    // is active.
    for (int i = 0; i < BUFSIZE; ++i) {
        captured[i] = buffer[i];
    }
}

void aae_replay_buffer( void )
{
    for (int i = 0; i < BUFSIZE; ++i) {
        buffer[i] = captured[i];
    }

    // Ensure the replayed content is written to DRAM
    aae_flush_buffer();
}
