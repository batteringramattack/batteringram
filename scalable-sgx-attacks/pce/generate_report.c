#include <sgx_urts.h>
#include <sgx_report.h>
#include <signal.h>
#include <sys/reg.h>
#include <unistd.h>
#include <sys/mman.h>

#include "libsgxstep/apic.h"
#include "libsgxstep/pt.h"
#include "libsgxstep/sched.h"
#include "libsgxstep/enclave.h"
#include "libsgxstep/debug.h"
#include "libsgxstep/file.h"
#include "Enclave/encl_u.h"

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

void *target_ptr = NULL, *target_page = NULL;
int fault_fired = 0, aep_fired = 0;
sgx_enclave_id_t eid = 0;

#define ECC_SIG_SIZE 64 // (sizeof(sgx_ec256_signature_t))

void dump_attributes(sgx_attributes_t *attr, const char *name)
{
    printf("    Attr(%s)->flags: 0x%" PRIx64 "\n", name, attr->flags);
    printf("      L--> INIT      = %d\n", !!(attr->flags & SGX_FLAGS_INITTED) );
    printf("      L--> DEBUG     = %d\n", !!(attr->flags & SGX_FLAGS_DEBUG) );
    printf("      L--> 64BIT     = %d\n", !!(attr->flags & SGX_FLAGS_MODE64BIT) );
    printf("      L--> PROV_KEY  = %d\n", !!(attr->flags & SGX_FLAGS_PROVISION_KEY) );
    printf("      L--> EINIT_KEY = %d\n", !!(attr->flags & SGX_FLAGS_EINITTOKEN_KEY) );
    printf("    Attr(%s)->XFRM:  0x%" PRIx64 "\n", name, attr->xfrm);
}

void dump_report(sgx_report_t *report, const char *name)
{
    printf("=== Local attestation REPORT: '%s' ===\n", name);
    printf("    CPU_SVN:     0x"); dump_hex(report->body.cpu_svn.svn, SGX_CPUSVN_SIZE);
    printf("    CONFIG_SVN:  0x%" PRIx16 "\n", report->body.config_svn);
    printf("    CONFIG_ID:   0x"); dump_hex(report->body.config_id, SGX_CONFIGID_SIZE);
    printf("    MISC_SEL:    0x%" PRIx32 "\n", report->body.misc_select);
    dump_attributes(&report->body.attributes, "Enclave");
    printf("    MRENCLAVE:   0x"); dump_hex(report->body.mr_enclave.m, SGX_HASH_SIZE);
    printf("    MRSIGNER:    0x"); dump_hex(report->body.mr_signer.m, SGX_HASH_SIZE);
    printf("    PROD_ID/SVN: 0x%" PRIx16 "/0x%" PRIx32 "\n", report->body.isv_prod_id, report->body.isv_svn);
    printf("    DATA:        0x"); dump_hex(report->body.report_data.d, SGX_REPORT_DATA_SIZE/2);
    printf("                   "); dump_hex(report->body.report_data.d+SGX_REPORT_DATA_SIZE/2, SGX_REPORT_DATA_SIZE/2);
    printf("    KEY_ID:      0x"); dump_hex(report->key_id.id, SGX_KEYID_SIZE);
    printf("    MAC:         0x"); dump_hex(report->mac, SGX_MAC_SIZE);
}

void dump_target_info(sgx_target_info_t *target_info, const char *name)
{
    printf("=== Local attestation TARGET INFO: '%s' ===\n", name);
    printf("    MRENCLAVE:   0x"); dump_hex(target_info->mr_enclave.m, SGX_HASH_SIZE);
    dump_attributes(&target_info->attributes, "Enclave");
    printf("    CONFIG_SVN:  0x%" PRIx16 "\n", target_info->config_svn);
    printf("    MISC_SEL:    0x%" PRIx32 "\n", target_info->misc_select);
    printf("    CONFIG_ID:   0x"); dump_hex(target_info->config_id, SGX_CONFIGID_SIZE);
}

/* Untrusted main function to create/enter the trusted enclave. */
int main( int argc, char **argv )
{
    sgx_enclave_id_t pce_eid, are_eid;
    int updated = 0;
    sgx_report_t report = {0};
    sgx_target_info_t target_info = {0};
    sgx_status_t pce_rv;
    uint8_t sig[ECC_SIG_SIZE] = {0};
    uint32_t pce_sig_out_sz;
    psvn_t pce_psvn = {
        .cpu_svn = 0,
        .isv_svn = 0
    };

    info_event("Creating and calling attacker report enclave at '" PCE_PATH "'");
    SGX_ASSERT( sgx_create_enclave( "Enclave/encl.so", /*dbg=*/1, NULL,
                                    &updated, &are_eid, NULL ));
    print_enclave_info();
    SGX_ASSERT( mk_report(are_eid, &report, &target_info) );
    dump_target_info(&target_info, "pce info");
    dump_report(&report, "pce report");

    SGX_ASSERT( sgx_destroy_enclave(are_eid) );
    file_write("./pce-report.bin", (uint8_t*)&report, sizeof(report));

    return 0;
}
