/*
 *  This file is part of the SGX-Step enclave execution control framework.
 *
 *  Copyright (C) 2017 Jo Van Bulck <jo.vanbulck@cs.kuleuven.be>,
 *                     Raoul Strackx <raoul.strackx@cs.kuleuven.be>
 *
 *  SGX-Step is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  SGX-Step is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with SGX-Step. If not, see <http://www.gnu.org/licenses/>.
 */
#include "sgx_report.h"
#include <sgx_utils.h>
#include <string.h>

/* sgx_sign dump -enclave libsgx_pce.signed.so -dumpfile out.dump 
 * also checked with sgx-tracer:
 * 	SECS: size=4194304; base=0x7fb9df800000; ssa_frame_size=1; miscselect=0; attributes=0x14; xfrm=231
 * MRENCLAVE: 4e4345fdd5a62736f935ed072a70026cb6ab5e1d5db4aa7dce9784d4c5f659d5
 */
const uint8_t pce_mrenclave[SGX_HASH_SIZE] = {0x4e, 0x43, 0x45, 0xfd, 0xd5, 0xa6, 0x27, 0x36, \
                                   0xf9, 0x35, 0xed, 0x07, 0x2a, 0x70, 0x02, 0x6c, \
                                   0xb6, 0xab, 0x5e, 0x1d, 0x5d, 0xb4, 0xaa, 0x7d, \
                                   0xce, 0x97, 0x84, 0xd4, 0xc5, 0xf6, 0x59, 0xd5 };

void mk_report(sgx_report_t *report, sgx_target_info_t *target_info)
{
    memset(target_info, 0x0, sizeof(sgx_target_info_t));
    memcpy(&target_info->mr_enclave.m, pce_mrenclave, SGX_HASH_SIZE);
    target_info->attributes.flags = SGX_FLAGS_INITTED | SGX_FLAGS_MODE64BIT | SGX_FLAGS_PROVISION_KEY; // 0x15
    target_info->attributes.xfrm = SGX_XFRM_LEGACY | SGX_XFRM_AVX512; //0xe7 = 231
    target_info->misc_select = 0x0;
    target_info->config_svn = 0x0;

    sgx_report_data_t report_data = {
        .d = {0xde, 0xad, 0xbe, 0xef},
    };
 
    sgx_create_report(target_info, &report_data, report);
}
