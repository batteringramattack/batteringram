# Patches for the Scalable SGX attacks

## Linux SGX driver patches

This folder contains the patches for the [out-of-tree Linux SGX driver](https://github.com/intel/linux-sgx-driver).

* `linux-sgx-driver.patch`  
  Modifies the legacy SGX driver’s EPC allocation to ensure all pages reside in regions unaffected by the interposer, allowing enclaves to run while the interposer is active. Additionally, it adds an interface to request a specific EPC page at a given physical address. This functionality is used, for example, to allocate an attacker EPC page that aliases with a victim EPC page.
  > [!NOTE]  
  > This patch includes hardcoded physical addresses, which may need to be adjusted based on the installed DIMMs and the physical-to-DRAM address mapping of your system.
* `linux-sgx-driver-lepubkeyhash.patch`  
  Ports FLC support to the out-of-tree kernel module.
* `linux-sgx-driver-vm_flags.patch`  
  Updates the driver to compile on kernels version 6.3 and above.

## SGX-Step patch

A small patch enabling the sgx_step device to be opened multiple times.
