from cryptography.hazmat.primitives import cmac
from cryptography.hazmat.primitives.ciphers import algorithms
from ecdsa import NIST256p, SigningKey
import sys

# Derive the Provisioning Certification Key (PCK) from the provisioning key.
# This python script implements the ECDSA private key derivation from 
# `get_pce_priv_key` in `./psw/ae/pce/pce_helper.cpp` of linux-sgx.

# 128-bit provisioning key
provisioning_key = sys.argv[1]
pkey_seed = bytes.fromhex(provisioning_key)

print("pkey_seed: " + provisioning_key)

PAK_STRING = b"PAK_KEY_DER"

def aes_cmac_block(seed, counter):
    content = bytearray(16)
    content[0] = counter
    content[1:12] = PAK_STRING
    content[14] = 0x01
    content[15] = 0x40
    c = cmac.CMAC(algorithms.AES(seed))
    c.update(bytes(content))
    return c.finalize()

# Generate 3 blocks
block1 = aes_cmac_block(pkey_seed, 1)
block2 = aes_cmac_block(pkey_seed, 2)
block3 = aes_cmac_block(pkey_seed, 3)

# Concatenate and take first 320 bits
hash_drbg = block1 + block2 + block3[:8]

# Swap endianness
hash_drbg = bytearray(hash_drbg)
for i in range(len(hash_drbg)//2):
    j = len(hash_drbg)-1-i
    hash_drbg[i], hash_drbg[j] = hash_drbg[j], hash_drbg[i]

print("hash_drg_output: ", hash_drbg.hex())

# Derive ECDSA private key
N = NIST256p.order
drbg_int = int.from_bytes(hash_drbg, 'little')
priv_int = (drbg_int % (N - 1)) + 1
priv_key_bytes = priv_int.to_bytes(32, 'little')

# Compute public key
sk = SigningKey.from_string(priv_key_bytes, curve=NIST256p)
vk = sk.verifying_key

print("ECDSA Private Key:", priv_key_bytes.hex())

ecdsa_pub_x = vk.pubkey.point.x().to_bytes(32,'little').hex()
ecdsa_pub_y = vk.pubkey.point.y().to_bytes(32,'little').hex()
print("ECDSA Public Key (PCK):", ecdsa_pub_x+ecdsa_pub_y)
