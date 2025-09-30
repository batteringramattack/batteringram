# Scalable SGX Attacks

This directory contains proof-of-concept implementations of the Scalable SGX attacks. Each subdirectory includes a more detailed README describing its specific setup and usage.

* `./simple-replay` demonstrates the ability to replay ciphertexts.
* `./simple-read` shows how Intel's Total Memory Encryption (TME) single-key domain can be exploited for arbitrary plaintext access.
* `./pce` demonstrates an end-to-end attack that extracts the provisioning key from the PCE.
