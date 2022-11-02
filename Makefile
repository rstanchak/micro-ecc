COMPILE=$(CC) -I. $^ -g -o $@

all: ecdsa_test_vectors \
	public_key_test_vectors \
	test_compress \
	test_compute \
	test_ecdh \
	test_ecdsa \
	signbench

ecdsa_test_vectors: uECC.c test/ecdsa_test_vectors.c
	$(COMPILE)
public_key_test_vectors: uECC.c test/public_key_test_vectors.c
	$(COMPILE)
test_compress: uECC.c test/test_compress.c
	$(COMPILE)
test_compute: uECC.c test/test_compute.c
	$(COMPILE)
test_ecdh: uECC.c test/test_ecdh.c
	$(COMPILE)
test_ecdsa: uECC.c test/test_ecdsa.c
	$(COMPILE)
signbench: uECC.c test/signbench.c
	$(COMPILE)
