#include "uECC.h"
#include <stdint.h> // int64_t
#include <time.h>   // clock_gettime
#include <stdio.h>  // printf
#include <string.h> // memcpy


int64_t nanoticks(void) {
    struct timespec ts;
    clock_gettime(CLOCK_BOOTTIME, &ts);
    return (ts.tv_sec * 1000000000LL) + ts.tv_nsec;
}

#define NS_TO_S(x) (x)*(1e-09f)
int main(int argc, char ** argv) {
    uint8_t private[32] = {0};
    uint8_t public[64] = {0};
    uint8_t hash[32] = {0};
    uint8_t sig[64] = {0};

    const struct uECC_Curve_t * curve = uECC_secp256r1();
    int64_t a, b;
    a = nanoticks();
    if (!uECC_make_key(public, private, curve)) {
        printf("uECC_make_key() failed\n");
        return 1;
    }
    b = nanoticks();
    printf("uECC_make_key in %f s\n", NS_TO_S((b-a)));
    memcpy(hash, public, sizeof(hash));

    // generate random data which represents the hash of a message
    uECC_RNG_Function rng = uECC_get_rng();
    rng(hash, sizeof(hash));

    printf("\nUsing standard ECDSA algorithm =========================\n");
    a = nanoticks();
    if (!uECC_sign(private, hash, sizeof(hash), sig, curve)) {
        printf("uECC_sign() failed\n");
        return 1;
    }
    b = nanoticks();
    printf("uECC_sign in %f s\n", NS_TO_S((b-a)));

    a = nanoticks();
    if (!uECC_verify(public, hash, sizeof(hash), sig, curve)) {
        printf("uECC_verify() failed\n");
        return 1;
    }
    b = nanoticks();
    printf("uECC_verify in %f s\n", NS_TO_S((b-a)));

    printf("\nUsing pre-compute ECDSA algorithm =========================\n");
    uECC_SignatureContext ctx;

    a = nanoticks();
    if (!uECC_sign_init(&ctx, private, sig, curve)) {
        printf("uECC_sign_init() failed\n");
        return 1;
    }
    b = nanoticks();
    printf("uECC_sign_init in %f s\n", NS_TO_S((b-a)));

    a = nanoticks();
    if (!uECC_sign_finish(&ctx, hash, sizeof(hash))) {
        printf("uECC_sign_finish() failed\n");
        return 1;
    }
    b = nanoticks();
    printf("uECC_sign_finish in %f s\n", NS_TO_S((b-a)));

    a = nanoticks();
    if (!uECC_verify(public, hash, sizeof(hash), sig, curve)) {
        printf("uECC_verify() failed\n");
        return 1;
    }
    b = nanoticks();
    printf("uECC_verify in %f s\n", NS_TO_S((b-a)));
}
