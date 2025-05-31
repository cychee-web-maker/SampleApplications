#include "SHA3_test.h"

void sha3_256(const char *input, unsigned char *output) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha3_256(), NULL);
    EVP_DigestUpdate(ctx, input, strlen(input));
    EVP_DigestFinal_ex(ctx, output, NULL);
    EVP_MD_CTX_free(ctx);
}
