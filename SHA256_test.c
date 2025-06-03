#include <stdio.h>
#include <string.h>
#include <openssl/sha.h>

void sha256_hash(const char *input, unsigned char *output) {
    // Just add comment
    // Comment to test CI/CD scan for this file changed.
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, input, strlen(input));
    SHA256_Final(output, &ctx);
}
