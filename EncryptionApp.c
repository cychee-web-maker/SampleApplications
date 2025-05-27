#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>

// Function to encrypt using AES-192-GCM
void encrypt_AES192_GCM(const unsigned char *plaintext, const unsigned char *key, const unsigned char *iv,
                        unsigned char *ciphertext, unsigned char *tag) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_192_gcm(), NULL, key, iv);

    int len;
    EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, strlen((char*)plaintext));

    // Finalize encryption
    EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);

    // Get authentication tag
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag);

    EVP_CIPHER_CTX_free(ctx);
}

// Function to decrypt using AES-192-GCM
int decrypt_AES192_GCM(const unsigned char *ciphertext, const unsigned char *key, const unsigned char *iv,
                       const unsigned char *tag, unsigned char *decryptedtext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_192_gcm(), NULL, key, iv);

    int len, ret;
    EVP_DecryptUpdate(ctx, decryptedtext, &len, ciphertext, strlen((char*)ciphertext));

    // Set expected authentication tag
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void *)tag);

    // Finalize decryption & verify authentication
    ret = EVP_DecryptFinal_ex(ctx, decryptedtext + len, &len);

    EVP_CIPHER_CTX_free(ctx);

    return ret;  // Returns 1 if authentication succeeds, 0 otherwise
}

int main() {
    // AES-192 key (24 bytes)
    unsigned char key[24] = "0123456789abcdef01234567";
    // AES-GCM IV (12 bytes recommended)
    unsigned char iv[12] = "abcdef987654";
    // Example plaintext
    unsigned char plaintext[] = "Hello, AES-192-GCM!";
    // Buffers for encrypted & decrypted text
    unsigned char ciphertext[128], decryptedtext[128], tag[16];

    // Encrypt the plaintext
    encrypt_AES192_GCM(plaintext, key, iv, ciphertext, tag);
    printf("Encrypted text: %s\n", ciphertext);
    printf("Tag: %s\n", tag);

    // Decrypt the ciphertext
    int success = decrypt_AES192_GCM(ciphertext, key, iv, tag, decryptedtext);
    if (success)
        printf("Decrypted text: %s\n", decryptedtext);
    else
        printf("Decryption failed: Authentication error!\n");

    return 0;
}

