#include "rc4.h"
#include <openssl/evp.h>
#include <openssl/err.h>
#include <cstdio>
#include <cstdlib>

// code taken from EVP_example.cxx from class examples

void Error()
{
    ERR_print_errors_fp(stderr);
    abort();
}

int decryptRC4(unsigned char *ciphertext, int ciphertextLength, unsigned char *key, unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx;
    int length;
    int plaintextLength;

    // create and initialize the context
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
    {
        Error();
    }

    // initialize the decrpytion operation
    if (1 != EVP_DecryptInit_ex(ctx, EVP_rc4(), NULL, key, NULL))
    {
        Error();
    }

    // provide the message to be decrypted and obtain plaintext output
    if (1 != EVP_DecryptUpdate(ctx, plaintext, &length, ciphertext, ciphertextLength))
    {
        Error();
    }
    plaintextLength = length;

    // finilize the decryption. further plaintext can be written
    if (1 != EVP_DecryptFinal_ex(ctx, plaintext + length, &length))
    {
        Error();
    }
    plaintextLength += length;

    // cleanup
    EVP_CIPHER_CTX_free(ctx);
    return plaintextLength;
}