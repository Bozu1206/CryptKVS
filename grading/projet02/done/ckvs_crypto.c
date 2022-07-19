#include "ckvs.h"
#include "ckvs_crypto.h"
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>

//=======================================================================================
#define AUTH_MESSAGE "Auth Key"
#define C1_MESSAGE   "Master Key Encryption"
#define SEPARATOR    "|"
#define ERROR        "ERROR"

//=======================================================================================
/**
 * @date  20/03/2022
 * @brief Helper function to compute the HMAC signature for auth_key and c1.
 *
 * @param to_compute  (unsigned char*)   the value for which we have to compute the hmac (auth_key or cq).
 * @param mr          (ckvs_memrecord_t) contains the stretched key.
 * @param msg         (const char*)      the message that we will sign.
 *
 * @return (int) error code (@see error.h/c)
 */
static int compute_hmac(unsigned char *to_compute, ckvs_memrecord_t *mr, const char *msg)
{
    M_REQUIRE_NON_NULL_VARGS(to_compute, mr, msg);

    unsigned int to_compute_size = 0;
    HMAC(EVP_sha256(),
         mr->stretched_key.sha,
         SHA256_DIGEST_LENGTH,
         (const unsigned char *) msg,
         strlen(msg),
         to_compute,
         &to_compute_size);

    M_REQUIRE(to_compute_size == SHA256_DIGEST_LENGTH, ERR_INVALID_COMMAND, ERROR);
    return ERR_NONE;
}

//=======================================================================================
/**
 * @see ckvs_crypto.h
 */
int ckvs_client_encrypt_pwd(ckvs_memrecord_t *mr, const char *key, const char *pwd)
{
    M_REQUIRE_NON_NULL_VARGS(mr, key, pwd);

    const size_t buf_size = 2 * (CKVS_MAXKEYLEN) + 2;
    char * buffer = calloc(buf_size, sizeof(char));
    M_REQUIRE(buffer != NULL, ERR_OUT_OF_MEMORY, ERROR);

    strncat(buffer, key, CKVS_MAXKEYLEN);
    strcat(buffer, SEPARATOR);
    strncat(buffer, pwd, CKVS_MAXKEYLEN);

    /* Compute the SHA256 of the stretched key */
    SHA256((unsigned char *) buffer, strlen(buffer), mr->stretched_key.sha);
    free(buffer);

    const int err_auth = compute_hmac(mr->auth_key.sha, mr, AUTH_MESSAGE);
    M_REQUIRE(err_auth == ERR_NONE, err_auth, ERROR);

    const int err_c1 = compute_hmac(mr->c1.sha, mr, C1_MESSAGE);
    M_REQUIRE(err_c1 == ERR_NONE, err_c1, ERROR);

    return ERR_NONE;
}

//=======================================================================================
/**
 * @see ckvs_crypto.h
 */
int ckvs_client_compute_masterkey(struct ckvs_memrecord *mr, const struct ckvs_sha *c2)
{
    M_REQUIRE_NON_NULL_VARGS(mr, c2);

    unsigned int size = 0;
    HMAC(EVP_sha256(),
         mr->c1.sha,
         SHA256_DIGEST_LENGTH,
         c2->sha,
         SHA256_DIGEST_LENGTH,
         mr->master_key.sha,
         &size);

    M_REQUIRE(size == SHA256_DIGEST_LENGTH, ERR_INVALID_COMMAND, ERROR);
    return ERR_NONE;
}

//=======================================================================================
/**
 * @see ckvs_crypto.h
 */
int ckvs_client_crypt_value(const struct ckvs_memrecord *mr, const int do_encrypt,
                            const unsigned char *inbuf, size_t inbuflen,
                            unsigned char *outbuf, size_t *outbuflen)
{
    /* ======================================
     * Implementation adapted from the web:
     *     https://man.openbsd.org/EVP_EncryptInit.3
     * Man page: EVP_EncryptInit
     * Reference:
     *    https://www.coder.work/article/6383682
     * ======================================
     */
    M_REQUIRE_NON_NULL_VARGS(mr, inbuf, outbuf, outbuflen);

    // constant IV -- ok given the entropy in c2
    unsigned char iv[16];
    bzero(iv, 16);

    // Don't set key or IV right away; we want to check lengths
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_CipherInit_ex(ctx, EVP_aes_256_cbc(), NULL, NULL, NULL, do_encrypt);

    assert(EVP_CIPHER_CTX_key_length(ctx) == 32);
    assert(EVP_CIPHER_CTX_iv_length(ctx)  == 16);

    // Now we can set key and IV
    const unsigned char* const key = (const unsigned char*) mr->master_key.sha;
    EVP_CipherInit_ex(ctx, NULL, NULL, key, iv, do_encrypt);

    int outlen = 0;
    if (!EVP_CipherUpdate(ctx, outbuf, &outlen, inbuf, (int) inbuflen))
    {
        // Error
        printf("loo");
        EVP_CIPHER_CTX_free(ctx);
        return ERR_INVALID_ARGUMENT;
    }

    int tmplen = 0;
    if (!EVP_CipherFinal_ex(ctx, outbuf+outlen, &tmplen))
    {
        // Error
        debug_printf("crypt inbuflen %ld outlen %d tmplen %d", inbuflen, outlen, tmplen);
        EVP_CIPHER_CTX_free(ctx);
        return ERR_INVALID_ARGUMENT;
    }

    outlen += tmplen;
    EVP_CIPHER_CTX_free(ctx);

    *outbuflen = (size_t) outlen;

    return ERR_NONE;
}

