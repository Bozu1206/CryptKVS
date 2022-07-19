#include "ckvs.h"
#include "error.h"
#include "util.h"
#include "ckvs_io.h"
#include "ckvs_utils.h"
#include "ckvs_crypto.h"
#include <stdlib.h>
#include <string.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

//=======================================================================================
/**
 * @brief Value for ckvs_client_crypt_value to determine if we have to en/decrypt.
 */
#define ENCRYPT       1
#define DECRYPT       0

//========================================================================================
static int ckvs_perform_decryption(ckvs_entry_t **out, CKVS_t *ckvs, ckvs_memrecord_t *mr);
static int ckvs_perform_set(const char *set_value, CKVS_t *ckvs, ckvs_memrecord_t *mr, ckvs_entry_t *out);
int ckvs_local_getset(const char *filename, const char *key, const char *pwd, const char *set_value);
int init_stuff(ckvs_memrecord_t *mr, CKVS_t *ckvs, ckvs_entry_t **out, const char *filename,
               const char *key, const char *pwd);

//=======================================================================================
/**
 * @date  07/04/2022
 * @brief Useful function to avoid duplication of code in ckvs_local_getset and ckvs_local_new.
 *        Initializes the mr parameter by computing the stretched key, the auth_key and c1.
 *        Initializes the ckvs parameter by opening the file.
 *        Initializes the out parameter.
 *
 * @param mr       (ckvs_memrecord_t *) the memrecord to initialize
 * @param ckvs     (CKVS_t *)           the ckvs (database) to initialize
 * @param out      (ckvs_entry_t **)    the entry pointer to initialize
 * @param filename (const char *)       the filename of the ckvs database (init ckvs)
 * @param key      (const char *)       the key used to compute fields of mr (init mr)
 * @param pwd      (const char *)       the password used to compute fields of mr (init mr)
 *
 * @return (int) error code (@see error.c/h)
 */
int init_stuff(ckvs_memrecord_t *mr, CKVS_t *ckvs, ckvs_entry_t **out,
               const char *filename, const char *key, const char *pwd)
{
    M_REQUIRE_NON_NULL_VARGS(mr, ckvs, out, filename, key, pwd);

    /* ---- Init crypto structure ---- */
    memset(mr, 0, sizeof(ckvs_memrecord_t));
    const int err_encrypt = ckvs_client_encrypt_pwd(mr, key, pwd);
    M_REQUIRE(err_encrypt == ERR_NONE, err_encrypt, "");

    /* ---- Init and open the database ---- */
    memset(ckvs, 0, sizeof(CKVS_t));
    const int err_open = ckvs_open(filename, ckvs);
    M_REQUIRE(err_open == ERR_NONE, err_open, "");

    return ERR_NONE;
}

//=======================================================================================
/**
 * @see ckvs_local.h
 */
int ckvs_local_stats(const char *filename, int optargc, _unused char** optargv)
{
    ARG_CHECK(0, optargc);
    M_REQUIRE_NON_NULL(filename);

    CKVS_t ckvs;
    memset(&ckvs, 0, sizeof(ckvs));

    const int err = ckvs_open(filename, &ckvs);
    M_REQUIRE(err == ERR_NONE, err, "");

    print_header(&ckvs.header);

    for (size_t i = 0; i < ckvs.header.table_size; ++i)
    {
        if ((ckvs.entries + i)->key[0] != '\0')
        {
            print_entry(ckvs.entries + i);
        }
    }

    ckvs_close(&ckvs);
    return ERR_NONE;
}

//=======================================================================================
/**
 * @date  20/03/2022
 * @brief Helper function which perform the decryption from the entry out and print
 *        the result into the standard output.
 *
 * @param out  (ckvs_entry_out **) the entry for which we have to perform the decryption.
 * @param ckvs (CKVS_t)            the database.
 * @param mr   (ckvs_memrecord_t*) the cryptographic tools to do the decryption.
 *
 * @return (int) error code (@see error.h/c)
 */
static int ckvs_perform_decryption(ckvs_entry_t **out, CKVS_t *ckvs, ckvs_memrecord_t *mr)
{
    M_REQUIRE_NON_NULL_VARGS(out, ckvs, mr);

    const long int offset = (long int) (*out)->value_off;
    const unsigned long int size = (long unsigned int) (*out)->value_len;

    if (fseek(ckvs->file, offset, SEEK_SET) != 0)
    {
        ckvs_close(ckvs);
        return ERR_IO;
    }

    unsigned char *encrypted_value = calloc(size, sizeof(unsigned char));
    if (encrypted_value == NULL)
    {
        ckvs_close(ckvs);
        return ERR_OUT_OF_MEMORY;
    }

    if (fread(encrypted_value, sizeof(char), size, ckvs->file) < size)
    {
        ckvs_close(ckvs);
        free(encrypted_value);
        return ERR_IO;
    }

    size_t decrypt_size = 0;
    unsigned char *value = calloc(size + EVP_MAX_BLOCK_LENGTH, sizeof(unsigned char));
    if (value == NULL)
    {
        ckvs_close(ckvs);
        free(encrypted_value);
        return ERR_OUT_OF_MEMORY;
    }
    const int decrypt = ckvs_client_crypt_value(mr,DECRYPT,
                        encrypted_value,size,
                        value,&decrypt_size);

    if (decrypt != ERR_NONE)
    {
        ckvs_close(ckvs);
        free(value);
        free(encrypted_value);
        return decrypt;
    }

    pps_printf("%s", value);
    ckvs_close(ckvs);
    free(value);
    free(encrypted_value);
    return ERR_NONE;
}

//=======================================================================================
/**
 * @date  02/05/2022
 * @brief Helper function that regenerate C2 and the masterkey to encrypt and write a secret
 *        on the disk. Basically, this function perfoms a 'set' on the ckvs database.
 *
 * @param set_value  (const char *)         the value to write on the disk.
 * @param ckvs       (CKVS_t *)             the database where to store the value.
 * @param mr         (ckvs_memrecord_t *)   the data structure holding crypto parameters
 * @param out        (ckvs_entry_t *)       the updated entry that will be written on disk
 *
 * @return (int) error code (@see error.h/c)
 */
static int ckvs_perform_set(const char *set_value, CKVS_t *ckvs, ckvs_memrecord_t *mr, ckvs_entry_t *out)
{
    /* C2 Regeneration */
    if (RAND_bytes(out->c2.sha, SHA256_DIGEST_LENGTH) != 1)
    {
        ckvs_close(ckvs);
        return ERR_IO;
    }

    /* Recompute the master-key because of new C2 */
    const int err_masterkey = ckvs_client_compute_masterkey(mr, &out->c2);
    if (err_masterkey != ERR_NONE)
    {
        ckvs_close(ckvs);
        return err_masterkey;
    }

    size_t size = 0;
    unsigned char *crypted_value = calloc(1 + strlen(set_value) + EVP_MAX_BLOCK_LENGTH,
                                          sizeof(unsigned char));
    if (crypted_value == NULL)
    {
        ckvs_close(ckvs);
        return ERR_OUT_OF_MEMORY;
    }

    /* ENCRYPTION */
    const int encrypt = ckvs_client_crypt_value(mr, ENCRYPT,
                        (const unsigned char *)set_value,
                        strlen(set_value) + 1,
                        crypted_value,
                        &size);
    if (encrypt != ERR_NONE)
    {
        ckvs_close(ckvs);
        free(crypted_value);
        return encrypt;
    }

    /* Update the database */
    const int write_to_disk = ckvs_write_encrypted_value(ckvs, out,
                              (const unsigned char *) crypted_value,
                              size);

    if (write_to_disk != ERR_NONE)
    {
        ckvs_close(ckvs);
        free(out);
        return write_to_disk;
    }

    ckvs_close(ckvs);
    free(crypted_value);
    return ERR_NONE;
}

//=======================================================================================
/**
 * @date  26/03/2002
 * @brief Helper function for function get and set based on the value of @param set_value:
 *                  - if @param set_value == NULL : we perform a get on the database.
 *                  - if @param set_value != NULL : we perform a set on the database.
 *
 * @param filename    (const char *) the name of the database (.ckvs)
 * @param key         (const char *) the key of the entry.
 * @param pwd         (const char *) the password of the entry.
 * @param set_value   (const char *) the value to encrypt and to write in the database (if not NULL).
 *
 * @return (int) error code (@see error.h/c)
 */
int ckvs_local_getset(const char *filename, const char *key, const char *pwd, const char *set_value)
{
    M_REQUIRE_NON_NULL_VARGS(filename, key, pwd);

    CKVS_t ckvs;
    ckvs_memrecord_t mr;
    ckvs_entry_t *out = NULL;

    /* ---------- Init ckvs, mr, entry and compute the masterkey ---------- */
    const int err_init = init_stuff(&mr, &ckvs, &out, filename, key, pwd);
    if (err_init != ERR_NONE)
    {
        ckvs_close(&ckvs);
        return err_init;
    }

    const int err_find_entry = ckvs_find_entry(&ckvs, key, &mr.auth_key, &out);
    if (err_find_entry != ERR_NONE)
    {
        ckvs_close(&ckvs);
        return err_find_entry;
    }

    const int err_mk = ckvs_client_compute_masterkey(&mr, &out->c2);
    if (err_mk != ERR_NONE)
    {
        ckvs_close(&ckvs);
        return err_mk;
    }

    /* ------------------------------ GET ------------------------------------ */
    if (set_value == NULL)
    {
        /* Because of 'new' command, there could be empty secret in DB */
        if (out->value_len == 0)
        {
            ckvs_close(&ckvs);
            return ERR_NO_VALUE;
        }

        return ckvs_perform_decryption(&out, &ckvs, &mr);
    }

    /* ------------------------------- SET ------------------------------------ */
    else
    {
        return ckvs_perform_set(set_value, &ckvs, &mr, out);
    }
}

//=======================================================================================
/**
 * @see ckvs_local.h
 */
int ckvs_local_get(const char *filename, int optargc, char** optargv)
{
    ARG_CHECK(2, optargc);

    const char* key = optargv[0];
    const char* password = optargv[1];

    M_REQUIRE_NON_NULL_VARGS(filename, key, password);
    CKVS_CHECK_KEY(key);

    return ckvs_local_getset(filename, key, password, NULL);
}

//=======================================================================================
/**
 * @see ckvs_local.h
 */
int ckvs_local_set(const char *filename, int optargc, char** optargv)
{
    ARG_CHECK(3, optargc);

    const char* key = optargv[0];
    const char* password = optargv[1];
    const char* valuefilename = optargv[2];

    M_REQUIRE_NON_NULL_VARGS(filename, key, password, valuefilename);
    CKVS_CHECK_KEY(key);

    size_t size = 0;
    char *buffer = NULL;
    const int err_read = read_value_file_content(valuefilename, &buffer, &size);
    if (err_read != ERR_NONE)
    {
        return err_read;
    }

    const int err_set = ckvs_local_getset(filename, key, password, buffer);
    if (err_set != ERR_NONE)
    {
        free(buffer);
        return err_set;
    }

    free(buffer);
    return ERR_NONE;
}

//=======================================================================================
/**
 * @note Week 07
 *
 * @see ckvs_local.h
 */
int ckvs_local_new(const char *filename, int optargc, char** optargv)
{
    ARG_CHECK(2, optargc);

    const char* key = optargv[0];
    const char* password = optargv[1];

    M_REQUIRE_NON_NULL_VARGS(filename, key, password);
    CKVS_CHECK_KEY(key);

    CKVS_t ckvs;
    ckvs_memrecord_t mr;
    ckvs_entry_t *out = NULL;

   const int err_init = init_stuff(&mr, &ckvs, &out, filename, key, password);
    if (err_init != ERR_NONE)
    {
        ckvs_close(&ckvs);
        return err_init;
    }

    const int err_new = ckvs_new_entry(&ckvs, key, &mr.auth_key, &out);
    if (err_new != ERR_NONE)
    {
        ckvs_close(&ckvs);
        return err_new;
    }

    ckvs_close(&ckvs);
    return ERR_NONE;
}
