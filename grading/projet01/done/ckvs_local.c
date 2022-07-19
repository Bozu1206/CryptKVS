#include "ckvs.h"
#include "error.h"
#include "ckvs_io.h"
#include "ckvs_utils.h"
#include "ckvs_crypto.h"
#include <stdlib.h>
#include <string.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

//=======================================================================================
#define ENCRYPT       1
#define DECRYPT       0

//=============================== PROTOTYPES ============================================
static int ckvs_check_key(size_t length);
static int ckvs_perform_decryption(ckvs_entry_t **out, CKVS_t *ckvs, ckvs_memrecord_t *mr);
int ckvs_local_getset(const char *filename, const char *key, const char *pwd, const char *set_value);
int init_stuff(ckvs_memrecord_t *mr, CKVS_t *ckvs, ckvs_entry_t **out,
               const char *filename, const char *key, const char *pwd);

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

    memset(mr, 0, sizeof(ckvs_memrecord_t));
    const int err_encrypt = ckvs_client_encrypt_pwd(mr, key, pwd);
    M_REQUIRE(err_encrypt == ERR_NONE, err_encrypt, "");

    memset(ckvs, 0, sizeof(CKVS_t));
    const int err_open = ckvs_open(filename, ckvs);
    M_REQUIRE(err_open == ERR_NONE, err_open, "");

    init_entry(*out);
    return ERR_NONE;
}

//=======================================================================================
/**
 * @brief Check the length of the key, indeed the can't be only "\0" because it represents
 *        a free entry in the database, although this key could be considered valid.
 *
 * @param length  (size_t)  the lenght of the key
 *
 * @return error code (@see error.h/c)
 */
static int ckvs_check_key(const size_t length)
{
    if (length == 0 || length > CKVS_MAXKEYLEN)
    {
        return ERR_INVALID_ARGUMENT;
    }

    return ERR_NONE;
}

//=======================================================================================
/**
 * @see ckvs_local.h
 */
int ckvs_local_stats(const char *filename)
{
    M_REQUIRE_NON_NULL(filename);

    CKVS_t ckvs;
    memset(&ckvs, 0, sizeof(ckvs));

    const int err = ckvs_open(filename, &ckvs);
    M_REQUIRE(err == ERR_NONE, err, "");

    print_header(&ckvs.header);

    for (size_t i = 0; i < CKVS_FIXEDSIZE_TABLE; ++i)
    {
        if (strlen(ckvs.entries[i].key))
        {
            print_entry(&(ckvs.entries[i]));
        }
    }

    M_FREE_MEMORY(&ckvs, NULL);
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
 * @returns (int) error code (@see error.h/c)
 */
static int ckvs_perform_decryption(ckvs_entry_t **out, CKVS_t *ckvs, ckvs_memrecord_t *mr)
{
    M_REQUIRE_NON_NULL_VARGS(out, ckvs, mr);

    const long int offset = (long int) (*out)->value_off;
    const unsigned long int size = (long unsigned int) (*out)->value_len;

    if (fseek(ckvs->file, offset, SEEK_SET) != 0)
    {
        M_FREE_MEMORY(ckvs, out);
        return ERR_IO;
    }

    unsigned char encrypted_value[size];
    if (fread(encrypted_value, sizeof(char), size, ckvs->file) < size)
    {
        M_FREE_MEMORY(ckvs, out);
        return ERR_IO;
    }

    size_t decrypt_size = 0;
    unsigned char value[size + EVP_MAX_BLOCK_LENGTH];
    const int decrypt = ckvs_client_crypt_value(mr,DECRYPT,
                                          encrypted_value,size,
                                       value,&decrypt_size);

    if (decrypt != ERR_NONE)
    {
        M_FREE_MEMORY(ckvs, out);
        return decrypt;
    }

    pps_printf("%s", value);
    M_FREE_MEMORY(ckvs, out);
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
    ckvs_entry_t **out = calloc(1, sizeof(ckvs_entry_t *));

    if (out == NULL)
    {
        M_FREE_MEMORY(&ckvs, NULL);
        return ERR_OUT_OF_MEMORY;
    }

    const int err_init = init_stuff(&mr, &ckvs, out, filename, key, pwd);
    if (err_init != ERR_NONE)
    {
        M_FREE_MEMORY(&ckvs, out);
        return err_init;
    }

    const int err_find_entry = ckvs_find_entry(&ckvs, key, &mr.auth_key, out);
    if (err_find_entry != ERR_NONE)
    {
        M_FREE_MEMORY(&ckvs, out);
        return err_find_entry;
    }

    const int err_mk = ckvs_client_compute_masterkey(&mr, &(*out)->c2);
    if (err_mk != ERR_NONE)
    {
        M_FREE_MEMORY(&ckvs, out);
        return err_mk;
    }

    // ------------------------------ GET ------------------------------------
    if (set_value == NULL)
    {
        /* Week 07 */
        if ((*out)->value_len == 0)
        {
            M_FREE_MEMORY(&ckvs, out);
            return ERR_NO_VALUE;
        }

        return ckvs_perform_decryption(out, &ckvs, &mr);
    }

    // ------------------------------- SET ------------------------------------
    else
    {
        /* C2 Regeneration */
        if (RAND_bytes((*out)->c2.sha, SHA256_DIGEST_LENGTH) != 1)
        {
            M_FREE_MEMORY(&ckvs, out);
            return ERR_IO;
        }

        /* Recompute the master-key because of new C2 */
        const int err_masterkey = ckvs_client_compute_masterkey(&mr, &(*out)->c2);
        if (err_masterkey != ERR_NONE)
        {
            M_FREE_MEMORY(&ckvs, out);
            return err_masterkey;
        }

        size_t size = 0;
        unsigned char *crypted_value = calloc(strlen(set_value) + 1 + EVP_MAX_BLOCK_LENGTH,
                                              sizeof(unsigned char));

        if (crypted_value == NULL)
        {
            M_FREE_MEMORY(&ckvs, out);
            return ERR_OUT_OF_MEMORY;
        }

        /* ENCRYPTION */
        const int encrypt = ckvs_client_crypt_value(&mr, ENCRYPT,
                                               (const unsigned char *)set_value,
                                             strlen(set_value) + 1,
                                            crypted_value,
                                            &size);
        if (encrypt != ERR_NONE)
        {
            M_FREE_MEMORY(&ckvs, out, crypted_value);
            return encrypt;
        }

        /* UPDATE THE DATABASE */
        const int write_to_disk = ckvs_write_encrypted_value(&ckvs, (*out),
                                                             (const unsigned char *) crypted_value,
                                                             size);

        if (write_to_disk != ERR_NONE)
        {
            M_FREE_MEMORY(&ckvs, out, crypted_value);
            return write_to_disk;
        }

        M_FREE_MEMORY(&ckvs, out, crypted_value);
        return ERR_NONE;
    }

}

//=======================================================================================
/**
 * @see ckvs_local.h
 */
int ckvs_local_get(const char *filename, const char *key, const char *pwd)
{
    M_REQUIRE_NON_NULL_VARGS(filename, key, pwd);

    const size_t key_len = strlen(key);
    M_REQUIRE(!ckvs_check_key(key_len), ERR_INVALID_ARGUMENT, "");
    return ckvs_local_getset(filename, key, pwd, NULL);
}

//=======================================================================================
/**
 * @see ckvs_local.h
 */
int ckvs_local_set(const char *filename, const char *key, const char *pwd, const char *valuefilename)
{
    M_REQUIRE_NON_NULL_VARGS(filename, key, pwd, valuefilename);

    const size_t key_len = strlen(key);
    M_REQUIRE(!ckvs_check_key(key_len), ERR_INVALID_ARGUMENT, "");

    char *buffer;
    size_t size = 0;
    const int err_read = read_value_file_content(valuefilename, &buffer, &size);
    if (err_read != ERR_NONE)
    {
        free(buffer);
        return err_read;
    }

    const int err_set = ckvs_local_getset(filename, key, pwd, buffer);
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
int ckvs_local_new(const char *filename, const char *key, const char *pwd)
{
    M_REQUIRE_NON_NULL_VARGS(filename, key, pwd);

    const size_t key_len = strlen(key);
    M_REQUIRE(!ckvs_check_key(key_len), ERR_INVALID_ARGUMENT, "");

    CKVS_t ckvs;
    ckvs_memrecord_t mr;
    ckvs_entry_t **out = calloc(1, sizeof(ckvs_entry_t *));
    M_REQUIRE(out != NULL, ERR_OUT_OF_MEMORY, "");

    const int err_init = init_stuff(&mr, &ckvs, out, filename, key, pwd);
    if (err_init != ERR_NONE)
    {
        M_FREE_MEMORY(&ckvs, out);
        return err_init;
    }

    const int err_new = ckvs_new_entry(&ckvs, key, &mr.auth_key, out);
    if (err_new != ERR_NONE)
    {
        M_FREE_MEMORY(&ckvs, out);
        return err_new;
    }

    M_FREE_MEMORY(&ckvs, out);
    return ERR_NONE;
}