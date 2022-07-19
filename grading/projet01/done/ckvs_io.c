#include "error.h"
#include "ckvs_io.h"
#include <stdio.h>
#include <stdlib.h>
#include "ckvs_utils.h"

//=============================== PROTOTYPES ============================================
void init_header(ckvs_header_t *header);
int read_header(ckvs_header_t *header, FILE *file);
int read_entries(ckvs_entry_t *entry, size_t len, FILE *file);
static uint32_t ckvs_hashkey(struct CKVS *ckvs, const char *key);
static int ckvs_write_entry_to_disk(struct CKVS *ckvs, uint32_t idx);

//=======================================================================================
/**
 * @date  20/03/2022
 * @brief Initialize a header by setting zeros (explicitly) to  all fields.
 *
 * @param header (ckvs_header_t *) the header to be initialized.
 */
void init_header(ckvs_header_t *header)
{
    M_REQUIRE_NON_NULL_VOID_FUNCTION(header);

    header->num_entries = 0;
    header->table_size = 0;
    header->threshold_entries = 0;
    header->version = 0;
    memset(header->header_string, '\0', CKVS_HEADERSTRINGLEN);
}

//=======================================================================================
/**
 * @see ckvs_io.c
 */
void init_entry(ckvs_entry_t *entry)
{
    M_REQUIRE_NON_NULL_VOID_FUNCTION(entry);

    entry->value_len = 0;
    entry->value_off = 0;
    memset(entry->key, '\0', CKVS_MAXKEYLEN);
    memset(entry->auth_key.sha, 0, SHA256_DIGEST_LENGTH);
    memset(entry->c2.sha, 0, SHA256_DIGEST_LENGTH);
}

//=======================================================================================
/**
 * @date  20/03/2022
 * @brief Read a header from the file.
 *
 * This function also checks the validity of the header.
 * @see check_header in ckvs_util.c
 *
 * @param  header (ckvs_header_t *) the resulting header
 * @param  file   (FILE *)          the file to read the header
 *
 * @return (int) error code (@see error.h/c)
 */
int read_header(ckvs_header_t *header, FILE *file)
{
    M_REQUIRE_NON_NULL_VARGS(header, file);

    const size_t err = fread(header, sizeof(ckvs_header_t), 1, file);
    M_REQUIRE(err >= 1, ERR_IO, "");

    M_REQUIRE(check_header(header) == ERR_NONE, ERR_CORRUPT_STORE, "");
    return ERR_NONE;
}

//=======================================================================================
/**
 * @date  20/03/2022
 * @brief Read @param len entries in the file file.
 *
 * @param entry (ckvs_entry_t *) the array where the entries are stored.
 * @param len   (size_t)         the number of entries to read.
 * @param file  (FILE *)         where we read the entries.
 *
 * @return (int) error code (@see error.h/c)
 */
int read_entries(ckvs_entry_t *entry, const size_t len, FILE *file)
{
    M_REQUIRE_NON_NULL_VARGS(entry, file);

    /* No error, if nothing to read :-) */
    if (len == 0)
    {
        return ERR_NONE;
    }

    const size_t err = fread(entry, sizeof(ckvs_entry_t), len, file);
    M_REQUIRE(err >= len, ERR_IO, "");

    return ERR_NONE;
}

//=======================================================================================
/**
 * @see ckvs_io.h
 */
int ckvs_open(const char *filename, struct CKVS *ckvs)
{
    M_REQUIRE_NON_NULL_VARGS(filename, ckvs);

    ckvs_header_t header;
    init_header(&header);
    ckvs->header = header;

    FILE *file = fopen(filename, "rb+");
    M_REQUIRE(file != NULL, ERR_IO, "");

    ckvs->file = file;
    const int err_header = read_header(&ckvs->header, file);
    if (err_header != ERR_NONE)
    {
        M_FREE_MEMORY(ckvs, NULL);
        return err_header;
    }

    if (ckvs->header.table_size != CKVS_FIXEDSIZE_TABLE)
    {
        M_FREE_MEMORY(ckvs, NULL);
        return ERR_CORRUPT_STORE;
    }

    for (size_t i = 0; i < CKVS_FIXEDSIZE_TABLE; ++i)
    {
        init_entry(ckvs->entries + i);

        const int err_entries = read_entries(ckvs->entries + i, 1, file);
        if (err_entries != ERR_NONE)
        {
            ckvs_close(ckvs);
            return err_entries;
        }
    }

    return ERR_NONE;
}

//=======================================================================================
/**
 * @see ckvs_io.h
 */
void ckvs_close(struct CKVS *ckvs)
{
    M_REQUIRE_NON_NULL_VOID_FUNCTION(ckvs);

    if (ckvs->file != NULL)
    {
        fclose(ckvs->file);
        ckvs->file = NULL;
    }
}

//=======================================================================================
/**
 * @date  2/04/2002
 * @brief Compute the hash of the key to get the index of the entry in the database (Hash-Table)
 *
 * @param ckvs (struct CKVS *) the database where the entries are stored.
 * @param key  (const char *)  the key to be hashed.
 *
 * @returns (uint32_t) the index of the entry based on the key.
 */
static uint32_t ckvs_hashkey(struct CKVS *ckvs, const char *key)
{
    M_REQUIRE_NON_NULL_VARGS(ckvs, key);

    unsigned char * hashed = calloc(SHA256_DIGEST_LENGTH, sizeof(unsigned char));
    M_REQUIRE(hashed != NULL, ERR_OUT_OF_MEMORY, "");

    /* Compute the SHA256 of the key */
    SHA256((const unsigned char *) key, strlen(key), hashed);

    uint32_t _4_MSB;
    memcpy(&_4_MSB, hashed, sizeof(uint32_t));
    free(hashed);

    return _4_MSB & (ckvs->header.table_size - 1);
}


//=======================================================================================
/**
 * @see ckvs_io.h
 */
int ckvs_find_entry(struct CKVS *ckvs, const char *key, const struct ckvs_sha *auth_key, struct ckvs_entry **e_out)
{
    M_REQUIRE_NON_NULL_VARGS(ckvs, key, auth_key, e_out);

    /* Get the index for the beginning of the search */
    const uint32_t index = ckvs_hashkey(ckvs, key);
    for (size_t i = index, tries = 0; tries < CKVS_FIXEDSIZE_TABLE; ++tries)
    {
        /* Because in the database a key can exceed the max length */
        char new_key[CKVS_MAXKEYLEN + 1];
        strncpy(new_key, (ckvs->entries + i)->key, CKVS_MAXKEYLEN);
        new_key[CKVS_MAXKEYLEN] = '\0';

        if (strcmp(key, new_key) == 0)
        {
            /* HIT case */
            if (ckvs_cmp_sha(auth_key, &(ckvs->entries + i)->auth_key) != 0)
            {
                return ERR_DUPLICATE_ID;
            }
            else
            {
                *e_out = ckvs->entries + i;
                return ERR_NONE;
            }
        }

        /* MISS */
        if (strlen(new_key) == 0)
        {
            /* We'll use this free entry for the new one */
            *e_out = ckvs->entries + i;
            return ERR_KEY_NOT_FOUND;
        }

        /* Collision */
        if (strncmp(key, new_key, CKVS_MAXKEYLEN) != 0)
        {
            /* Circular & linear probing, we check the next memory slot.
             * Note the use of comma operator ;-) */
            ++i, i &= ckvs->header.table_size - 1;
        }
    }

    return ERR_NONE;
}

//=======================================================================================
/**
 * @date  25/03/2022
 * @brief Read the the content of a file.
 *
 * @param filename     (const char*) the file to be read.
 * @param buffer_ptr   (char**)      a pointer to the buffer
 *                                   that will contain the contents of the file.
 * @param buffer_size  (size_t*)     a pointer to the size (bytes) of the read file.
 *
 * @return (int) error code (@see error.h/c)
 */
int read_value_file_content(const char *filename, char **buffer_ptr, size_t *buffer_size)
{
    M_REQUIRE_NON_NULL_VARGS(filename, buffer_ptr, buffer_size);

    FILE *file = fopen(filename, "r");
    M_REQUIRE(file != NULL, ERR_IO, "");

    /* Go to the end of the file to get the size */
    if (fseek(file, 0L, SEEK_END) != 0)
    {
        fclose(file);
        return ERR_IO;
    }

    const size_t size = (size_t) ftell(file);
    rewind(file); // Go back to the beginning of the file

    char *content = calloc(size + 1, sizeof(char));
    if (content == NULL)
    {
        fclose(file);
        return ERR_OUT_OF_MEMORY;
    }

    /* Read the whole file */
    if (fread(content, size, 1, file) != 1)
    {
        free(content);
        fclose(file);
        return ERR_IO;
    }

    fclose(file);

    content[size] = '\0';
    *buffer_ptr = content;
    *buffer_size = size + 1; // counting the '\0'
    return ERR_NONE;
}

//=======================================================================================
/**
 * @date  25/03/2022
 * @brief Update one entry in a .ckvs file.
 *
 * @param ckvs  (CKVS_t *) the ckvs that represent the database.
 * @param idx   (uint32_t) the index of the entry to be updated.
 *
 * @return (int) error code (@see error.h/c)
 */
static int ckvs_write_entry_to_disk(struct CKVS *ckvs, const uint32_t idx)
{
    M_REQUIRE_NON_NULL(ckvs);
    M_REQUIRE(idx <= CKVS_FIXEDSIZE_TABLE, ERR_INVALID_ARGUMENT, "");

    const long int offset = (long int) (sizeof(ckvs_header_t) + idx * sizeof(ckvs_entry_t));

    if (fseek(ckvs->file, offset, SEEK_SET) != 0)
    {
        M_FREE_MEMORY(ckvs, NULL);
        return ERR_IO;
    }

    if (fwrite(ckvs->entries + idx, sizeof(ckvs_entry_t), 1, ckvs->file) < 1)
    {
        M_FREE_MEMORY(ckvs, NULL);
        return ERR_IO;
    }

    return ERR_NONE;
}

//=======================================================================================
/**
 * @see ckvs_io.h
 */
int ckvs_write_encrypted_value(struct CKVS *ckvs, struct ckvs_entry *e, const unsigned char *buf, uint64_t buflen)
{
    M_REQUIRE_NON_NULL_VARGS(ckvs, buf, e);

    if (fseek(ckvs->file, 0L, SEEK_END) != 0)
    {
        M_FREE_MEMORY(ckvs, NULL);
        return ERR_IO;
    }

    /* Update the entry */
    e->value_len = buflen;
    e->value_off = (uint64_t) ftell(ckvs->file);

    if (fwrite(buf, buflen, 1, ckvs->file) != 1)
    {
        M_FREE_MEMORY(ckvs, NULL);
        return ERR_IO;
    }

    const int err_code = ckvs_write_entry_to_disk(ckvs, (const uint32_t) (e - ckvs->entries));
    M_REQUIRE(err_code == ERR_NONE, err_code, "");

    return ERR_NONE;
}

//=======================================================================================
/**
 * @note Week 07
 *
 * @see ckvs_io.h
 */
int ckvs_new_entry(struct CKVS *ckvs, const char *key, struct ckvs_sha *auth_key, struct ckvs_entry **e_out)
{
    M_REQUIRE_NON_NULL_VARGS(ckvs, key, auth_key, e_out);
    M_REQUIRE(strlen(key) <= CKVS_MAXKEYLEN, ERR_INVALID_ARGUMENT, "");

    const int err_find_entry = ckvs_find_entry(ckvs, key, auth_key, e_out);

    if (err_find_entry == ERR_KEY_NOT_FOUND)
    {
        if (strlen((*e_out)->key) == 0)
        {
            (*e_out)->value_len = 0;
            (*e_out)->value_off = 0;
            strncpy((*e_out)->key, key, CKVS_MAXKEYLEN);
            memcpy((*e_out)->auth_key.sha, auth_key, SHA256_DIGEST_LENGTH);
        }
    }
    else
    {
        return ERR_DUPLICATE_ID;
    }

    M_REQUIRE(++ckvs->header.num_entries <= ckvs->header.threshold_entries, ERR_MAX_FILES, "");

    rewind(ckvs->file);
    if (fwrite(&(ckvs->header), sizeof(ckvs_header_t), 1, ckvs->file) < 1)
    {
        M_FREE_MEMORY(ckvs, NULL);
        return ERR_IO;
    }
    rewind(ckvs->file);

    return ckvs_write_entry_to_disk(ckvs, (const uint32_t) (*e_out - ckvs->entries));
}
