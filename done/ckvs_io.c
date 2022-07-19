#include "error.h"
#include "ckvs_io.h"
#include <stdio.h>
#include <stdlib.h>
#include "ckvs_utils.h"
#include <unistd.h>

//=======================================================================================
int read_header(ckvs_header_t *header, FILE *file);
int read_entries(ckvs_entry_t *entry, size_t len, FILE *file);
static uint32_t ckvs_hashkey(struct CKVS *ckvs, const char *key);

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
 * @brief Read @param len entries in the file @param file.
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
    memset(&ckvs->header, 0, sizeof(ckvs_header_t));

    FILE *file = fopen(filename, "rb+");
    M_REQUIRE(file != NULL, ERR_IO, "");

    ckvs->file = file;
    const int err_header = read_header(&ckvs->header, file);
    if (err_header != ERR_NONE)
    {
        return err_header;
    }

    ckvs->entries = calloc(ckvs->header.table_size, sizeof(ckvs_entry_t));
    if (ckvs->entries == NULL)
    {
        fclose(ckvs->file);
        return ERR_OUT_OF_MEMORY;
    }

    const int err_entries = read_entries(ckvs->entries, ckvs->header.table_size, file);
    if (err_entries != ERR_NONE)
    {
        free(ckvs->entries);
        return err_entries;
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

    free(ckvs->entries);
    ckvs->entries = NULL;

    if (ckvs->file != NULL)
    {
        fclose(ckvs->file);
        ckvs->file = NULL;
    }
}

//=======================================================================================
/**
 * @date  2/04/2022
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

    unsigned char hashed[SHA256_DIGEST_LENGTH];
    M_REQUIRE(hashed != NULL, ERR_OUT_OF_MEMORY, "");

    /* Compute the SHA256 of the key */
    SHA256((const unsigned char *) key, strnlen(key, CKVS_MAXKEYLEN), hashed);

    uint32_t _4_MSB;
    memcpy(&_4_MSB, hashed, sizeof(uint32_t));
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
    for (size_t i = index, tries = 0; tries < ckvs->header.table_size; ++tries)
    {
        /* MISS */
        if ((ckvs->entries + i)->key[0] == '\0')
        {
            /* We'll use this free entry for the new one */
            *e_out = ckvs->entries + i;
            return ERR_KEY_NOT_FOUND;
        }

        if (strncmp(key, (ckvs->entries + i)->key, CKVS_MAXKEYLEN) == 0)
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
        else
        {
            /* Circular & linear probing, we check the next memory slot. */
            ++i;
            i &= ckvs->header.table_size - 1;
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
    *buffer_ptr  = content;
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
int ckvs_write_entry_to_disk(struct CKVS *ckvs, const uint32_t idx)
{
    M_REQUIRE_NON_NULL(ckvs);
    M_REQUIRE(idx <= ckvs->header.table_size, ERR_INVALID_ARGUMENT, "");

    const long int offset = (long int) (sizeof(ckvs_header_t) + idx * sizeof(ckvs_entry_t));

    if (fseek(ckvs->file, offset, SEEK_SET) != 0)
    {
        return ERR_IO;
    }

    if (fwrite(ckvs->entries + idx, sizeof(ckvs_entry_t), 1, ckvs->file) < 1)
    {
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
        return ERR_IO;
    }

    /* Update the entry */
    e->value_len = buflen;
    e->value_off = (uint64_t) ftell(ckvs->file);

    if (fwrite(buf, buflen, 1, ckvs->file) != 1)
    {
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

    M_REQUIRE(++ckvs->header.num_entries <= ckvs->header.threshold_entries, ERR_MAX_FILES, "");

    const int err_find_entry = ckvs_find_entry(ckvs, key, auth_key, e_out);

    /* ------------------------------------- Setup new entry ------------------------------------- */
    /* Key not found means that the entry does not exist yet on the DB, so setup this new entry.   */
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

    /* --------------------------------- Update header on disk ----------------------------------- */
    rewind(ckvs->file);
    if (fwrite(&(ckvs->header), sizeof(ckvs_header_t), 1, ckvs->file) < 1)
    {
        return ERR_IO;
    }

    return ckvs_write_entry_to_disk(ckvs, (const uint32_t) (*e_out - ckvs->entries));
}

//================================================== EXTENSION =========================================================

//=======================================================================================
/**
 * @brief Helper function for create function. Get an input from standard input
 *
 * @param name (const char *) A string to display (help the user)
 * @warning this function use scanf.
 *
 * @return (uint32_t) the input value of the user
 */
uint32_t request_value_to_user(const char * name)
{
    pps_printf("\t%s", name);
    uint32_t ret = 0;
    if (scanf("%u", &ret) != 1)
    {
        return (uint32_t) ERR_IO;
    }
    return ret;
}
//=======================================================================================
/**
 * @brief Some color to improve user experience.
 */
#define RED       "\x1B[31m"
#define GREEN     "\x1B[32m"
#define RESET     "\x1B[0m"
#define is_power_of_two(X) (((X)!=0) && (((X) & ((X)-1)) == 0))

//=======================================================================================
/**
 * @see ckvs_io.h
 */
int ckvs_new_database(const char *name)
{
    M_REQUIRE_NON_NULL(name);

    if (access(name, F_OK) == 0)
    {
        pps_printf(RED "La base de données %s existe déjà ! \n" RESET, name);
        return ERR_NONE;
    }

    ckvs_header_t header = {.header_string = "CS212 CryptKVS v1",
                            .version = 1,
                            .table_size = 0,
                            .threshold_entries = 0,
                            .num_entries = 0
                           };

    pps_printf("Merci de renseigner plusieurs informations concernant votre base de données\n");
    uint32_t table_size;
    uint32_t threshold;
    do
    {
        table_size = request_value_to_user("Combien voulez-vous d'entrées (rentrez une puissance de 2) : ");
        threshold  = request_value_to_user("Quel seuil pour le nombre d'entrée (< nombre d'entrées) : ");
    }
    while (!is_power_of_two(table_size) || threshold > table_size);

    header.table_size = table_size;
    header.threshold_entries = threshold;

    FILE * file = fopen(name, "wb");
    M_REQUIRE(file != NULL, ERR_IO, "");

    if (fwrite(&header, sizeof(ckvs_header_t), 1, file) < 1)
    {
        fclose(file);
        return ERR_IO;
    }

    ckvs_entry_t *entries = calloc(header.table_size, sizeof(ckvs_entry_t));
    M_REQUIRE(entries != NULL, ERR_OUT_OF_MEMORY, "");

    if (fwrite(entries, sizeof(ckvs_entry_t), header.table_size, file) < header.table_size)
    {
        fclose(file);
        free(entries);
        return ERR_IO;
    }

    pps_printf(GREEN "\n La base de données %s a été créée ! \n" RESET, name);
    free(entries);
    fclose(file);
    return ERR_NONE;
}

