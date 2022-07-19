#include "ckvs.h"
#include "util.h"
#include <stdlib.h>

//=======================================================================================
/**
 * @brief Simple error to return in case of an error in header check.
 */
#define ERROR_CHECK   -1

//=======================================================================================
/**
 * @brief Prints the key.
 * @Note  there exist surely a more simpler method, but I can't understand STR_LENGTH_FMT well)
 */
#define print_key(key)                               \
    pps_printf("    Key   : ");                      \
    pps_printf(STR_LENGTH_FMT(CKVS_MAXKEYLEN), key); \
    pps_printf("\n")                                 \

//=======================================================================================
/**
 * @brief Determine if a number is a power of two.
 * @Note  Code was taken from :
 *       https://stackoverflow.com/questions/600293/how-to-check-if-a-number-is-a-power-of-2
 *
 *       The idea is to mask the value x with x - 1.
 *       In the case where x is a power of two then x has just his first MSB sets to 1
 *       and then x - 1 will have all bits set to one except his MSB.
 *
 *       For a power of 2, the masking will always return 0.
 *       Ex :
 *          16 --- binary ---> 1000
 *          15 --- binary ---> 0111
 *
 *                    1000
 *                    0111
 *          16 & 15 = 0000
 *
 *        The condition x != 0 is here to ensure to 0 is not a power of two.
 *
 * @param  x the number that have to be tested.
 *
 * @return (int) 1 if the number x is a power of two, 0 otherwise
 */
#define is_power_of_two(X) (((X)!=0) && (((X) & ((X)-1)) == 0))

//=======================================================================================
static int convert(uint8_t *buf, size_t size, const char * input);
static char *append_at_beginning(char before, const char *str, size_t len);

//=======================================================================================

/**
 * @see ckvs_utils.h
 */
void print_header(const struct ckvs_header *header)
{
    M_REQUIRE_NON_NULL_VOID_FUNCTION(header);

    pps_printf(HEADER_TYPE_MSG,  header->header_string);
    pps_printf(HEADER_VERS_MSG, (unsigned long) header->version);
    pps_printf(HEADER_SIZE_MSG, (unsigned long) header->table_size);
    pps_printf(HEADER_THRE_MSG, (unsigned long) header->threshold_entries);
    pps_printf(HEADER_NENT_MSG, (unsigned long) header->num_entries);
}

//=======================================================================================
/**
 * @see ckvs_utils.c
 */
int check_header(const struct ckvs_header *header)
{
    M_REQUIRE_NON_NULL(header);

    M_REQUIRE(strncmp(CKVS_HEADERSTRING_PREFIX, header->header_string,
                      strlen(CKVS_HEADERSTRING_PREFIX)) == 0, ERROR_CHECK, "");
    M_REQUIRE(header->version == 1, ERROR_CHECK, "");
    M_REQUIRE(is_power_of_two(header->table_size), ERROR_CHECK, "");

    /* Week 09 : check that fields are not too big (because of dynamic allocation) */
    M_REQUIRE(header->table_size < CKVS_MAX_ENTRIES, ERROR_CHECK, "");
    M_REQUIRE(header->threshold_entries <= header->table_size, ERROR_CHECK, "");
    M_REQUIRE(header->num_entries <= header->threshold_entries, ERROR_CHECK, "");
    return ERR_NONE;
}

//=======================================================================================
/**
 * @see ckvs_utils.h
 */
void print_entry(const struct ckvs_entry *entry)
{
    M_REQUIRE_NON_NULL_VOID_FUNCTION(entry);

    /* Because the key isn't necessarily NULL-terminated */
    char key[CKVS_MAXKEYLEN + 1];
    strncpy(key, entry->key, CKVS_MAXKEYLEN);
    key[CKVS_MAXKEYLEN] = '\0';

    print_key(key);
    pps_printf("    Value : off %lu len %lu\n",
               (unsigned long) entry->value_off,
               (unsigned long) entry->value_len);
    print_SHA("    Auth  ", &entry->auth_key);
    print_SHA("    C2    ", &entry->c2);
}

//=======================================================================================
/**
 * @see ckvs_utils.h
 */
void print_SHA(const char *prefix, const struct ckvs_sha *sha)
{
    M_REQUIRE_NON_NULL_VOID_FUNCTION(prefix);
    M_REQUIRE_NON_NULL_VOID_FUNCTION(sha);

    char buffer[SHA256_PRINTED_STRLEN];
    SHA256_to_string(sha, buffer);

    pps_printf("%-5s: %s\n", prefix, buffer);
}

//=======================================================================================
/**
 * @see ckvs_utils.h
 */
void SHA256_to_string(const struct ckvs_sha *sha, char *buf)
{
    M_REQUIRE_NON_NULL_VOID_FUNCTION(sha);
    M_REQUIRE_NON_NULL_VOID_FUNCTION(buf);

    hex_encode(sha->sha, SHA256_DIGEST_LENGTH, buf);
}

//=======================================================================================
/**
 * @see ckvs_utils.h
 */
void hex_encode(const uint8_t *in, const size_t len, char *buf)
{
    M_REQUIRE_NON_NULL_VOID_FUNCTION(in);
    M_REQUIRE_NON_NULL_VOID_FUNCTION(buf);

    for (size_t i = 0; i < len; ++i)
    {
        buf += sprintf(buf, "%02x", in[i]);
    }
}

//=======================================================================================
/**
 * @see ckvs_utils.h
 */
int ckvs_cmp_sha(const struct ckvs_sha *a, const struct ckvs_sha *b)
{
    M_REQUIRE_NON_NULL_VARGS(a, b);
    return memcmp(a, b, SHA256_DIGEST_LENGTH);
}

//=======================================================================================
/**
 * @date  4/05/2022
 * @brief Append a character at the beginning of the string str.
 *
 * @param before (char)         the new character to append.
 * @param str    (const char*)  the string where to append.
 * @param len    (const size_t) the length of the string str.
 *
 * @return (char*) A pointer to the new string or NULL if calloc fails.
 */
static char *append_at_beginning(char before, const char *str, const size_t len)
{
    char *ret = calloc(len + 2, sizeof(char)); // null-byte + new character
    if (!ret)
    {
        return NULL;
    }

    *ret = before;
    memmove(ret + 1, str, len);
    return ret;
}

//=======================================================================================
/**
 * @date  4/05/2022
 * @brief convert a hex encoded string into an array of bytes
 *
 * @param buf   (uint8_t)     the resulting array of bytes
 * @param size  (size_t)      the size of the string input
 * @param input (const char*) the string to be converted
 *
 * @return (int) the number of bytes written in buf.
 */
static int convert(uint8_t *buf, const size_t size, const char * input)
{
    size_t i = 0, count = 0;
    while(i < size)
    {
        char data[2] = { input[i], input[i + 1] };
        buf[count++] = (uint8_t) strtoul(data, NULL, 16);
        i += 2;
    }
    return (int) count;
}

//=======================================================================================
/**
 * @see ckvs_utils.h
 */
int hex_decode(const char *in, uint8_t *buf)
{
    if (in == NULL || buf == NULL || *in == '\0')
    {
        return -1;
    }

    const size_t size = strlen(in);

    if (size % 2)
    {
        char* formated_input = append_at_beginning('0', in, size);
        if (!formated_input)
        {
            return ERR_OUT_OF_MEMORY;
        }

        const int ret = convert(buf, size, formated_input);
        free(formated_input);
        return ret;
    }

    return convert(buf, size, in);
}

//=======================================================================================
/**
 * @see ckvs_utils.h
 */
int SHA256_from_string(const char *in, struct ckvs_sha *sha)
{
    M_REQUIRE_NON_NULL_VARGS(in, sha);
    return hex_decode(in, sha->sha);
}

