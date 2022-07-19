#include "ckvs.h"
#include "util.h"
#include <stdlib.h>

/**
 * @brief Because with a hex number fits in 4 bits
 */
#define HEX_LEN        2

/**
 * @brief Simple error to return in case of an error in header check.
 */
#define ERROR_CHECK   -1

/**
 * @brief Many messages define here when printing the database
 */
#define C2_MSG           "    C2    "
#define KEY_MSG          "    Key   : "
#define AUTH_MSG         "    Auth  "
#define VALUE_OFF_MSG    "    Value : off %lu len %lu\n"
#define SHA_PREFIX_FMT   "%-5s: %s\n"

/**
 * @brief Messages for printing the header's informations.
 */
#define HEADER_TYPE_MSG  "CKVS Header type       : %s\n"
#define HEADER_VERS_MSG  "CKVS Header version    : %lu\n"
#define HEADER_SIZE_MSG  "CKVS Header table_size : %lu\n"
#define HEADER_THRE_MSG  "CKVS Header threshold  : %lu\n"
#define HEADER_NENT_MSG  "CKVS Header num_entries: %lu\n"

/**
 * @brief Prints the key.
 * @Note: there exist surely a more simpler method, but I can't understand STR_LENGTH_FMT well)
 */
#define print_key(key)                               \
    pps_printf(KEY_MSG);                             \
    pps_printf(STR_LENGTH_FMT(CKVS_MAXKEYLEN), key); \
    pps_printf("\n");                                \

/**
 * @brief Determine if a number is a power of two.
 * @Note Code was taken from :
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

    M_REQUIRE(strncmp(CKVS_HEADERSTRING_PREFIX, header->header_string, strlen(CKVS_HEADERSTRING_PREFIX)) == 0, ERROR_CHECK, "");
    M_REQUIRE(header->version == 1, ERROR_CHECK, "");
    M_REQUIRE(is_power_of_two(header->table_size), ERROR_CHECK, "");

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
    pps_printf(VALUE_OFF_MSG, (unsigned long) entry->value_off, (unsigned long) entry->value_len);
    print_SHA(AUTH_MSG, &entry->auth_key);
    print_SHA(C2_MSG, &entry->c2);
}

//=======================================================================================
/**
 * @see ckvs_utils.h
 */
void print_SHA(const char *prefix, const struct ckvs_sha *sha)
{
    M_REQUIRE_NON_NULL_VOID_FUNCTION(prefix);
    M_REQUIRE_NON_NULL_VOID_FUNCTION(sha);

    char buffer[HEX_LEN * SHA256_PRINTED_STRLEN];
    SHA256_to_string(sha, buffer);

    pps_printf(SHA_PREFIX_FMT, prefix, buffer);
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
