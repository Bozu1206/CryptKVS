#pragma once
/**
 * @file util.h
 * @brief PPS (CS-212) Tool macros
 *
 * @author Jean-Cédric Chappelier
 * @date 2017-2021
 */
#include <assert.h> // see TO_BE_IMPLEMENTED

//=======================================================================================
/**
 * @brief tag a variable as POTENTIALLY unused, to avoid compiler warnings
 */
#define _unused __attribute__((unused))

//=======================================================================================
/**
 * @brief useful for partial implementation
 */
#define TO_BE_IMPLEMENTED() \
    do { fprintf(stderr, "TO_BE_IMPLEMENTED!\n"); assert(0); } while (0)

//=======================================================================================
/**
 * @brief useful to free pointers to const without warning. Use with care!
 */
#define free_const_ptr(X) free((void*)X)

//=======================================================================================
/**
 * @brief useful to have C99 (!) %zu to compile in Windows
 */
#if defined _WIN32  || defined _WIN64
#define SIZE_T_FMT "%u"
#else
#define SIZE_T_FMT "%zu"
#endif

//=======================================================================================
/**
 * @brief useful to specify a length defined by a macro for format strings
 */
#define STR(x) #x
#define STR_LENGTH_FMT(x) "%." STR(x) "s"

/* -------------------------------- Added by the group --------------------------------- */

//=======================================================================================
/**
 *
 * @brief Check the length of the key, indeed the key can't be only "\0" because it represents
 *        a free entry in the database, although this key could be considered valid.
 *
 *        Useful to define this here, because both ckvs_local and ckvs_client will use it.
 */
#define CKVS_CHECK_KEY(key)                                                \
        const size_t length = strnlen(key, CKVS_MAXKEYLEN);                \
        M_REQUIRE(length != 0, ERR_INVALID_ARGUMENT, "");                  \
        M_REQUIRE(length <= CKVS_MAXKEYLEN, ERR_INVALID_ARGUMENT, "")      \

//=======================================================================================
/**
 *
 * @brief Useful definition the check whether a command has the correct number of arguments.
 *
 *        We decide to define this macro here because both ckvs_local and ckvs_client will use it.
 */
#define ARG_CHECK(N, ARG)                                        \
    const int error = ((ARG) > (N) ? ERR_TOO_MANY_ARGUMENTS      \
                    :  (ARG) < (N) ? ERR_NOT_ENOUGH_ARGUMENTS    \
                    : 0);                                        \
    M_REQUIRE(error == 0, error, "")

//=======================================================================================
/**
 * @brief Messages for printing the header's information's. Defined here because both ckvs_client
 *        and ckvs_local will use it.
 */
#define HEADER_TYPE_MSG  "CKVS Header type       : %s\n"
#define HEADER_VERS_MSG  "CKVS Header version    : %lu\n"
#define HEADER_SIZE_MSG  "CKVS Header table_size : %lu\n"
#define HEADER_THRE_MSG  "CKVS Header threshold  : %lu\n"
#define HEADER_NENT_MSG  "CKVS Header num_entries: %lu\n"

//=======================================================================================