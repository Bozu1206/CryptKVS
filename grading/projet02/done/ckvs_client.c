#include "error.h"
#include "ckvs_rpc.h"
#include "ckvs.h"
#include "util.h"
#include "ckvs_crypto.h"
#include <stdlib.h>
#include <json-c/json.h>
#include <openssl/hmac.h>

//=======================================================================================
/**
 * @brief Prefix for printing keys in command stats.
 */
#define KEY_PREFIX        "Key       : %s\n"
#define PAYLOAD           "/get?key=&auth_key="
#define PAYLOAD_FORMAT    "/get?key=%s&auth_key=%s"

//=======================================================================================
/**
 * @brief Useful to map string error to error for JSON parsing + convenience typedef.
 */
struct ckvs_string_error_mapping
{
    const char *string;
    const int err_code;
};

typedef struct ckvs_string_error_mapping ckvs_string_error_mapping_t;

//=======================================================================================
/**
 * @brief Mapping between string error fetched from JSON response and corresponding error code
 */
static const ckvs_string_error_mapping_t JSON_string_error_mapping[] =
{
    {.string = "Error: Incorrect key/password", .err_code = ERR_DUPLICATE_ID},
    {.string = "Error: Invalid argument", .err_code = ERR_INVALID_ARGUMENT},
    {.string = "Error: Key not found", .err_code = ERR_KEY_NOT_FOUND}
};

//=======================================================================================
/**
 * @date  3/05/2022
 * @brief Do the conversion between string error obtained when an HTTP/S request was made and error code
 *
 * @param connection (ckvs_connection_t *) the data structure holding the response.
 *
 * @return (int) error code (@see error.h/c)
 */
static int ckvs_error_checker(const ckvs_connection_t *connection)
{
    int err_response = 0;
    for (size_t i = 0; i < 3; ++i)
    {
        if (strcmp(connection->resp_buf, JSON_string_error_mapping[i].string) == 0)
        {
            err_response = JSON_string_error_mapping[i].err_code;
        }
    }

    return err_response;
}

//=======================================================================================
/**
 * @date  3/05/2022
 * @brief Helper function to prepare the payload for the get command.
 *        This function escape the key.
 *
 * @param key               (const char *)          the key, also be in the payload
 * @param connection        (ckvs_connection_t *)   the connection
 * @param hex_encoded_auth  (char *)                the hex encoded auth key
 * @param escaped_key       (char **)               reference to the string which will hold the escaped key
 * @param payload           (char **)               the final payload
 *
 * @return (int) error code (@see error.h/c)
 */
static int payload_preparation(const char *key, ckvs_connection_t *connection,
                               char *hex_encoded_auth, char **escaped_key, char **payload)
{
    /* Escape key */
    *escaped_key = curl_easy_escape(connection->curl, key, 0);
    if (!(*escaped_key))
    {
        return ERR_OUT_OF_MEMORY;
    }

    const size_t payload_size = 1 + strlen(PAYLOAD)
                                + strlen((*escaped_key))
                                + strlen(hex_encoded_auth);
    /* Init the payload */
    *payload = calloc(payload_size, sizeof(char));
    if (!(*payload))
    {
        return ERR_OUT_OF_MEMORY;
    }

    /* Format the payload in the correct format */
    /* -1 in the condition because snprintf returns
     * the number of characters without counting the null byte. */
    if (snprintf((*payload), payload_size, PAYLOAD_FORMAT, (*escaped_key), hex_encoded_auth)
        != (int) payload_size - 1)
    {
        return ERR_IO;
    }

    return ERR_NONE;
}

//=======================================================================================
/**
 * @date  3/05/2022
 * @brief Helper function for get command to decrypt the buffer and display it.
 *
 * @param mr         (ckvs_memrecord_t *mr)  Hold crypto parameters.
 * @param c2_string  (const char *)          Useful to compute the masterkey
 * @param data       (const char *)          The data to decrypt.
 *
 * @return (int) error code (@see error.h/c)
 */
static int ckvs_performs_decryption(ckvs_memrecord_t *mr, const char *c2_string, const char *data)
{
    ckvs_sha_t *c2 = calloc(1, sizeof(ckvs_sha_t));
    if (!c2)
    {
        return ERR_OUT_OF_MEMORY;
    }

    SHA256_from_string(c2_string, c2);

    const int err_master_key = ckvs_client_compute_masterkey(mr, c2);
    if (err_master_key != ERR_NONE)
    {
        free(c2);
        return err_master_key;
    }

    free(c2);

    size_t decrypt_size = 0;
    unsigned char *value = calloc(strlen(data) + EVP_MAX_BLOCK_LENGTH, sizeof(unsigned char));
    if (value == NULL)
    {
        return ERR_OUT_OF_MEMORY;
    }

    uint8_t *raw_data = calloc(strlen(data) / 2, sizeof(uint8_t));
    const size_t bytes_number = (size_t) hex_decode(data, raw_data);

    const int err_dec = ckvs_client_crypt_value(mr, 0,
                                                (unsigned char *) raw_data, bytes_number,
                                                value, &decrypt_size);

    if (err_dec != ERR_NONE)
    {
        free(raw_data);
        free(value);
        return err_dec;
    }

    free(raw_data);

    pps_printf("%s", value);
    free(value);
    return ERR_NONE;
}


//=======================================================================================
/**
 * @date  3/05/2022
 * @brief Parse a JSON response and do specific thing based on the value of @param ID
 *
 * @param connection      (ckvs_connection_t *)  the current connection
 * @param json_from_con   (json_object **)       the JSON object from the current connection buffer.
 * @param json_c2_string  (json_object **)       NOT NULL if @param ID = 1
 * @param json_data       (json_object **)       NOT NULL if @param ID = 1
 * @param ID              (const int)            if id == 0 then parse for a 'stats' command
 *                                               if id == 1 then parse for a 'get' command
 *
 * @return (int) error code (@see error.h/c)
 */
static int JSON_parser_and_print(ckvs_connection_t *connection, json_object **json_from_con,
                                 json_object **json_c2_string, json_object **json_data, const int ID)
{
    *json_from_con = json_tokener_parse(connection->resp_buf);
    if (*json_from_con == NULL)
    {
        return ERR_OUT_OF_MEMORY;
    }

    if (ID == 0)
    {
        json_object *json_header_string, *json_version, *json_table_size;
        json_object *json_threshold, *json_num_entries, *json_key_array;

        if (!json_object_object_get_ex(*json_from_con, "header_string", &json_header_string) ||
            !json_object_object_get_ex(*json_from_con, "version", &json_version)             ||
            !json_object_object_get_ex(*json_from_con, "table_size", &json_table_size)       ||
            !json_object_object_get_ex(*json_from_con, "threshold_entries", &json_threshold) ||
            !json_object_object_get_ex(*json_from_con, "num_entries", &json_num_entries)     ||
            !json_object_object_get_ex(*json_from_con, "keys", &json_key_array))
        {
            json_object_put(*json_from_con);
            return ERR_IO;
        }

        const char *header_string = json_object_get_string(json_header_string);
        const int32_t version     = json_object_get_int(json_version);
        const int32_t table_size  = json_object_get_int(json_table_size);
        const int32_t threshold   = json_object_get_int(json_threshold);
        const int32_t num_entries = json_object_get_int(json_num_entries);

        pps_printf(HEADER_TYPE_MSG, header_string);
        pps_printf(HEADER_VERS_MSG, (unsigned long) version);
        pps_printf(HEADER_SIZE_MSG, (unsigned long) table_size);
        pps_printf(HEADER_THRE_MSG, (unsigned long) threshold);
        pps_printf(HEADER_NENT_MSG, (unsigned long) num_entries);

        const size_t array_len = json_object_array_length(json_key_array);
        for (size_t i = 0; i < array_len; ++i)
        {
            json_object *key_arr = json_object_array_get_idx(json_key_array, i);
            if (!key_arr)
            {
                json_object_put(*json_from_con);
                return ERR_IO;
            }

            const char *key = json_object_get_string(key_arr);
            pps_printf(KEY_PREFIX, key);
        }
    }
    else
    {
            if (!json_object_object_get_ex((*json_from_con), "c2", json_c2_string) ||
                !json_object_object_get_ex((*json_from_con), "data", json_data))
            {
                json_object_put((*json_from_con));
                return ERR_IO;
            }
    }

    return ERR_NONE;
}

//=======================================================================================
/**
 * @see ckvs_client.h
 */
int ckvs_client_stats(const char *url, int optargc, char **optargv)
{
    M_REQUIRE_NON_NULL_VARGS(url, optargv);
    ARG_CHECK(0, optargc);

    /* ------------------------- Init connection and request  ------------------------- */
    ckvs_connection_t *connection = calloc(1, sizeof(ckvs_connection_t));
    if (!connection)
    {
        return ERR_OUT_OF_MEMORY;
    }

    const int err_init = ckvs_rpc_init(connection, url);
    if (err_init != ERR_NONE)
    {
        free(connection);
        return err_init;
    }

    const int err_get = ckvs_rpc(connection, "/stats");
    if (err_get != ERR_NONE)
    {
        ckvs_rpc_close(connection);
        free(connection);
        return err_get;
    }

    /* ------------------------- JSON Parsing and printing ------------------------- */
    json_object *json_from_con;
    const int err_parse =
            JSON_parser_and_print(connection, &json_from_con, NULL, NULL, 0);

    if (err_parse)
    {
        ckvs_rpc_close(connection);
        free(connection);
        return err_parse;
    }

    json_object_put(json_from_con);
    ckvs_rpc_close(connection);
    free(connection);
    return ERR_NONE;
}

//=======================================================================================
/**
 * @brief Clean the memrecord structure and the connection, because those lines are repeated
 *        very often.
 */
#define CLEAN_UP(MR, CON)   free(MR);               \
                            ckvs_rpc_close(CON);    \
                            free(CON)               \
                                                    \
//=======================================================================================
/**
 * @see ckvs_client.h
 */
int ckvs_client_get(const char *url, int optargc, char **optargv)
{
    /* ------------------------- Checks ------------------------- */
    M_REQUIRE_NON_NULL_VARGS(url, optargv);
    ARG_CHECK(2, optargc);

    const char *key = optargv[0];
    const char *password = optargv[1];

    M_REQUIRE_NON_NULL_VARGS(key, password);
    CKVS_CHECK_KEY(key);

    /* ------------------------- Initialization ------------------------- */
    ckvs_memrecord_t *mr = calloc(1, sizeof(ckvs_memrecord_t));
    if (!mr)
    {
        return ERR_OUT_OF_MEMORY;
    }

    const int err_init = ckvs_client_encrypt_pwd(mr, key, password);
    if (err_init)
    {
        free(mr);
        return err_init;
    }

    ckvs_connection_t *connection = calloc(1, sizeof(ckvs_connection_t));
    if (!connection)
    {
        free(mr);
        return ERR_OUT_OF_MEMORY;
    }

    const int err_init_rpc = ckvs_rpc_init(connection, url);
    if (err_init_rpc != ERR_NONE)
    {
        CLEAN_UP(mr, connection);
        return err_init_rpc;
    }

    /* ------------------------- Communication with the server ------------------------- */
    char *hex_encoded_auth = calloc(SHA256_PRINTED_STRLEN, sizeof(char));
    if (!hex_encoded_auth)
    {
        CLEAN_UP(mr, connection);
        return ERR_OUT_OF_MEMORY;
    }

    SHA256_to_string(&mr->auth_key, hex_encoded_auth);

    /* ------------------------- Payload preparation ------------------------- */
    char *escaped_key = NULL;
    char *payload = NULL;

    const int err_payload_prep =
    payload_preparation(key, connection, hex_encoded_auth, &escaped_key, &payload);

    if (err_payload_prep)
    {
        CLEAN_UP(mr, connection);
        curl_free(escaped_key);
        free(hex_encoded_auth);
        free(payload);
        return err_payload_prep;
    }

    curl_free(escaped_key);
    free(hex_encoded_auth);

    const int err_get = ckvs_rpc(connection, payload);
    if (err_get != ERR_NONE)
    {
        CLEAN_UP(mr, connection);
        free(payload);
        return err_get;
    }

    free(payload);

    const int err_response = ckvs_error_checker(connection);
    if (err_response)
    {
        CLEAN_UP(mr, connection);
        return err_response;
    }

    /* ------------------------- JSON Parsing  ------------------------- */
    json_object *json_from_con, *json_c2_string, *json_data;

    const int err_parse =
            JSON_parser_and_print(connection, &json_from_con, &json_c2_string, &json_data, 1);

    if (err_parse)
    {
        CLEAN_UP(mr, connection);
        return ERR_IO;
    }

    /* ------------------------- Decryption ------------------------- */
    const char *c2_string = json_object_get_string(json_c2_string);
    const char *data = json_object_get_string(json_data);
    const int err_dec = ckvs_performs_decryption(mr, c2_string, data);

    CLEAN_UP(mr, connection);
    json_object_put(json_from_con);
    return (err_dec != ERR_NONE ? err_dec : ERR_NONE);
}
