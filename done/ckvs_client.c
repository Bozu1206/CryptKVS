#include "util.h"
#include "ckvs.h"
#include "error.h"
#include "ckvs_io.h"
#include "ckvs_rpc.h"
#include "ckvs_crypto.h"
#include <stdlib.h>
#include <json-c/json.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

//=======================================================================================
/**
 * @brief Some prefix and format mostly used to build URL's.
 */
#define KEY_PREFIX            "Key       : %s\n"
#define GET_PAYLOAD           "/get?key=&auth_key="
#define GET_PAYLOAD_FORMAT    "/get?key=%s&auth_key=%s"
#define SET_PAYLOAD           "/set?name=&offset=0&key=&auth_key="
#define SET_PAYLOAD_FORMAT    "/set?name=%s&offset=0&key=%s&auth_key=%s"
#define POST_FILENAME         "data.json"

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
 * @param code              (const int)             differentiate a get from a set
 *
 * @return (int) error code (@see error.h/c)
 */
static int getset_payload_preparation(const char *key, ckvs_connection_t *connection, char *hex_encoded_auth,
                                      char **payload, const int code)
{
    M_REQUIRE_NON_NULL_VARGS(key, connection, hex_encoded_auth, payload);

    /* Escape key */
    char * escaped_key = curl_easy_escape(connection->curl, key, 0);
    M_REQUIRE(escaped_key != NULL, ERR_OUT_OF_MEMORY, "");

    if (code == 0)
    {
        const size_t payload_size = 1 + strlen(GET_PAYLOAD)
                                    + strlen(escaped_key)
                                    + strlen(hex_encoded_auth);
        /* Init the payload */
        *payload = calloc(payload_size, sizeof(char));
        M_REQUIRE(*payload != NULL, ERR_OUT_OF_MEMORY, "");


        /* Format the payload in the correct format */
        /* -1 in the condition because snprintf returns
         * the number of characters without counting the null byte. */
        if (snprintf((*payload), payload_size, GET_PAYLOAD_FORMAT, escaped_key, hex_encoded_auth)
                != (int) payload_size - 1)
        {
            curl_free(escaped_key);
            return ERR_IO;
        }
    }
    else
    {
        const size_t payload_size = 1 + strlen(SET_PAYLOAD)
                                    + strlen(POST_FILENAME)
                                    + strlen(escaped_key)
                                    + strlen(hex_encoded_auth);
        /* Init the payload */
        *payload = calloc(payload_size, sizeof(char));
        M_REQUIRE(*payload != NULL, ERR_OUT_OF_MEMORY, "");

        if (snprintf((*payload), payload_size, SET_PAYLOAD_FORMAT, POST_FILENAME, escaped_key, hex_encoded_auth)
                != (int) payload_size - 1)
        {
            curl_free(escaped_key);
            return ERR_IO;
        }
    }

    curl_free(escaped_key);
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
    M_REQUIRE_NON_NULL_VARGS(mr, c2_string, data);

    ckvs_sha_t c2;
    SHA256_from_string(c2_string, &c2);

    const int err_master_key = ckvs_client_compute_masterkey(mr, &c2);
    M_REQUIRE(err_master_key == ERR_NONE, ERR_OUT_OF_MEMORY, "");

    size_t decrypt_size = 0;
    size_t size_of_raw_data = (1 + strlen(data)) >> 1;
    unsigned char *value = calloc(size_of_raw_data + EVP_MAX_BLOCK_LENGTH, sizeof(unsigned char));
    M_REQUIRE(value != NULL, ERR_OUT_OF_MEMORY, "");

    uint8_t *raw_data = calloc(size_of_raw_data, sizeof(uint8_t));
    if (raw_data == NULL)
    {
        free(value);
        return ERR_OUT_OF_MEMORY;
    }

    const size_t bytes_number = (size_t) hex_decode(data, raw_data);
    const int err_dec = ckvs_client_crypt_value(mr, 0,
                        (unsigned char *) raw_data, bytes_number,
                        value, &decrypt_size);

    pps_printf("%s", value);
    free(raw_data);
    free(value);
    return (err_dec != ERR_NONE) ? err_dec : ERR_NONE;
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
static int JSON_parser_and_print(ckvs_connection_t *connection, const char **c2, const char **data,
                                 ckvs_memrecord_t *mr, const int ID)
{
    M_REQUIRE_NON_NULL_VARGS(connection);

    json_object *json_from_con = json_tokener_parse(connection->resp_buf);
    if (json_from_con == NULL)
    {
        pps_printf("%s\n", connection->resp_buf);
        return ERR_IO;
    }

    if (ID == 0)
    {
        /* --------------------------------- Stats --------------------------------- */
        json_object *json_header_string, *json_version, *json_table_size;
        json_object *json_threshold, *json_num_entries, *json_key_array;

        if (!json_object_object_get_ex(json_from_con, "header_string", &json_header_string)     ||
                !json_object_object_get_ex(json_from_con, "version", &json_version)             ||
                !json_object_object_get_ex(json_from_con, "table_size", &json_table_size)       ||
                !json_object_object_get_ex(json_from_con, "threshold_entries", &json_threshold) ||
                !json_object_object_get_ex(json_from_con, "num_entries", &json_num_entries)     ||
                !json_object_object_get_ex(json_from_con, "keys", &json_key_array))
        {
            json_object_put(json_from_con);
            return ERR_IO;
        }

        ckvs_header_t header =
        {
            .header_string     = {0},
            .version           = (uint32_t)  json_object_get_int(json_version),
            .table_size        = (uint32_t)  json_object_get_int(json_table_size),
            .threshold_entries = (uint32_t)  json_object_get_int(json_threshold),
            .num_entries       = (uint32_t)  json_object_get_int(json_num_entries)
        };

        strncpy(header.header_string, json_object_get_string(json_header_string), CKVS_HEADERSTRINGLEN);
        print_header(&header);

        const size_t array_len = json_object_array_length(json_key_array);
        for (size_t i = 0; i < array_len; ++i)
        {
            json_object *key_arr = json_object_array_get_idx(json_key_array, i);
            if (key_arr == NULL)
            {
                json_object_put(json_from_con);
                return ERR_IO;
            }

            const char *key = json_object_get_string(key_arr);
            pps_printf(KEY_PREFIX, key);
        }
    }
    else
    {
        /* --------------------------------- GET --------------------------------- */
        json_object *json_c2_string;
        if (!json_object_object_get_ex(json_from_con, "c2", &json_c2_string))
        {
            json_object_put(json_from_con);
            return ERR_IO;
        }
        *c2 = json_object_get_string(json_c2_string);

        ckvs_sha_t sha_c2;
        SHA256_from_string(*c2, &sha_c2);
        const int err_masterkey = ckvs_client_compute_masterkey(mr, &sha_c2);
        if (err_masterkey != ERR_NONE)
        {
            json_object_put(json_from_con);
            return err_masterkey;
        }

        json_object *json_data;
        if (!json_object_object_get_ex(json_from_con, "data", &json_data))
        {
            json_object_put(json_from_con);
            return ERR_IO;
        }
        *data = json_object_get_string(json_data);

        const int err_dec = ckvs_performs_decryption(mr, *c2, *data);
        if (err_dec != ERR_NONE)
        {
            json_object_put(json_from_con);
            return err_dec;
        }
    }

    json_object_put(json_from_con);
    return ERR_NONE;
}

//=======================================================================================
/**
 * @brief Read a file and encrypt it's content.
 *
 * @param filename     (const char *)      the file to be read
 * @param crypted      (unsigned char **)  the buffer that will contain the encrypted content of the file
 * @param crypted_size (size_t *)          the (future) size of the encrypted buffer
 * @param mr           (ckvs_memrecord_t)  the cryptographic structure used for encryption
 *
 * @return (int) error code (@see error.h/c)
 */
static int read_encrypt_file(const char * filename, unsigned char **crypted, size_t *crypted_size, ckvs_memrecord_t *mr)
{
    M_REQUIRE_NON_NULL_VARGS(filename, mr);

    size_t set_size = 0;
    char * set_value = NULL;
    const int err_read = read_value_file_content(filename, &set_value, &set_size);
    M_REQUIRE(err_read == ERR_NONE, err_read, "");

    size_t size = 0;
    unsigned char *crypted_value = calloc(1 + strlen(set_value) + EVP_MAX_BLOCK_LENGTH,
                                          sizeof(unsigned char));
    if (crypted_value == NULL)
    {
        return ERR_OUT_OF_MEMORY;
    }

    /* ENCRYPTION */
    const int encrypt = ckvs_client_crypt_value(mr, 1,
                        (const unsigned char *) set_value,
                        strlen(set_value) + 1,
                        crypted_value,
                        &size);
    if (encrypt != ERR_NONE)
    {
        free(crypted_value);
        return encrypt;
    }

    *crypted_size = size;
    *crypted = crypted_value;
    free(set_value);
    return ERR_NONE;
}

//=======================================================================================
/**
 * @see ckvs_client.h
 */
int ckvs_client_stats(const char *url, int optargc, char **optargv)
{
    /* ------------------------- Checks ------------------------- */
    M_REQUIRE_NON_NULL_VARGS(url, optargv);
    ARG_CHECK(0, optargc);

    /* ------------------------- Init connection and request  ------------------------- */
    ckvs_connection_t *connection = calloc(1, sizeof(ckvs_connection_t));
    M_REQUIRE(connection != NULL, ERR_OUT_OF_MEMORY, "");

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
    const int err_parse = JSON_parser_and_print(connection, NULL, NULL, NULL, 0);

    ckvs_rpc_close(connection);
    free(connection);
    return (err_parse != ERR_NONE) ? err_parse : ERR_NONE;
}

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
    ckvs_memrecord_t mr;
    memset(&mr, 0, sizeof(ckvs_memrecord_t));
    const int err_init = ckvs_client_encrypt_pwd(&mr, key, password);
    M_REQUIRE(err_init == ERR_NONE, err_init, "");

    ckvs_connection_t *connection = calloc(1, sizeof(ckvs_connection_t));
    M_REQUIRE(connection != NULL, ERR_OUT_OF_MEMORY, "");

    const int err_init_rpc = ckvs_rpc_init(connection, url);
    if (err_init_rpc != ERR_NONE)
    {
        free(connection);
        return err_init_rpc;
    }

    /* ------------------------- Communication with the server ------------------------- */
    char *hex_encoded_auth = calloc(SHA256_PRINTED_STRLEN, sizeof(char));
    if (!hex_encoded_auth)
    {
        ckvs_rpc_close(connection);
        free(connection);
        return ERR_OUT_OF_MEMORY;
    }

    SHA256_to_string(&mr.auth_key, hex_encoded_auth);

    /* ------------------------- Payload preparation ------------------------- */
    char *payload = NULL;

    const int err_payload_prep =
    getset_payload_preparation(key, connection, hex_encoded_auth, &payload, 0);

    free(hex_encoded_auth);

    if (err_payload_prep)
    {
        ckvs_rpc_close(connection);
        free(connection);
        free(payload);
        return err_payload_prep;
    }

    const int err_get = ckvs_rpc(connection, payload);
    if (err_get != ERR_NONE)
    {
        ckvs_rpc_close(connection);
        free(connection);
        free(payload);
        return err_get;
    }

    free(payload);

    /* ------------------------- JSON Parsing & decryption (done in JSON parser) ------------------------- */
    const char *c2 = NULL;
    const char *data = NULL;
    const int err_parse = JSON_parser_and_print(connection, &c2, &data, &mr, 1);

    ckvs_rpc_close(connection);
    free(connection);
    return (err_parse != ERR_NONE) ? ERR_IO : ERR_NONE;
}

//=======================================================================================
/**
 * @see ckvs_client.h
 */
int ckvs_client_set(const char *url, int optargc, char **optargv)
{
    /* ------------------------- Checks ------------------------- */
    M_REQUIRE_NON_NULL_VARGS(url, optargv);
    ARG_CHECK(3, optargc);

    const char *key = optargv[0];
    const char *password = optargv[1];
    const char *filename = optargv[2];

    M_REQUIRE_NON_NULL_VARGS(key, password, filename);
    CKVS_CHECK_KEY(key);

    /* ------------------------- Initialization ------------------------- */
    ckvs_sha_t c2[SHA256_DIGEST_LENGTH];
    if (RAND_bytes(c2->sha, SHA256_DIGEST_LENGTH) != 1)
    {
        return ERR_IO;
    }

    ckvs_memrecord_t mr;
    memset(&mr, 0, sizeof(ckvs_memrecord_t));
    const int err_init = ckvs_client_encrypt_pwd(&mr, key, password);
    M_REQUIRE(err_init == ERR_NONE, err_init, "");

    /* Recompute the master-key because of new C2 */
    const int err_masterkey = ckvs_client_compute_masterkey(&mr, c2);
    M_REQUIRE(err_masterkey == ERR_NONE, err_masterkey, "");

    /* ------------------------- Read and encrypt file ------------------------- */
    size_t size = 0;
    unsigned char *crypted_value = NULL;
    const int err_encrypt = read_encrypt_file(filename, &crypted_value, &size, &mr);
    M_REQUIRE(err_encrypt == ERR_NONE, err_encrypt, "");

    /* ------------------------- Encode C2 and data ------------------------- */
    char hex_encoded_c2[SHA256_PRINTED_STRLEN];
    hex_encode(c2->sha, SHA256_DIGEST_LENGTH, hex_encoded_c2);

    char * hex_encoded_data = calloc(2 * size + 1, sizeof(char));
    M_REQUIRE(hex_encoded_data != NULL, ERR_OUT_OF_MEMORY, "");
    hex_encode(crypted_value,size, hex_encoded_data);
    hex_encoded_data[2 * size] = '\0';

    free(crypted_value);

    /* ------------------------- Init connection ------------------------- */
    ckvs_connection_t *connection = calloc(1, sizeof(ckvs_connection_t));
    M_REQUIRE(connection != NULL, ERR_OUT_OF_MEMORY, "");

    const int err_init_rpc = ckvs_rpc_init(connection, url);
    if (err_init_rpc != ERR_NONE)
    {
        ckvs_rpc_close(connection);
        free(connection);
        return err_init_rpc;
    }

    /* ------------------------- Payload preparation ------------------------- */
    char *hex_encoded_auth = calloc(SHA256_PRINTED_STRLEN, sizeof(char));
    if (hex_encoded_auth == NULL)
    {
        ckvs_rpc_close(connection);
        free(connection);
        free(hex_encoded_data);
        return ERR_OUT_OF_MEMORY;
    }

    SHA256_to_string(&mr.auth_key, hex_encoded_auth);

    char *payload = NULL;
    const int err_payload_prep =
    getset_payload_preparation(key, connection, hex_encoded_auth, &payload, 1);

    free(hex_encoded_auth);

    if (err_payload_prep != ERR_NONE)
    {
        ckvs_rpc_close(connection);
        free(connection);
        free(payload);
        free(hex_encoded_data);
        return err_payload_prep;
    }

    /* ------------------------- Create JSON POST ------------------------- */
    json_object *POST = json_object_new_object();

    json_object *json_c2   = json_object_new_string(hex_encoded_c2);
    json_object *json_data = json_object_new_string(hex_encoded_data);

    json_object_object_add(POST, "c2", json_c2);
    json_object_object_add(POST, "data", json_data);

    free(hex_encoded_data);

    /* ------------------------- Send data ------------------------- */
    const int post_error = ckvs_post(connection, payload, json_object_get_string(POST));

    json_object_put(POST);
    ckvs_rpc_close(connection);
    free(payload);
    free(connection);
    return (post_error != ERR_NONE) ? post_error : ERR_NONE;
}

//=======================================================================================
/**
 * @see ckvs_client.h
 *
 * @note : not done in project.
 */
int ckvs_client_new(const char _unused *url, int _unused optargc, char _unused **optargv)
{
    return NOT_IMPLEMENTED;
}
