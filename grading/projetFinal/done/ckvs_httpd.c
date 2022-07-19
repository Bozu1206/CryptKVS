/**
 * @file ckvs_httpd.c
 * @brief webserver
 *
 * @author Edouard Bugnion
 */
// ======================================================================
#include "ckvs.h"
#include "ckvs_io.h"
#include "ckvs_utils.h"
#include "error.h"
#include "ckvs_httpd.h"
#include <assert.h>
#include "mongoose.h"
#include <json-c/json.h>
#include <string.h>
#include <assert.h>
#include <curl/curl.h>
#include "util.h"

// Handle interrupts, like Ctrl-C
static int s_signo;

// ======================================================================
/**
 * @brief Common HTTP codes used
 */
#define HTTP_ERROR_CODE    500
#define HTTP_OK_CODE       200
#define HTTP_FOUND_CODE    302
#define HTTP_NOTFOUND_CODE 404

// ======================================================================
/**
 * @brief Helper macro to check argument before handling command
 */
#define ARGUMENT_CHECKER(nc, ckvs, hm) M_REQUIRE_NON_NULL_VOID_FUNCTION(nc); \
                                       M_REQUIRE_NON_NULL_VOID_FUNCTION(hm); \
                                       M_REQUIRE_NON_NULL_VOID_FUNCTION(ckvs)

// ======================================================================
/**
 * @brief Sends an http error message
 * @param nc the http connection
 * @param err the error code corresponding the error message
*/
void mg_error_msg(struct mg_connection* nc, int err)
{
    assert(err>= 0 && err < ERR_NB_ERR);
    mg_http_reply(nc, HTTP_ERROR_CODE, NULL, "Error: %s", ERR_MESSAGES[err]);
}

// ======================================================================
/**
 * @brief Handles signal sent to program, eg. Ctrl+C
 */
static void signal_handler(int signo)
{
    s_signo = signo;
}

// ======================================================================
/**
 * @brief Unescape the parameter key from an URL.
 *
 * @param hm  (mg_http_message *) contains the HTTP request.
 * @param arg (const char *)      the argument to unescape.
 *
 * @return (char *) the unescaped string.
 */
static char* get_urldecoded_argument(struct mg_http_message *hm, const char *arg)
{
    if (hm == NULL || arg == NULL)
    {
        return NULL;
    }

    /* Magic number here ... sorry */
    char temp[1024] = { 0 };
    if (mg_http_get_var(&hm->query, arg, temp, sizeof(temp)) <= 0)
    {
        return NULL;
    }

    CURL *curl = curl_easy_init();
    if (!curl)
    {
        return NULL;
    }

    int decoded_len = 0;
    char *decoded =
    curl_easy_unescape(curl, temp, sizeof(temp), &decoded_len);
    if (decoded == NULL)
    {
        return NULL;
    }

    curl_easy_cleanup(curl);
    return decoded;
}

// ======================================================================
/**
 * @brief Helper function that contain common code for get and set calls (@see ckvs_local.c)
 *
 * @param nc    (mg_connection *)    the current connection
 * @param ckvs  (struct CKVS *)      the database (.ckvs)
 * @param hm    (mg_http_message *)  contains the HTTP request
 * @param code  (int)                Used for differentiation (0 == GET, 1 == SET)
 */
static void handle_getset_call(struct mg_connection *nc, struct CKVS *ckvs, struct mg_http_message *hm, const int code)
{
    ARGUMENT_CHECKER(nc, ckvs, hm);

    /* ------------- Get escaped key ------------- */
    char *key = get_urldecoded_argument(hm, "key");
    if (key == NULL)
    {
        mg_error_msg(nc, ERR_INVALID_ARGUMENT);
        return;
    }

    /* ------------- Get auth key and convert it to sha ------------- */
    char auth_key[SHA256_PRINTED_STRLEN];
    if (mg_http_get_var(&hm->query, "auth_key", auth_key, sizeof(auth_key)) <= 0)
    {
        curl_free(key);
        mg_error_msg(nc, ERR_INVALID_ARGUMENT);
        return;
    }

    ckvs_sha_t auth_key_sha;
    const int err_auth_key = SHA256_from_string(auth_key, &auth_key_sha);
    if (err_auth_key < 0)
    {
        curl_free(key);
        mg_error_msg(nc, ERR_IO);
        return;
    }

    ckvs_entry_t *entry = NULL;
    const int err_find_entry = ckvs_find_entry(ckvs, key, &auth_key_sha, &entry);

    curl_free(key);
    if (err_find_entry != ERR_NONE)
    {
        mg_error_msg(nc, err_find_entry);
        return;
    }

    if (code == 0)
    {
        /* --------------------------- GET --------------------------- */
        if (entry->value_len == 0)
        {
            mg_error_msg(nc, ERR_NO_VALUE);
            return;
        }

        char c2[SHA256_PRINTED_STRLEN];
        SHA256_to_string(&entry->c2, c2);

        /* ------------- Read and encode secret ------------- */
        unsigned char * data = calloc(entry->value_len, sizeof(unsigned char));
        if (data == NULL)
        {
            mg_error_msg(nc, ERR_OUT_OF_MEMORY);
            return;
        }

        if (fseek(ckvs->file, (long int) entry->value_off, SEEK_SET) != 0)
        {
            mg_error_msg(nc, ERR_IO);
            free(data);
            return;
        }

        if (fread(data, entry->value_len, 1, ckvs->file) != 1)
        {
            mg_error_msg(nc, ERR_IO);
            free(data);
            return;
        }

        char * value = calloc(1 + 2 * entry->value_len, sizeof(char));
        if (value == NULL)
        {
            free(data);
            mg_error_msg(nc, ERR_OUT_OF_MEMORY);
            return;
        }

        hex_encode(data, entry->value_len, value);
        free(data);

        /* ----------------------------------- Create response ----------------------------------- */
        json_object *response  = json_object_new_object();

        json_object *json_c2   = json_object_new_string(c2);
        json_object *json_data = json_object_new_string(value);

        free(value);

        if (json_object_object_add(response, "c2", json_c2) < 0 ||
                json_object_object_add(response, "data", json_data) < 0)
        {
            mg_error_msg(nc, ERR_IO);
            return;
        }


        /* ----------------------------------- Send response ----------------------------------- */
        mg_http_reply(nc, HTTP_OK_CODE, "Content-Type: application/json\r\n",
                      "%s\n", json_object_to_json_string(response));

        json_object_put(response);
    }
    else
    {
        /* --------------------------- SET --------------------------- */
        char filename[30];
        if (mg_http_get_var(&hm->query, "name", filename, sizeof(filename)) <= 0)
        {
            mg_error_msg(nc, ERR_INVALID_ARGUMENT);
            return;
        }

        /* --------------------------- Construct path to file --------------------------- */
        const size_t path_size = strlen(filename) + strlen("/tmp/") + 1;
        char path[path_size];
        if (snprintf(path, path_size, "/tmp/%s", filename) != (int) path_size - 1)
        {
            mg_error_msg(nc, ERR_IO);
            return;
        }

        /* --------------------------- Read JSON file --------------------------- */
        char *buffer = NULL;
        size_t size = 0;
        const int err_read = read_value_file_content(path, &buffer, &size);
        if (err_read != ERR_NONE)
        {
            mg_error_msg(nc, err_read);
            return;
        }

        /* --------------------------- Parse JSON file --------------------------- */
        json_object * json_from_con = json_tokener_parse(buffer);
        free(buffer);

        if (json_from_con == NULL)
        {
            mg_error_msg(nc, ERR_IO);
            return;
        }

        json_object *c2, *data;
        if (!json_object_object_get_ex(json_from_con, "c2", &c2) ||
                !json_object_object_get_ex(json_from_con, "data", &data))
        {
            json_object_put(json_from_con);
            mg_error_msg(nc, ERR_IO);
            return;
        }

        const char * hex_c2   = json_object_get_string(c2);
        const char * hex_data = json_object_get_string(data);

        ckvs_sha_t decoded_c2;
        SHA256_from_string(hex_c2, &decoded_c2);
        uint8_t * decoded_data = calloc( 1 + (strlen(hex_data)) / 2, sizeof(uint8_t));
        if (decoded_data == NULL)
        {
            mg_error_msg(nc, ERR_OUT_OF_MEMORY);
            return;
        }

        /* --------------------------- Update the database --------------------------- */
        const size_t bytes_numbers = (size_t) hex_decode(hex_data, decoded_data);
        const int err_write = ckvs_write_encrypted_value(ckvs, entry, decoded_data, bytes_numbers);
        free(decoded_data);
        if (err_write != ERR_NONE)
        {
            mg_error_msg(nc, err_write);
            return;
        }

        memcpy(entry->c2.sha, decoded_c2.sha, SHA256_DIGEST_LENGTH);
        const int err_code = ckvs_write_entry_to_disk(ckvs, (const uint32_t) (entry - ckvs->entries));
        if (err_code != ERR_NONE)
        {
            mg_error_msg(nc, err_code);
            return;
        }

        json_object_put(json_from_con);
        mg_http_reply(nc, HTTP_OK_CODE, "", "");
    }
}

// ======================================================================
/**
 * @brief Handle a stats call requested by the URI
 *
 * @param nc   (mg_connection *)    the current and open connection
 * @param ckvs (struct CKVS *)      the CKVS database
 * @param hm   (mg_http_message *)  the HTTP request
 */
static void handle_stats_call(struct mg_connection *nc, struct CKVS *ckvs, _unused struct mg_http_message *hm)
{
    ARGUMENT_CHECKER(nc, ckvs, hm);

    json_object *response = json_object_new_object();

    /* ------------------------------------ Create response ------------------------------------ */
    json_object *header_string      = json_object_new_string(ckvs->header.header_string);
    json_object *header_version     = json_object_new_int((int32_t) ckvs->header.version);
    json_object *header_table_size  = json_object_new_int((int32_t) ckvs->header.table_size);
    json_object *header_threshold   = json_object_new_int((int32_t) ckvs->header.threshold_entries);
    json_object *header_num_entries = json_object_new_int((int32_t) ckvs->header.num_entries);

    json_object *keys = json_object_new_array();
    for (size_t i = 0; i < ckvs->header.table_size; ++i)
    {
        if ((ckvs->entries + i)->key[0])
        {
            char null_terminated_key[CKVS_MAXKEYLEN + 1];
            strncpy(null_terminated_key, (ckvs->entries+i)->key, CKVS_MAXKEYLEN);
            null_terminated_key[CKVS_MAXKEYLEN] = '\0';

            json_object *key = json_object_new_string(null_terminated_key);
            json_object_array_add(keys, key);
        }
    }

    json_object_object_add(response, "header_string", header_string);
    json_object_object_add(response, "version", header_version);
    json_object_object_add(response, "table_size", header_table_size);
    json_object_object_add(response, "threshold_entries", header_threshold);
    json_object_object_add(response, "num_entries", header_num_entries);
    json_object_object_add(response, "keys", keys);

    /* ------------------------------------ Send response ------------------------------------ */
    mg_http_reply(nc,
                  HTTP_OK_CODE,
                  "Content-Type: application/json\r\n",
                  "%s\n", json_object_to_json_string(response));

    json_object_put(response);
}

// ======================================================================
/**
 * @brief Handle a get call requested by the URI
 *
 * @param nc   (mg_connection *)    the current and open connection
 * @param ckvs (struct CKVS *)      the CKVS database
 * @param hm   (mg_http_message *)  the HTTP request
 */
static void handle_get_call(struct mg_connection *nc, struct CKVS *ckvs, struct mg_http_message *hm)
{
    ARGUMENT_CHECKER(nc, ckvs, hm);
    handle_getset_call(nc, ckvs, hm, 0);
}

// ======================================================================
/**
 * @brief Handle a set call requested by the URI
 *
 * @param nc   (mg_connection *)    the current and open connection
 * @param ckvs (struct CKVS *)      the CKVS database
 * @param hm   (mg_http_message *)  the HTTP request
 */
static void handle_set_call(struct mg_connection *nc, struct CKVS *ckvs, struct mg_http_message *hm)
{
    ARGUMENT_CHECKER(nc, ckvs, hm);

    if (hm->body.len > 0)
    {
        mg_http_upload(nc, hm, "/tmp");
    }
    else if (hm->body.len == 0)
    {
        handle_getset_call(nc, ckvs, hm, 1);
    }
}

// ======================================================================
/**
 * @brief Handles server events (eg HTTP requests).
 * For more check https://cesanta.com/docs/#event-handler-function
 */
static void ckvs_event_handler(struct mg_connection *nc, int ev, void *ev_data, void *fn_data)
{
    struct mg_http_message *hm = (struct mg_http_message *) ev_data;
    struct CKVS *ckvs = (struct CKVS*) fn_data;

    if (ev != MG_EV_POLL)
    {
        debug_printf("Event received %d", ev);
    }

    switch (ev)
    {
    case MG_EV_POLL:
    case MG_EV_CLOSE:
    case MG_EV_READ:
    case MG_EV_WRITE:
    case MG_EV_HTTP_CHUNK:
        break;

    case MG_EV_ERROR:
        debug_printf("httpd mongoose error \n");
        break;
    case MG_EV_ACCEPT:
        // students: no need to implement SSL
        assert(ckvs->listening_addr);
        debug_printf("accepting connection at %s\n", ckvs->listening_addr);
        assert (mg_url_is_ssl(ckvs->listening_addr) == 0);
        break;

    case MG_EV_HTTP_MSG:
        if (mg_http_match_uri(hm, "/stats"))
        {
            handle_stats_call(nc, ckvs, hm);
        }

        if (mg_http_match_uri(hm, "/get"))
        {
            handle_get_call(nc, ckvs, hm);
        }

        if (mg_http_match_uri(hm, "/set"))
        {
            handle_set_call(nc, ckvs, hm);
        }

        mg_error_msg(nc, NOT_IMPLEMENTED);
        break;

    default:
        fprintf(stderr, "ckvs_event_handler %u\n", ev);
        assert(0);
    }
}

// ======================================================================
/**
 * @brief Mainloop that handles the different requests.
 *
 * @param filename (const char *) the name of the database (.ckvs)
 * @param optargc  (int)          the number of argument
 * @param optargv  (char**)       the array of arguments
 *
 * @return (int) error code.
 */
int ckvs_httpd_mainloop(const char *filename, int optargc, char **optargv)
{
    M_REQUIRE_NON_NULL_VARGS(filename, optargv);
    ARG_CHECK(1, optargc);

    /* Create server */
    signal(SIGINT, signal_handler); //adds interruption signals to the signal handler
    signal(SIGTERM, signal_handler);

    struct CKVS ckvs;
    int err = ckvs_open(filename, &ckvs);

    if (err != ERR_NONE)
    {
        return err;
    }

    ckvs.listening_addr = optargv[0];

    struct mg_mgr mgr;
    struct mg_connection *c;

    mg_mgr_init(&mgr);

    c = mg_http_listen(&mgr, ckvs.listening_addr, ckvs_event_handler, &ckvs);
    if (c == NULL)
    {
        debug_printf("Error starting server on address %s\n", ckvs.listening_addr);
        ckvs_close(&ckvs);
        return ERR_IO;
    }

    debug_printf("Starting CKVS server on %s for database %s\n", ckvs.listening_addr, filename);

    while (s_signo == 0)
    {
        mg_mgr_poll(&mgr, 1000); //infinite loop as long as no termination signal occurs
    }

    mg_mgr_free(&mgr);
    ckvs_close(&ckvs);
    debug_printf("Exiting HTTPD server\n");
    return ERR_NONE;
}

