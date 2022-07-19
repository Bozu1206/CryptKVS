/**
 * @file ckvs_rpc.c
 * @brief RPC handling using libcurl
 * @author E. Bugnion
 *
 * Includes example from https://curl.se/libcurl/c/getinmemory.html
 */
#include <stdlib.h>
#include "ckvs_rpc.h"
#include "error.h"
#include "ckvs_utils.h"

//=======================================================================================
/**
 * ckvs_curl_WriteMemoryCallback -- lifted from https://curl.se/libcurl/c/getinmemory.html
 *
 * @brief Callback that gets called when CURL receives a message.
 *        It writes the payload inside ckvs_connection.resp_buf.
 *        Note that it is already setup in ckvs_rpc_init.
 *
 * @param contents (void*)   content received by CURL
 * @param size     (size_t)  size of an element of of content. Always 1
 * @param nmemb    (size_t)  number of elements in content
 * @param userp    (void*)   points to a ckvs_connection (set with the CURLOPT_WRITEDATA option)
 *
 * @return (size_t) the number of written bytes, or 0 if an error occured
 */
static size_t ckvs_curl_WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
    M_REQUIRE_NON_NULL_VARGS(contents, userp);

    size_t realsize = size * nmemb;
    struct ckvs_connection *conn = (struct ckvs_connection *)userp;

    char *ptr = realloc(conn->resp_buf, conn->resp_size + realsize + 1);
    if(!ptr)
    {
        /* out of memory! */
        debug_printf("not enough memory (realloc returned NULL)\n");
        return 0;
    }

    conn->resp_buf = ptr;
    memcpy(&(conn->resp_buf[conn->resp_size]), contents, realsize);
    conn->resp_size += realsize;
    conn->resp_buf[conn->resp_size] = 0;

    return realsize;
}

//=======================================================================================
/**
 * @see ckvs_rpc.h
 */
int ckvs_rpc_init(struct ckvs_connection *conn, const char *url)
{
    M_REQUIRE_NON_NULL(conn);
    M_REQUIRE_NON_NULL(url);
    bzero(conn, sizeof(*conn));

    conn->url  = url;
    conn->curl = curl_easy_init();
    if (conn->curl == NULL)
    {
        return ERR_OUT_OF_MEMORY;
    }
    curl_easy_setopt(conn->curl, CURLOPT_WRITEFUNCTION, ckvs_curl_WriteMemoryCallback);
    curl_easy_setopt(conn->curl, CURLOPT_WRITEDATA, (void *)conn);

    return ERR_NONE;
}

//=======================================================================================
/**
 * @see ckvs_rpc.h
 */
void ckvs_rpc_close(struct ckvs_connection *conn)
{
    if (conn == NULL)
        return;

    if (conn->curl)
    {
        curl_easy_cleanup(conn->curl);
    }
    if (conn->resp_buf)
    {
        free(conn->resp_buf);
    }
    bzero(conn, sizeof(*conn));
}

//=======================================================================================
/**
 * @see ckvs_rpc.h
 */
int ckvs_rpc(struct ckvs_connection *conn, const char *GET)
{
    M_REQUIRE_NON_NULL_VARGS(conn, GET);

    const size_t url_length = strlen(conn->url) + strlen(GET) + 1;
    char * url = calloc(url_length, sizeof(char));
    M_REQUIRE(url != NULL, ERR_OUT_OF_MEMORY, "");

    /* According to documentation (C11, chapter §7.24.3.2),
     * strncat always append a null terminator character */
    strncat(url, conn->url, strlen(conn->url));
    strncat(url, GET, strlen(GET));

    const int err_opt = curl_easy_setopt(conn->curl, CURLOPT_URL, url);
    if (err_opt != CURLE_OK)
    {
        free(url);
        return ERR_OUT_OF_MEMORY;
    }

    free(url);

    CURLcode ret = curl_easy_perform(conn->curl);
    M_REQUIRE(ret == CURLE_OK, ERR_TIMEOUT, "");
    return ERR_NONE;
}

//=======================================================================================
/**
 * @see ckvs_rpc.h
 */
int ckvs_post(struct ckvs_connection* conn, const char* GET, const char* POST)
{
    M_REQUIRE_NON_NULL_VARGS(conn, GET, POST);

    const size_t url_length = strlen(conn->url) + strlen(GET) + 1;
    char * url = calloc(url_length, sizeof(char));
    M_REQUIRE(url != NULL, ERR_OUT_OF_MEMORY, "");

    /* ----------------------- Building the URL ----------------------- */
    strncat(url, conn->url, strlen(conn->url));
    strncat(url, GET, strlen(GET));

    curl_easy_setopt(conn->curl, CURLOPT_URL, url);
    free(url);

    /* ----------------------- Adding new header ----------------------- */
    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");

    const int header_err = curl_easy_setopt(conn->curl, CURLOPT_HTTPHEADER, headers);
    if (header_err != ERR_NONE)
    {
        curl_slist_free_all(headers);
        return ERR_IO;
    }

    /* ----------------------- Adding post ----------------------- */
    curl_easy_setopt(conn->curl, CURLOPT_POSTFIELDSIZE, strlen(POST));
    curl_easy_setopt(conn->curl, CURLOPT_POSTFIELDS, POST);

    /* ----------------------- Sending data to the server ----------------------- */
    CURLcode ret = curl_easy_perform(conn->curl);
    if (ret != CURLE_OK)
    {
        curl_slist_free_all(headers);
        return ERR_TIMEOUT;
    }

    if (conn->resp_size > 0)
    {
        pps_printf("%s\n", conn->resp_buf);
        curl_slist_free_all(headers);
        return ERR_IO;
    }

    /* ----------------------- Sending empty string to the server ----------------------- */
    curl_easy_setopt(conn->curl, CURLOPT_POSTFIELDSIZE, 0L);
    curl_easy_setopt(conn->curl, CURLOPT_POSTFIELDS, "");

    CURLcode empty_ret = curl_easy_perform(conn->curl);
    if (empty_ret != CURLE_OK)
    {
        curl_slist_free_all(headers);
        return ERR_TIMEOUT;
    }

    if (conn->resp_size > 0)
    {
        curl_slist_free_all(headers);
        pps_printf("%s\n", conn->resp_buf);
        return ERR_IO;
    }

    curl_slist_free_all(headers);
    return ERR_NONE;
}

