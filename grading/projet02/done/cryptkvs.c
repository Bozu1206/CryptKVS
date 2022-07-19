#include <stdio.h>
#include "error.h"
#include "ckvs_local.h"
#include "ckvs_utils.h"
#include "ckvs_client.h"

//=======================================================================================
/**
 * @brief Define the minimum command size counting the name of the exec, the database filename
 *        and the name of the command.
 */
#define MIN_CMD_SIZE    3

//=======================================================================================
/**
 * @brief Some color to improve user experience.
 */
#define YELLOW       "\x1B[33m"
#define RESET        "\x1B[0m"

//=======================================================================================
/**
 * @brief Max number of command supported by the application.
 */
#define NUMBER_OF_COMMAND 4

//=======================================================================================
/**
 * @brief Format used to display available commands.
 */
#define PRINT_FORMAT  "cryptkvs [<database>|<url>] %s %s\n"

//=======================================================================================
/**
 * @brief Prefix used to differentiate local commands from client commands
 */
#define sURL_PREFIX  "https://"
#define  URL_PREFIX  "http://"

//=======================================================================================
int ckvs_do_one_cmd(int argc, char *argv[]);
static void print_error(const char *execname, int err);
static void print_cmds(void);
static void usage(const char *execname, int err);

//=======================================================================================
/**
 * @brief Structure and convenience typedef to map a command name to a function.
 */
typedef int (*ckvs_command)(const char*, int, char**);

struct ckvs_command_mapping
{
    const char* name;
    const char* desc;
    const ckvs_command cmd;
};

typedef struct ckvs_command_mapping ckvs_command_mapping_t;

//=======================================================================================
/**
 * @brief Short table that maintains mapping between name command and functions.
 */
static const ckvs_command_mapping_t command[] =
{
    {.name = "stats", .desc = "", .cmd = ckvs_local_stats},
    {.name = "get"  , .desc = "<key> <password>", .cmd = ckvs_local_get},
    {.name = "set"  , .desc = "<key> <password> <filename>", .cmd = ckvs_local_set},
    {.name = "new"  , .desc = "<key> <password>", .cmd = ckvs_local_new},
    {.name = "stats", .desc = "", .cmd = ckvs_client_stats},
    {.name = "get"  , .desc = "<key> <password>", .cmd = ckvs_client_get}
};

//=======================================================================================
/**
 * @brief Helper function for printing commands.
 */
static void print_cmds(void)
{
    pps_printf(YELLOW "Available Commands : \n" RESET);
    for (size_t i = 0; i < NUMBER_OF_COMMAND; ++i)
    {
        pps_printf(PRINT_FORMAT, command[i].name, command[i].desc);
    }
}

//=======================================================================================
/**
 * @brief Helper function for error printing.
 *
 * @param execname  the name of the executable.
 * @param err       the code of the error.
 */
static void print_error(const char *execname, int err)
{
    M_REQUIRE_NON_NULL_VOID_FUNCTION(execname);

    if (err >= 0 && err < ERR_NB_ERR)
    {
        pps_printf("%s exited with error: %s\n\n\n", execname, ERR_MESSAGES[err]);
    }
    else
    {
        pps_printf("%s exited with error: %d (out of range)\n\n\n", execname, err);
    }
}

//=======================================================================================
/**
 * @brief Handle error and command display.
 *
 * @param execname  the name of the executable.
 * @param err       the code of the error.
 */
static void usage(const char *execname, int err)
{
    M_REQUIRE_NON_NULL_VOID_FUNCTION(execname);

    if (err == ERR_INVALID_COMMAND)
    {
        print_cmds();
    }
    else
    {
        print_error(execname, err);
    }
}

//=======================================================================================
/**
 * @brief Runs the command requested by the user in the command line, or
 *        returns ERR_INVALID_COMMAND if the command is not found.
 *
 * @param argc (int)     the number of arguments in the command line
 * @param argv (char*[]) the arguments of the command line, as passed to main()
 */
int ckvs_do_one_cmd(int argc, char *argv[])
{
    if (argc < MIN_CMD_SIZE)
    {
        return ERR_INVALID_COMMAND;
    }

    size_t index = 0;
    const char* db_filename = argv[1];
    const char* cmd = argv[2];

    M_REQUIRE_NON_NULL_VARGS(db_filename, cmd);

    /* Check if the command is used for a remote access */
    if (strncmp(db_filename, URL_PREFIX, strlen(URL_PREFIX)) == 0 ||
        strncmp(db_filename, sURL_PREFIX, strlen(sURL_PREFIX)) == 0)
    {
        /* Skip local function in the command table */
        index += NUMBER_OF_COMMAND;
    }

    const size_t number_commands = sizeof(command) / sizeof(ckvs_command_mapping_t);
    for (; index < number_commands; ++index)
    {
        if (strcmp(command[index].name, cmd) == 0)
        {
            return command[index].cmd(db_filename, argc - MIN_CMD_SIZE, argv + MIN_CMD_SIZE);
        }
    }

    return ERR_INVALID_COMMAND;
}

//=======================================================================================
#ifndef FUZZ
/**
 * @brief main function, runs the requested command and prints the resulting error if any.
 */
int main(int argc, char *argv[])
{
    const int ret = ckvs_do_one_cmd(argc, argv);

    if (ret != ERR_NONE)
    {
        usage(argv[0], ret);
    }

    return ret;
}
#endif
