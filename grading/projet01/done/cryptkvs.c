/*
 * cryptkvs -- main ; argument parsing and dispatch ; etc.
 */
#include <stdio.h>
#include "error.h"
#include "ckvs_local.h"
#include "ckvs_utils.h"

//=======================================================================================
/**
 * @brief Max number of command supported by the application (+ 1, because of the first line).
 * @see @file cryptkvs.txt
 */
#define MAX_COMMAND 5

/**
 * @brief Useful definition the check whether a command has the correct number of arguments.
 */
#define ARG_CHECK(N, ARG)                                      \
    const int err = ((ARG) > (N) ? ERR_TOO_MANY_ARGUMENTS      \
                   : (ARG) < (N) ? ERR_NOT_ENOUGH_ARGUMENTS    \
                   : 0);                                       \
    M_REQUIRE(err == 0, err, "")

//=======================================================================================
/**
 * Helper function for printing commands.
 *
 * @Note  this function use the file "cryptkvs.txt", make sure this file is present in
 *        directory done/
 *
 *        @see @file cryptkvs.txt
 *
 * @brief This function use the file "cryptkvs.txt" to find the text to print.
 *        We find this more practical and easier to maintain.
 */
static void print_cmds(void)
{
    /* Declare here to avoid global variable */
    static const char * COMMAND[MAX_COMMAND] =
    {
        #include "cryptkvs.txt"
    };

    for (const char** p = COMMAND; *p; ++p)
    {
        pps_printf("%s", *p);
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
    if (argc < 3)
    {
        return ERR_INVALID_COMMAND;
    }

    const char* db_filename = argv[1];
    const char* cmd = argv[2];

    if (strcmp(cmd, "stats") == 0)
    {
        return ckvs_local_stats(db_filename);
    }

    const char* key = argv[3];
    const char* password = argv[4];

    if (strcmp(cmd, "get") == 0)
    {
        ARG_CHECK(5, argc);
        return ckvs_local_get(db_filename, key, password);
    }

    if (strcmp(cmd, "set") == 0)
    {
        ARG_CHECK(6, argc);
        const char* filename = argv[5];
        return ckvs_local_set(db_filename, key, password, filename);
    }

    if (strcmp(cmd, "new") == 0)
    {
        ARG_CHECK(5, argc);
        return ckvs_local_new(db_filename, key, password);
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
