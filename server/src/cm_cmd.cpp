/*
 * Copyright (C) 2008 Search Solution Corporation. All rights reserved by Search Solution.
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *
 */


/*
 * cm_cmd.cpp -
 */

#include <stdio.h>

#if defined(WINDOWS)
#include <io.h>
#include <direct.h>
#include <process.h>
#else
#include <unistd.h>
#include <dirent.h>
#endif

#include "cm_config.h"
#include "cm_cmd_task.h"
#include "cm_cmd_util.h"

static void _print_help (void);

int
main (int argc, char *argv[])
{
    int retval = 0;

    if (argc < 2)
    {
        retval = 0;
        goto print_help_msg;
    }

    sys_config_init ();
    if (uReadEnvVariables (argv[0]) < 0)
        return -1;

    retval = run_task (argv[1], (argc - 1), (const char **) (&argv[1]));

    if (retval == E_CMD_NOT_EXIST)
    {
        retval = -1;
        goto print_help_msg;
    }

    return 0;

print_help_msg:
    _print_help ();
    return retval;
}

static void
_print_help (void)
{
    const char *title_pattern =
        "cmserver utility, version R%s\nusage: %s <utility-name> [args]\n";
    printf (title_pattern, CM_ADMIN_VERSION, CM_ADMIN_NAME);
    print_cmd ();

    return;
}
