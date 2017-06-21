# setsysparam

Update configuration files.

## Request Json Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| token | token string encrypted. |
| confname | |
| confdata | contents of a configuration file |

## Request Sample

```
{
  "task": "setsysparam",
  "token": "cdfb4c5717170c5e9c6856b4d1c61ee8132bcc7d82bd609066ed9ece2554c47f7926f07dd201b6aa",
  "confname": "cubridconf",
  "confdata": [
    "#",
    "# Copyright (C) 2009 Search Solution Corporation. All rights reserved by Search Solution.",
    "#",
    "#   This program is free software; you can redistribute it and/or modify",
    "#   it under the terms of the GNU General Public License as published by",
    "#   the Free Software Foundation; version 2 of the License.",
    "#",
    "#  This program is distributed in the hope that it will be useful,",
    "#  but WITHOUT ANY WARRANTY; without even the implied warranty of",
    "#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the",
    "#  GNU General Public License for more details.",
    "#",
    "#  You should have received a copy of the GNU General Public License",
    "#  along with this program; if not, write to the Free Software",
    "#  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA",
    "",
    "#",
    "# $Id$",
    "#",
    "# cubrid.conf",
    "#",
    "# For complete information on parameters, see the CUBRID",
    "# Database Administration Guide chapter on System Parameters",
    "",
    "# Service section - a section for 'cubrid service' command",
    "[service]",
    "",
    "# The list of processes to be started automatically by 'cubrid service start' command",
    "# Any combinations are available with server, broker and manager.",
    "service=server,broker,manager",
    "",
    "# The list of database servers in all by 'cubrid service start' command.",
    "# This property is effective only when the above 'service' property contains 'server' keyword.",
    "server=demodb",
    "",
    "# Common section - properties for all databases",
    "# This section will be applied before other database specific sections.",
    "[common]",
    "",
    "# Size of data buffer are using K, M, G, T unit",
    "data_buffer_size=512M",
    "",
    "# Size of log buffer are using K, M, G, T unit",
    "log_buffer_size=4M",
    "",
    "# Size of sort buffer are using K, M, G, T unit",
    "# The sort buffer should be allocated per thread.",
    "# So, the max size of the sort buffer is sort_buffer_size * max_clients.",
    "sort_buffer_size=2M",
    "",
    "# The maximum number of concurrent client connections the server will accept.",
    "# This value also means the total # of concurrent transactions.",
    "max_clients=100",
    "",
    "# TCP port id for the CUBRID programs (used by all clients).",
    "cubrid_port_id=1523"
  ]
}
```

## Response Json Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| status | execution result, success or failed. |
| note | if failed, a brief description will be given here |


## Response Sample

```
{
   "__EXEC_TIME" : "72 ms",
   "note" : "none",
   "status" : "success",
   "task" : "setsysparam"
}
```
