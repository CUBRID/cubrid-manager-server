# plandump

Run plandump utility.

## Request JSON Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| token | token string encrypted. |
| dbname | database name |
| plandrop | y : drop plans |

## Request Sample

```
{
  "task": "plandump",
  "token": "cdfb4c5717170c5e2d40a680732333064610bcfeec1c0d870c43c1586a92dd1f7926f07dd201b6aa",
  "dbname": "demodb",
  "plandrop": "y"
}
```

## Response JSON Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| status | execution result, success or failed. |
| note | if failed, a brief description will be given here |
| log | the lines of the query plan cache of the database server |

## Response Sample

```
{
   "__EXEC_TIME" : "54 ms",
   "log" : [
      {
         "line" : [
            "",
            "XASL cache",
            "Stats: ",
            "Current entry count:        0",
            "Lookups:                    151",
            "Hits:                       110",
            "Miss:                       41",
            "Inserts:                    20",
            "Found at insert:            0",
            "Recompiles:                 0",
            "Failed recompiles:          0",
            "Deletes:                    20",
            "Fix:                        110",
            "Unfix:                      130",
            "Cache cleanups:             0",
            "Deletes at cleanup:\t    0",
            "",
            "XASL Cache Memory Info:",
            "  Memory Hard Limit:           125.00 MB",
            "  Current Memory (cache):      0.00 KB",
            "  Current Memory (clone):      0.00 KB",
            "  Total Memory:                0.00 KB",
            "  Max Plan Size:               8.33 MB",
            "  Usage Percent:               0.00%",
            "",
            "",
            "Entries:",
            "",
            "Filter predicate cache",
            "Stats: ",
            "Max size:                   1000",
            "Current entry count:        0",
            "Current clone count:        0",
            "Lookups:                    0",
            "Entry Hits:                 0",
            "Entry Miss:                 0",
            "Entry discards:             0",
            "Clone Hits:                 0",
            "Clone Miss:                 0",
            "Clone discards:             0",
            "Adds:                       0",
            "Clone adds:                 0",
            "Cleanups:                   0",
            "Cleaned entries:            0",
            "",
            "Entries:"
         ]
      }
   ],
   "note" : "none",
   "status" : "success",
   "task" : "plandump"
}
```
