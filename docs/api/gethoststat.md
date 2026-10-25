# gethoststat

Get host level statistics.

Permissions required to run this task: none (any logged-in user)

## Request JSON Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| token | token string encrypted. |


## Request Sample

```
{
 "task":"gethoststat",
 "token":"4504b930fc1be99bf5dfd31fc5799faaa3f117fb903f397de087cd3544165d857926f07dd201b6aa"
 }
```
## Response JSON Syntax

| **Key** | **Description** |
| --- | --- |
| note | if failed, a brief description will be given here |
| status | execution result, success or failed. |
| task | task name |
| cpu_idle | |
| cpu_iowait | |
| cpu_kernel | |
| cpu_user | |
| mem_phy_free | |
| mem_phy_total | |
| mem_swap_free | |
| mem_swap_total | |

## Response Sample

```
{
   "__EXEC_TIME" : "1 ms",
   "cpu_idle" : "220045292007",
   "cpu_iowait" : "5670144",
   "cpu_kernel" : "405547982",
   "cpu_user" : "2069376964",
   "mem_phy_free" : "177477308416",
   "mem_phy_total" : "202272628736",
   "mem_swap_free" : "17140805632",
   "mem_swap_total" : "17179865088",
   "note" : "none",
   "status" : "success",
   "task" : "gethoststat"
}
```