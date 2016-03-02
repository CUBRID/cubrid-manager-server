
import httplib,urllib
import json
import struct

cmsip="localhost"
port=8003
url="/cci"

cciinfo = "{\"task\":\"sql\",\
\"bip\":\"localhost\",\
\"bport\":33000,\
\"dbname\":\"demodb\",\
\"class\":[\"event\"],\
\"classname\":\"code\",\
\"dbid\":\"dba\",\
\"dbpasswd\":\"\",\
\"charset\":\"utf-8\",\
\"stmt\":[\"select * FROM code;\"],\
\"oids\":[{\"oid\":\"@540|1|0\", \"attribute\":[\"s_name\"], \"value\":[\"Y\"]}],\
\"fetch_size\":100,\
\"error_continue\":1,\
\"export_path\":\"task_test_sql/export.sql\",\
\"import_path\":\"task_test_sql/import.sql\",\
\"export_type\":0,\
\"import_type\":0,\
\"autocommit\":0,\
\"time_out\":120}"

json_cci = json.loads(cciinfo)

def exec_task(ip, port, url, body):
    conn = httplib.HTTPConnection(ip, port)
    conn.request("POST", url, body)
    resp = conn.getresponse().read()
    conn.close()
    data=json.loads(resp.decode())
    print (str(data["status"]) + " : " + data["note"])
    print (resp.decode())
    return data

def do_task(task):
    json_cci["task"] = task
    response = exec_task(cmsip, port, url, str(json.dumps(json_cci)))
    return response

do_task("unknowntask")
do_task("sql")

# import sql
do_task("importdb")
# export sql
do_task("exportdb")

json_cci["class"] = ["code"]
# export csv
json_cci["export_type"] = 1
json_cci["export_path"] = "task_test_sql/db.csv"
do_task("exportdb")
#import csv
json_cci["import_type"] = 1
json_cci["import_path"] = "task_test_sql/db.csv"
do_task("importdb")

do_task("oid_get")
do_task("oid_put")
json_cci["oids"] = ["@540|1|0"]
do_task("oid_del")

