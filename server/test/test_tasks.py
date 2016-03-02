#! /usr/bin/env python
import httplib,urllib
import json
import struct
import os, sys

def findport():
    cubrid = os.environ.get("CUBRID")
    conf = cubrid + "/conf/cm_httpd.conf"
    cwm_find = False;
    cf = open(conf, "r")
    for line in cf:
        idx = line.find("cwm.cubrid.org")
        if idx > 0:
            cwm_find = True
        if cwm_find:
            idx = line.find("server")
            if idx > 0:
                idx1 = line[idx:].find(":")
                idx2 = line[idx:].find(";")
                if idx1 < 0 or idx2 < 0:
                    continue
                return line[idx:][idx1+1:idx2]

#cmsip="192.168.0.1"
cmsip="localhost"
port=int(findport())
url="/cm_api"
testdir="task_test_case_json/"

token=""
CUBRID=""
CUBRID_DATABASES=""

def exec_task(ip, port, url, body):
    conn = httplib.HTTPConnection(ip, port)
    conn.request("POST", url, body)
    resp = conn.getresponse().read()
    conn.close()
    return resp

def load_task(taskfile):
    task=open(taskfile, "r")
    filebuf=task.read()
    filebuf=filebuf.replace("$CUBRID_DATABASES", str(CUBRID_DATABASES))
    filebuf=filebuf.replace("$CUBRID", str(CUBRID))
    data = json.loads(filebuf)
    return data

def do_one_job(taskfile, token):
    request = load_task(taskfile)
    if list == type(request):
        for req in request:
            req["token"] = token
            response = exec_task(cmsip, port, url, json.dumps(req))
            data=json.loads(response.decode())
            if data["status"] == "failure":
                print (data["task"] + " : " + '\033[31m{0}\033[0m'.format(data["note"]))
            else:
                print (data["task"] + " : " + '\033[32m{0}\033[0m'.format(data["status"]))
    else:
        req = request
        req["token"] = token
        response = exec_task(cmsip, port, url, json.dumps(req))
        data=json.loads(response.decode())
        if data["status"] == "failure":
            print (data["task"] + " : " + '\033[31m{0}\033[0m'.format(data["note"]))
        else:
            print (data["task"] + " : " + '\033[32m{0}\033[0m'.format(data["status"]))
    return data


def do_all_jobs(token):
    if len(sys.argv) == 1:
        tasks=open("task_list.txt", "r")
    else:
        tasks=open(sys.argv[1], "r")
    for data in tasks:
        data=data.rstrip()
        if data == "":
            continue
        if data[0] == '/':
            print '\n\033[33m{0}\033[0m'.format(data)
            continue
        do_one_job(testdir+data+".txt", token)

def init_env():
    response = do_one_job(testdir+"/login.txt", "")
    if response["status"] == "failure":
        request = load_task(testdir+"/login.txt")
        passwd = raw_input("Please input the passwd for %s: " %(request["id"]))
        request["password"] = passwd
        response = exec_task(cmsip, port, url, json.dumps(request))
        data=json.loads(response.decode())
        if data["status"] == "failure":
            print (data["task"] + " : " + '\033[31m{0}\033[0m'.format(data["note"]))
        else:
            print (data["task"] + " : " + '\033[32m{0}\033[0m'.format(data["status"]))
        response = data
    token = response["token"]
    response = do_one_job(testdir+"/getenv.txt", token)  
    bindir = response["CUBRID"]
    datadir = response["CUBRID_DATABASES"]
    return token, bindir, datadir

token, CUBRID, CUBRID_DATABASES = init_env()
#print (token, CUBRID, CUBRID_DATABASES)
#do_one_job("task_json/renamedb.txt", token)
do_all_jobs(token)

exec_task(cmsip, port, "/upload", "")
