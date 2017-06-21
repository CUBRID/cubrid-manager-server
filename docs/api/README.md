# CUBRID Manager Server API Manual

## Overview

The CUBRID Manager Server (CMS) HTTP Interface is an interface that exists between the CUBRID manager server and the application client, through which a web-based application client can access the CUBRID manager server. The CUBRID manager server delivers the request received from an application client to the CUBRID, and transfers the execution result to the client.

## System Architecture

CMS is a manager tools for CUBRID including database configure, monitor, SQL query. As the component of the CUBRID Database Management System, CMS provides a web-based tool that allows users to remotely manage the database and the Broker.

![CMS Architecture](images/architecture.png?raw=true "CMS Architecture")
CMS Architecture

## Writing HTTP Application Program

CMS http interface is REST-like interface, client can POST JSON-format request to url `http://cms_ip:cms_port/cm_api`, and receive the execution result.

The basic steps used for writing programs are as follows. First client must log in CMS with DBMT user name and password. If client login success, CMS will return a token which will be used in following request. The steps are implemented in example codes.

Example in Python Request:

```
import http.client,urllib.parse  

body = "{\"task\":\"login\",\  
\"id\":\"admin\",\  
\"password\":\"admin\",\  
\"clientver\":\"8.4\"}"  

headers = {"Accept": "text/plain;charset=utf-8"}  
conn = http.client.HTTPConnection("localhost", 8003)  
conn.request("POST", "/cm_api", body, headers)  
r = conn.getresponse()  
print (r.read())
```

The client will receive response in json-format. If success, `status` is `success`, otherwise `failure` and `note` will give error reason. The data `token` will be used in following request.

```
{
    "note" : "none",
    "status" : "success",
    "task" : "authenticate",
    "token" : "ae873897a0a9a2af8ea817532a4d722b124c446cb75876b9924a258f6351977e7926f07dd201b6aa"
}
```

## Interface Permission

There are seven permissions. These permissions can indicate which authorities are needed to perform a task.

| **Permission Name** | **Permission Description** |
| --- | --- |
| DBC | Database Creation - Can only create a new database |
| DBO | Database Operation Authority - Can use database utilities and modify conf files. |
| BRK | Broker Authority - Can only modify brokers (include shard broker |
| MON | Monitoring - R/W Configuration |
| JOB | Automation Authority - Can only use automations |
| VAR | Show Variable Authority - Can only read cubrid.conf, cubrid_broker.conf, ... etc. |
| ADMIN | Indicate the authority of admin |
| ALL_AUTHORITY | This value is equal to "DBC | DBO | BRK | MON | JOB | VAR" |

## CMS Interfaces

CMs Interfaces are conposed by Json and is used for communication between CMS and Cubrid Manager.

### Broker

| **Interface Name** | **Connection Type** | **Permission** | **Support Version** |
| --- | --- | --- | --- |
| getbrokersinfo | socket, http | ALL_AUTHORITY |
| startbroker | socket, http | DBC, DBO, BRK |
| stopbroker | socket, http | DBC, DBO, BRK |
| getaddbrokerinfo | socket, http | ALL_AUTHORITY |
| deletebroker | socket, http | DBC, DBO, BRK |
| getbrokerstatus | socket, http | ALL_AUTHORITY |
| broker_setparam | socket, http | DBC, DBO, BRK |
| broker_start | socket, http | DBC, DBO, BRK |
| broker_stop | socket, http | DBC, DBO, BRK |
| broker_restart | socket, http | DBC, DBO, BRK |
| getbrokerdiagdata | socket, http | ALL_AUTHORITY |

### DB

| **Interface Name** | **Connection Type** | **Permission** | **Support Version** |
| --- | --- | --- | --- |
| createdb | socket, http | DBC |
| deletedb | socket, http | DBC |
| renamedb | socket, http | DBC |
| startdb | socket, http | DBC, DBO |
| stopdb | socket, http | DBC, DBO |
| dbspaceinfo | socket, http | ALL_AUTHORITY |
| copydb | socket, http | DBC |
| optimizedb | socket, http | DBC, DBO |
| checkdb | socket, http | DBC, DBO |
| compactdb | socket, http | DBC, DBO |
| backupdb | socket, http | DBC, DBO |
| unloaddb | socket, http | DBC, DBO |
| loaddb | socket, http | DBC, DBO |
| lockdb | socket, http | ALL_AUTHORITY |
| restoredb | socket, http | DBC, DBO |
| getdbsize | socket, http | ALL_AUTHORITY |
| startinfo | socket, http | ALL_AUTHORITY |
| getbackuplist | socket, http | ALL_AUTHORITY |
| getdbprocstat | socket, http | ALL_AUTHORITY |
| changemode | socket, http | DBC, DBO |
| getdbmode | socket, http | ALL_AUTHORITY |
| dbspace | socket, http | ALL_AUTHORITY |
| addvoldb | socket, http | DBC, DBO |
| class | socket, http | ALL_AUTHORITY |
| classinfo | socket, http | ALL_AUTHORITY |
| updateattribute | socket, http | ALL_AUTHORITY |

### DB User

| **Interface Name** | **Connection Type** | **Permission** | **Support Version** |
| --- | --- | --- | --- |
| userinfo | socket, http | ALL_AUTHORITY |
| createuser | socket, http | DBO |
| deleteuser | socket, http | DBO |
| updateuser | socket, http | DBO |
| userverify | socket, http | ALL_AUTHORITY |

### CM User

| **Interface Name**| **Connection Type** | **Permission** | **Support Version** |
| --- | --- | --- | --- |
| getdbmtuserinfo | socket, http | ALL_AUTHORITY |
| deletedbmtuser | socket, http | DBC |
| updatedbmtuser | socket, http | DBC |
| setdbmtpasswd | socket, http | DBC and Owner |
| adddbmtuser | socket, http | DBC |
| getaddvolstatus | socket, http | ALL_AUTHORITY |
| dbmtuserlogin | socket, http | ALL_AUTHORITY |
| adddbmtuser_new | http | DBC |
| updatedbmtuser_new | http | DBC, DBO |
| getdbmtuserinfo_new | http | DBC, DBO |

### Transaction

| **Interface Name** | **Connection Type** | **Permission** | **Support Version** |
| --- | --- | --- | --- |
| gettransactioninfo | socket, http | ALL_AUTHORITY |
| killtransaction | socket, http | DBC, DBO, MON |

### Trigger

| **Interface Name** | **Connection Type** | **Permission** | **Support Version** |
| --- | --- | --- | --- |
| addtrigger | socket, http | DBC, DBO |
| altertrigger | socket, http | DBC, DBO |
| droptrigger | socket, http | DBC, DBO |
| gettriggerinfo | socket, http | ALL_AUTHORITY |

### Automation

| **Interface Name** | **Connection Type** | **Permission** | **Support Version** |
| --- | --- | --- | --- |
| backupdbinfo | socket, http | ALL_AUTHORITY |
| getbackupinfo | socket, http | ALL_AUTHORITY |
| addbackupinfo | socket, http | DBC, DBO, JOB |
| deletebackupinfo | socket, http | DBC, DBO, JOB |
| setbackupinfo | socket, http | DBC, DBO, JOB |
| getautoaddvol | socket, http | ALL_AUTHORITY |
| setautoaddvol | socket, http | DBC, DBO |
| getautoexecquery | socket, http | ALL_AUTHORITY |
| setautoexecquery | socket, http | DBC, DBO, JOB |
| setautostart | http | DBC, DBO, JOB |
| getautostart | http | ALL_AUTHORITY |
| getautojobconf | http | ALL_AUTHORITY |
| setautojobconf | http | DBC, DBO, JOB |
| execautostart | http | ALL_AUTHORITY |

### HA

| **Interface Name** | **Connection Type** | **Permission** | **Support Version** |
| --- | --- | --- | --- |
| heartbeatlist | socket, http | ALL_AUTHORITY |
| rolechange | socket, http | DBC, DBO |
| ha_reload | socket, http | DBC, DBO |
| ha_status | socket, http | ALL_AUTHORITY |
| ha_start | socket, http | DBC, DBO |
| ha_stop | socket, http | DBC, DBO |
| gethaapplyinfo | http | DBC, DBO |

### Monitoring

| **Interface Name** | **Connection Type** | **Permission** | **Support Version** |
| --- | --- | --- | --- |
| get_mon_interval | http | MON |
| set_mon_interval | http | ADMIN |
| get_mon_statistic | http | MON |
| monitorprocess | socket, http | ALL_AUTHORITY |

### Log

| **Interface Name** | **Connection Type** | **Permission** | **Support Version** |
| --- | --- | --- | --- |
| getloginfo | socket, http | ALL_AUTHORITY |
| [viewlog/viewlog2](viewlogviewlog2.md) | socket, http | ALL_AUTHORITY |
| loadaccesslog | socket, http | ALL_AUTHORITY |
| deleteaccesslog | socket, http | DBC, DBO |
| deleteerrorlog | socket, http | DBC, DBO |
| getautobackupdberrlog | socket, http | ALL_AUTHORITY |
| getautoexecqueryerrlog | socket, http | ALL_AUTHORITY |
| getautoaddvollog | socket, http | ALL_AUTHORITY |
| getadminloginfo | socket, http | ALL_AUTHORITY |
| getlogfileinfo | socket, http | ALL_AUTHORITY |
| analyzecaslog | socket, http | ALL_AUTHORITY |
| getcaslogtopresult | socket, http | ALL_AUTHORITY |

### Others

| **Interface Name** | **Connection Type** | **Permission** | **Support Version** |
| --- | --- | --- | --- |
| setsysparam | socket, http | DBC, DBO |
| getallsysparam | socket, http | ALL_AUTHORITY |
| plandump | socket, http | ALL_AUTHORITY |
| paramdump | socket, http | ALL_AUTHORITY |
| statdump | socket, http | ALL_AUTHORITY |
| unloaddbinfo | socket, http | ALL_AUTHORITY |
| backupvolinfo | socket, http | ALL_AUTHORITY |
| getdiagdata | socket, http | ALL_AUTHORITY |
| getstandbyserverstat | socket, http | ALL_AUTHORITY |
| login | socket, http | ALL_AUTHORITY |
| logout | socket, http | ALL_AUTHORITY |
| getcmsenv | socket, http | ALL_AUTHORITY |
| shard_start | socket, http | DBC, DBO, BRK |
| shard_stop | socket, http | DBC, DBO, BRK |
