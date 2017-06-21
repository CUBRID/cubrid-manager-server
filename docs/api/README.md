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
| [startbroker](startbroker.md) | socket, http | DBC, DBO, BRK |
| [stopbroker](stopbroker.md) | socket, http | DBC, DBO, BRK |
| [getaddbrokerinfo](getaddbrokerinfo.md) | socket, http | ALL_AUTHORITY |
| [deletebroker](deletebroker.md) | socket, http | DBC, DBO, BRK |
| [getbrokerstatus](getbrokerstatus.md) | socket, http | ALL_AUTHORITY |
| [broker_setparam](broker_setparam.md) | socket, http | DBC, DBO, BRK |
| [broker_start](broker_start.md) | socket, http | DBC, DBO, BRK |
| [broker_stop](broker_stop.md) | socket, http | DBC, DBO, BRK |
| [broker_restart](broker_restart.md) | socket, http | DBC, DBO, BRK |
| [getbrokerdiagdata](getbrokerdiagdata.md) | socket, http | ALL_AUTHORITY |
| [getbrokersinfo](getbrokersinfo.md) | socket, http | ALL_AUTHORITY |

### DB

| **Interface Name** | **Connection Type** | **Permission** | **Support Version** |
| --- | --- | --- | --- |
| [createdb](createdb.md) | socket, http | DBC |
| [deletedb](deletedb.md) | socket, http | DBC |
| [renamedb](renamedb.md) | socket, http | DBC |
| [startdb](startdb.md) | socket, http | DBC, DBO |
| [stopdb](stopdb.md) | socket, http | DBC, DBO |
| [dbspaceinfo](dbspaceinfo.md) | socket, http | ALL_AUTHORITY |
| [copydb](copydb.md) | socket, http | DBC |
| [optimizedb](optimizedb.md) | socket, http | DBC, DBO |
| [checkdb](checkdb.md) | socket, http | DBC, DBO |
| [compactdb](compactdb.md) | socket, http | DBC, DBO |
| [backupdb](backupdb.md) | socket, http | DBC, DBO |
| [unloaddb](unloaddb.md) | socket, http | DBC, DBO |
| [loaddb](loaddb.md) | socket, http | DBC, DBO |
| [lockdb](lockdb.md) | socket, http | ALL_AUTHORITY |
| [restoredb](restoredb.md) | socket, http | DBC, DBO |
| [getdbsize](getdbsize.md) | socket, http | ALL_AUTHORITY |
| [startinfo](startinfo.md) | socket, http | ALL_AUTHORITY |
| [getbackuplist](getbackuplist.md) | socket, http | ALL_AUTHORITY |
| [getdbprocstat](getdbprocstat.md) | socket, http | ALL_AUTHORITY |
| [changemode](changemode.md) | socket, http | DBC, DBO |
| [getdbmode](getdbmode.md) | socket, http | ALL_AUTHORITY |
| [dbspace](dbspace.md) | socket, http | ALL_AUTHORITY |
| [addvoldb](addvoldb.md) | socket, http | DBC, DBO |
| [class](class.md) | socket, http | ALL_AUTHORITY |
| [classinfo](classinfo.md) | socket, http | ALL_AUTHORITY |
| [updateattribute](updateattribute.md) | socket, http | ALL_AUTHORITY |

### DB User

| **Interface Name** | **Connection Type** | **Permission** | **Support Version** |
| --- | --- | --- | --- |
| [userinfo](userinfo.md) | socket, http | ALL_AUTHORITY |
| [createuser](createuser.md) | socket, http | DBO |
| [deleteuser](deleteuser.md) | socket, http | DBO |
| [updateuser](updateuser.md) | socket, http | DBO |
| [userverify](userverify.md) | socket, http | ALL_AUTHORITY |

### CM User

| **Interface Name**| **Connection Type** | **Permission** | **Support Version** |
| --- | --- | --- | --- |
| [getdbmtuserinfo](getdbmtuserinfo.md) | socket, http | ALL_AUTHORITY |
| [deletedbmtuser](deletedbmtuser.md) | socket, http | DBC |
| [updatedbmtuser](updatedbmtuser.md) | socket, http | DBC |
| [setdbmtpasswd](setdbmtpasswd.md) | socket, http | DBC and Owner |
| [adddbmtuser](adddbmtuser.md) | socket, http | DBC |
| [getaddvolstatus](getaddvolstatus.md) | socket, http | ALL_AUTHORITY |
| [dbmtuserlogin](dbmtuserlogin.md) | socket, http | ALL_AUTHORITY |
| [adddbmtuser_new](adddbmtuser_new.md) | http | DBC |
| [updatedbmtuser_new](updatedbmtuser_new.md) | http | DBC, DBO |
| [getdbmtuserinfo_new](getdbmtuserinfo_new.md) | http | DBC, DBO |

### Transaction

| **Interface Name** | **Connection Type** | **Permission** | **Support Version** |
| --- | --- | --- | --- |
| [gettransactioninfo](gettransactioninfo.md) | socket, http | ALL_AUTHORITY |
| [killtransaction](killtransaction.md) | socket, http | DBC, DBO, MON |

### Trigger

| **Interface Name** | **Connection Type** | **Permission** | **Support Version** |
| --- | --- | --- | --- |
| [addtrigger](addtrigger.md) | socket, http | DBC, DBO |
| [altertrigger](altertrigger.md) | socket, http | DBC, DBO |
| [droptrigger](droptrigger.md) | socket, http | DBC, DBO |
| [gettriggerinfo](gettriggerinfo.md) | socket, http | ALL_AUTHORITY |

### Automation

| **Interface Name** | **Connection Type** | **Permission** | **Support Version** |
| --- | --- | --- | --- |
| [backupdbinfo](backupdbinfo.md) | socket, http | ALL_AUTHORITY |
| [getbackupinfo](getbackupinfo.md) | socket, http | ALL_AUTHORITY |
| [addbackupinfo](addbackupinfo.md) | socket, http | DBC, DBO, JOB |
| [deletebackupinfo](deletebackupinfo.md) | socket, http | DBC, DBO, JOB |
| [setbackupinfo](setbackupinfo.md) | socket, http | DBC, DBO, JOB |
| [getautoaddvol](getautoaddvol.md) | socket, http | ALL_AUTHORITY |
| [setautoaddvol](setautoaddvol.md) | socket, http | DBC, DBO |
| [getautoexecquery](getautoexecquery.md) | socket, http | ALL_AUTHORITY |
| [setautoexecquery](setautoexecquery.md) | socket, http | DBC, DBO, JOB |
| [setautostart](setautostart.md) | http | DBC, DBO, JOB |
| [getautostart](getautostart.md) | http | ALL_AUTHORITY |
| [getautojobconf](getautojobconf.md) | http | ALL_AUTHORITY |
| [setautojobconf](setautojobconf.md) | http | DBC, DBO, JOB |
| [execautostart](execautostart.md) | http | ALL_AUTHORITY |

### HA

| **Interface Name** | **Connection Type** | **Permission** | **Support Version** |
| --- | --- | --- | --- |
| [heartbeatlist](heartbeatlist.md) | socket, http | ALL_AUTHORITY |
| [rolechange](rolechange.md) | socket, http | DBC, DBO |
| [ha_reload](ha_reload.md) | socket, http | DBC, DBO |
| [ha_status](ha_status.md) | socket, http | ALL_AUTHORITY |
| [ha_start](ha_start.md) | socket, http | DBC, DBO |
| [ha_stop](ha_stop.md) | socket, http | DBC, DBO |
| [gethaapplyinfo](gethaapplyinfo.md) | http | DBC, DBO |

### Monitoring

| **Interface Name** | **Connection Type** | **Permission** | **Support Version** |
| --- | --- | --- | --- |
| [get_mon_interval](get_mon_interval.md) | http | MON |
| [set_mon_interval](set_mon_interval.md) | http | ADMIN |
| [get_mon_statistic](get_mon_statistic.md) | http | MON |
| [monitorprocess](monitorprocess.md) | socket, http | ALL_AUTHORITY |

### Log

| **Interface Name** | **Connection Type** | **Permission** | **Support Version** |
| --- | --- | --- | --- |
| [getloginfo](getloginfo.md) | socket, http | ALL_AUTHORITY |
| [viewlog/viewlog2](viewlogviewlog2.md) | socket, http | ALL_AUTHORITY |
| [loadaccesslog](loadaccesslog.md) | socket, http | ALL_AUTHORITY |
| [deleteaccesslog](deleteaccesslog.md) | socket, http | DBC, DBO |
| [deleteerrorlog](deleteerrorlog.md) | socket, http | DBC, DBO |
| [getautobackupdberrlog](getautobackupdberrlog.md) | socket, http | ALL_AUTHORITY |
| [getautoexecqueryerrlog](getautoexecqueryerrlog.md) | socket, http | ALL_AUTHORITY |
| [getautoaddvollog](getautoaddvollog.md) | socket, http | ALL_AUTHORITY |
| [getadminloginfo](getadminloginfo.md) | socket, http | ALL_AUTHORITY |
| [getlogfileinfo](getlogfileinfo.md) | socket, http | ALL_AUTHORITY |
| [analyzecaslog](analyzecaslog.md) | socket, http | ALL_AUTHORITY |
| [getcaslogtopresult](getcaslogtopresult.md) | socket, http | ALL_AUTHORITY |

### Others

| **Interface Name** | **Connection Type** | **Permission** | **Support Version** |
| --- | --- | --- | --- |
| [setsysparam](setsysparam.md) | socket, http | DBC, DBO |
| [getallsysparam](getallsysparam.md) | socket, http | ALL_AUTHORITY |
| [plandump](plandump.md) | socket, http | ALL_AUTHORITY |
| [paramdump](paramdump.md) | socket, http | ALL_AUTHORITY |
| [statdump](statdump.md) | socket, http | ALL_AUTHORITY |
| [unloaddbinfo](unloaddbinfo.md) | socket, http | ALL_AUTHORITY |
| [backupvolinfo](backupvolinfo.md) | socket, http | ALL_AUTHORITY |
| [getdiagdata](getdiagdata.md) | socket, http | ALL_AUTHORITY |
| [getstandbyserverstat](getstandbyserverstat.md) | socket, http | ALL_AUTHORITY |
| [login](login.md) | socket, http | ALL_AUTHORITY |
| [logout](logout.md) | socket, http | ALL_AUTHORITY |
| [getcmsenv](getcmsenv.md) | socket, http | ALL_AUTHORITY |
| [shard_start](shard_start.md) | socket, http | DBC, DBO, BRK |
| [shard_stop](shard_stop.md) | socket, http | DBC, DBO, BRK |
