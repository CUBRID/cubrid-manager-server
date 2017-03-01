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
 * cm_cmd_exec.h -
 */

#ifndef _CM_COMMAND_EXECUTE_H_
#define _CM_COMMAND_EXECUTE_H_

#include <time.h>

#include "cm_dep.h"

#if defined(WINDOWS)
#define DBMT_EXE_EXT        ".exe"
#else
#define DBMT_EXE_EXT        ""
#endif

#define cmd_servstat_result_free(RESULT)        cmd_result_free(RESULT)
#define cmd_csql_result_free(RESULT)            cmd_result_free(RESULT)

#define ERR_MSG_SIZE    1024

#if !defined (DO_NOT_USE_CUBRIDENV)
#define CUBRID_ERROR_LOG_DIR            "log/server"
#define CUBRID_BROKER_LOG_DIR           "log/broker"
#else
#define CUBRID_ERROR_LOG_DIR            CUBRID_LOGDIR "/server"
#define CUBRID_BROKER_LOG_DIR           CUBRID_LOGDIR"/broker"
#endif

#define CUBRID_DATABASE_TXT             "databases.txt"
#define CUBRID_CUBRID_CONF              "cubrid.conf"
#define CUBRID_DBMT_CONF                "cm.conf"
#define CUBRID_BROKER_CONF              "cubrid_broker.conf"
#define CUBRID_HA_CONF                  "cubrid_ha.conf"
#define CUBRID_UNLOAD_EXT_INDEX         "_indexes"
#define CUBRID_UNLOAD_EXT_TRIGGER       "_trigger"
#define CUBRID_UNLOAD_EXT_OBJ           "_objects"
#define CUBRID_UNLOAD_EXT_SCHEMA        "_schema"
#define CUBRID_SERVER_LOCK_EXT          "_lgat__lock"
#define CUBRID_ACT_LOG_EXT              "_lgat"
#define CUBRID_ARC_LOG_EXT              "_lgar"
#define CUBRID_BACKUP_INFO_EXT          "_bkvinf"
#define CUBRID_ARC_LOG_EXT_LEN          strlen(CUBRID_ARC_LOG_EXT)

#define CUBRID_CMD_NAME_LEN    128

#if !defined (DO_NOT_USE_CUBRIDENV)
#if defined(WINDOWS)
#define CUBRID_DIR_BIN          "bin\\"
#else
#define CUBRID_DIR_BIN          "bin/"
#endif
#endif

#include <vector>
#include <typeinfo>
#include "cm_autojob.h"

typedef enum
{
    CUBRID_MODE_CS = 0,
    CUBRID_MODE_SA = 1
} T_CUBRID_MODE;

typedef struct
{
    int volid;
    int total_page;
    int free_page;
    char purpose[16];
    char location[128];
    char vol_name[128];
    time_t date;
} T_SPACEDB_INFO;

typedef struct
{
    int page_size;
    int log_page_size;
    int num_vol;
    T_SPACEDB_INFO *vol_info;
    int num_tmp_vol;
    T_SPACEDB_INFO *tmp_vol_info;
    char err_msg[ERR_MSG_SIZE];
} T_SPACEDB_RESULT;

struct SpaceDbVolumeInfoOldFormat{
    int volid;
    int total_size;
    int free_size;
    int data_size;
    int index_size;
    char purpose[16];
    char location[128];
    char vol_name[128];
    time_t date;
};

struct SpaceDbVolumeInfoNewFormat{
    int volid;
    int used_size;
    int free_size;
    int total_size;
    char type[16];
    char purpose[32];
    char volume_name[128];
};

struct DatabaseSpaceDescription{
    char type[16];
    char purpose[32];
    int volume_count;
    int used_size;
    int free_size;
    int total_size;
};

struct FileSpaceDescription{
    char data_type[8];
    int file_count;
    int used_size;
    int file_table_size;
    int reserved_size;
    int total_size;
};

class GeneralSpacedbResult{
protected:
    int page_size;
    int log_page_size;
    char err_msg[ERR_MSG_SIZE];
public:
    GeneralSpacedbResult(){
	page_size = 0;
	log_page_size = 0;
	err_msg[0] = '\0';
    }
    GeneralSpacedbResult(int page_size, int log_page_size){
	this->page_size = page_size;
	this->log_page_size = log_page_size;
	err_msg[0] = '\0';
    }
    int get_page_size(){
	return page_size;
    }
    int get_log_page_size(){
	return log_page_size;
    }
    void set_page_size(int page_size){
	this->page_size = page_size;
    }
    void set_log_page_size(int log_page_size){
	this->log_page_size = log_page_size;
    }
    const char *get_err_msg(){
	return err_msg;
    }
    void set_err_msg(char *str){
	strncpy(err_msg, str, ERR_MSG_SIZE);
    }
    virtual void create_result(nvplist *) = 0;
    virtual int get_no_tpage() = 0;
    virtual int get_total_and_free_page(const char *, double &, double &) = 0;
    virtual time_t get_my_time(char *) = 0;
    virtual void auto_add_volume(autoaddvoldb_node *, int, char *) = 0;
    virtual void read_spacedb_output(FILE *) = 0;
    virtual ~GeneralSpacedbResult(){}
};

class SpaceDbResultNewFormat : public GeneralSpacedbResult{
public:
    SpaceDbResultNewFormat(){}
    void add_volume(char *);
    int get_no_tpage();
    int get_total_and_free_page(const char *type, double &free_page, double &total_page){
	for (int i = 0; i < volumes.size(); i++) {
	    if (strcmp(volumes[i].purpose, type) == 0) {
		total_page += volumes[i].total_size;
		free_page += volumes[i].free_size;
	    }
	}
    }
    time_t get_my_time(char *);
    void auto_add_volume(autoaddvoldb_node *, int, char *);
    void read_spacedb_output(FILE *);
    void create_result(nvplist *);

    DatabaseSpaceDescription databaseSpaceDescriptions[3];
    FileSpaceDescription fileSpaceDescriptions[4];
private:
    std::vector<SpaceDbVolumeInfoNewFormat> volumes;
};

class SpaceDbResultOldFormat : public GeneralSpacedbResult{
public:
    SpaceDbResultOldFormat(){}
    int get_volume_info(char *, SpaceDbVolumeInfoOldFormat&);
    int add_volume(char *str_buf){
	SpaceDbVolumeInfoOldFormat volume;
	int rc = get_volume_info(str_buf, volume);
	if(rc == TRUE) {
	    volumes.push_back(volume);
	}
	return rc;
    }

    int add_temporary_volume(char *str_buf){
	SpaceDbVolumeInfoOldFormat volume;
	int rc = get_volume_info(str_buf, volume);
	if(rc == TRUE) {
	    temporary_volumes.push_back(volume);
	}
	return rc;
    }

    void create_result(nvplist *);
    int get_total_and_free_page(const char *type, double &free_page, double &total_page){
	for (int i = 0; i < volumes.size(); i++) {
	    if (strcmp(volumes[i].purpose, type) == 0) {
		total_page += volumes[i].total_size;
		free_page += volumes[i].free_size;
	    }
	}
    }
    int get_no_tpage();
    time_t get_my_time(char *);
    void auto_add_volume(autoaddvoldb_node *, int, char *);
    void read_spacedb_output(FILE *);
private:
    std::vector<SpaceDbVolumeInfoOldFormat> volumes;
    std::vector<SpaceDbVolumeInfoOldFormat> temporary_volumes;
};

typedef T_CMD_RESULT T_CSQL_RESULT;

GeneralSpacedbResult *cmd_spacedb (const char *dbname, T_CUBRID_MODE mode);
T_CSQL_RESULT *cmd_csql (char *dbname, char *uid, char *passwd,
                         T_CUBRID_MODE mode, char *infile, char *command, char *error_continue);
int cmd_start_server (char *dbname, char *err_buf, int err_buf_size);
int cmd_stop_server (char *dbname, char *err_buf, int err_buf_size);
void cmd_start_master (void);
char *cubrid_cmd_name (char *buf);
void cmd_spacedb_result_free (T_SPACEDB_RESULT * res);
int read_error_file (const char *err_file, char *err_buf, int err_buf_size);
int read_error_file2 (char *err_file, char *err_buf, int err_buf_size, int *err_code);
int read_csql_error_file (char *err_file, char *err_buf, int err_buf_size);

#endif                /* _CM_COMMAND_EXECUTE_H_ */
