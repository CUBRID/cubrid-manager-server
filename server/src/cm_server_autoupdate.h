#ifndef _CM_SERVER_AUTOUPDATE_H_
#define _CM_SERVER_AUTOUPDATE_H_

#ifdef WINDOWS

#define DEFAULT_UPDATE_HOST_NAME "jira.cubrid.org"
#define DEFAULT_UPDATE_REMOTE_PATH "/secure/attachment/14895/"
#define DOWNLOAD_BUFFER 16384
#define SHELL_NAME "auto_update.bat"

#else

#define DEFAULT_PATCH_URL "http://jira.cubrid.org/secure/attachment/14806/patch_9.1.0001.zip"
#define SHELL_NAME "auto_update.sh"

#endif

#define MAX_LINE 1024

int generate_update_script (char *patch_name, char *url, char *path,
			    char *_dbmt_error);
int unzip (const char *zip_file, const char *unzip_dir);

#endif
