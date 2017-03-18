/*
 * Copyright (C) 2013 Search Solution Corporation. All rights reserved by Search Solution.
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
*  cm_http_server.h
*/

#include <fcntl.h>

#ifdef WINDOWS
#ifndef S_ISDIR
# define S_ISDIR(m) (((m) & (_S_IFMT)) == (_S_IFDIR))
#endif
#include <winsock2.h>
#include <windows.h>
#include <io.h>
#include <direct.h>
#include <process.h>
#else
#include <sys/stat.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <dirent.h>
#endif

#include <openssl/ssl.h>
#include <openssl/err.h>

#ifdef _EVENT_HAVE_NETINET_IN_H
#include <netinet/in.h>
# ifdef _XOPEN_SOURCE_EXTENDED
#  include <arpa/inet.h>
# endif
#endif
#ifndef O_BINARY
#define O_BINARY 0x8000  //used for open  files that contains some unicodes
#endif


/**
 * @brief load_webfiles_cb
 * This callback gets invoked when we get any http request that doesn't match
 * any other callback.  Like any evhttp server callback, it has a simple job:
 * it must eventually call evhttp_send_error() or evhttp_send_reply().
 * It is a real http server,if want add SSL connection. must be called after:
 * create_sslconn_cb and init_SSL
 * @param req
 * http reuqest
 * See also: struct evhttp_request
 * @param arg
 * The path or the files that need to be called.
 * @return
 */
void load_webfiles_cb (struct evhttp_request *req, void *arg);

/**
 * @brief create_sslconn_cb
 * This callback is responsible for creating a new SSL connection
 * and wrapping it in an OpenSSL bufferevent.  This is the way
 * we implement an https server instead of a plain old http server.
 * @param base
 * See also: struct event_base and bufferevent_openssl_socket_new
 * @param arg
 * It must be struct SSL_CTX,
 * See also: SSL_CTX
 * @return bufferevent
 */
struct bufferevent *create_sslconn_cb (struct event_base *base, void *arg);

/**
 * @brief init_SSL
 * init the ssl methods,loading key and crt files,
 * return ctx that used to create ssl connections.
 * See also: create_sslconn_cb
 * @param certificate_chain
 * certificate chain file. It can be full path,also can be the name of file.
 * @param private_key
 * private key file. It can be full path,also can be the name of file.
 * @return SSL_CTX
 */
SSL_CTX *init_SSL (const char *certificate_chain,const char *private_key);

/**
 * @brief thread_setup_SSL
 * Setup the necessary resources to ensure that OpenSSL can safely
 * be used in multi-threaded environment.
 * @return
 */
void thread_setup_SSL (void);

/**
 * @brief thread_cleanup_SSL
 * Cleanup the allocated resources which is used for OpenSSL thread safety.
 * @return
 */
void thread_cleanup_SSL (void);
