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
*  cm_http_server.cpp -
*/

#include <event2/http.h>
#include <event2/buffer.h>
#include <event2/keyvalq_struct.h>
#include <event2/bufferevent_ssl.h>
#include <event2/http_struct.h>

#include "cm_http_server.h"
#include "cm_log.h"

using namespace std;

static void http_error_404 (struct evhttp_request *req, int fd);
static void server_setup_certs (SSL_CTX *ctx, const char *certificate_chain,const char *private_key);
static void web_error_404 (struct evhttp_request *req);
static void locking_callback (int mode, int type, const char *file, int line);

#if !defined(WINDOWS) && !defined(__BEOS__)
static void thread_id_callback (CRYPTO_THREADID *tid);
#endif

static char uri_root[512] = "/";
static char *userAgent   = NULL;
static MUTEX_T *lock_array = NULL;

/*
 * This struct is used to get type of the files to browser.
 * if git contains ico etc. web browser will loading them one by one.
 */
typedef const struct
{
  const char *extension;
  const char *content_type;
} table_entry;

table_entry content_type_table[] =
{
  { "txt", "text/plain" },
  { "c", "text/plain" },
  { "h", "text/plain" },
  { "properties", "text/plain" },
  { "html", "text/html" },
  { "htm", "text/htm" },
  { "css", "text/css" },
  { "gif", "image/gif" },
  { "jpg", "image/jpeg" },
  { "jpeg", "image/jpeg" },
  { "png", "image/png" },
  { "ico", "image/x-icon" },
  { "js", "application/x-javascript" },
  { NULL, NULL },
};

/**
 * @brief guess_content_type
 * This is a magic function, Try to guess a good content-type for 'path'
 * @param path
 * Full path
 * @return
 * Return the type of file that in content_type_table[],
 * Other return application/misc to browser.
 */
static const char *guess_content_type (const char *path)
{
  const char *last_period = NULL;
  const char *extension   = NULL;
  table_entry *ent        = NULL;

  last_period = strrchr (path, '.');

  if (!last_period || strchr (last_period, '/'))
    {
      return "application/misc"; /* no exension */
    }

  extension = last_period + 1;
  if (extension == NULL)
    {
      return "application/misc"; /* no exension */
    }

  for (ent = &content_type_table[0]; ent->extension; ++ent)
    {
      if (!evutil_ascii_strcasecmp (ent->extension, extension))
        {
          return ent->content_type;
        }
    }

  return "application/misc";
}

#ifdef WINDOWS
/**
 * @brief isDirectory
 * To check the path is file or path in windows OS.
 * @param path
 * Full path
 * @return
 * If file:0,
 * else: 1
 */
int isDirectory (char *path)
{
  DWORD fileAttributes = GetFileAttributes (path);

  if (fileAttributes != INVALID_FILE_ATTRIBUTES)
    {
      return (fileAttributes & FILE_ATTRIBUTE_DIRECTORY);
    }
  else
    {
      return 0;
    }
}
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
void load_webfiles_cb (struct evhttp_request *req, void *arg)
{
  struct evbuffer *evb       = NULL;
  const char *docroot        = (char *)arg;
  const char *uri            = NULL;
  struct evhttp_uri *decoded = NULL;
  const char *path           = NULL;
  const char *default_path   = "/index.html";
  char *decoded_path         = NULL;
  char *whole_path           = NULL;
  size_t len;
  int fd                     = -1;
  struct stat st;
  int disable_directrory_listing = 1;
  const char *get_query      = NULL;
  const char *type           = "application/misc";

#ifdef WINDOWS
  WIN32_FIND_DATA FileData;
  HANDLE handle;
#endif

  /* This is be debug print */
  struct evkeyvalq *headers   = NULL;
  struct evkeyval *header     = NULL;

  if (sco.iSupportWebManager == FALSE)
    {
      web_error_404 (req);
      LOG_WARN ("-- Web server: Not config support_web_manager");
      goto done;
    }

  headers = evhttp_request_get_input_headers (req);
  for (header = headers->tqh_first; header;
       header = header->next.tqe_next)
    {
      if (string (header->key).compare ("User-Agent") == 0)
        {
          userAgent = header->value;
        }
    }

  /* Decode the URI */
  uri     = evhttp_request_get_uri (req);
  decoded = evhttp_uri_parse (uri);
  if (!decoded)
    {
      evhttp_send_error (req, HTTP_BADREQUEST, 0);
      LOG_WARN ("-- %s -- %s -- Web server: bad request for [%s]", req->remote_host, userAgent, uri);
      return;
    }

  get_query = evhttp_uri_get_query (decoded);
  /* Basic path routing. */
  path = evhttp_uri_get_path (decoded);

  if (!path)
    {
      path = default_path;
    }
  if (strcmp (path, "/") == 0)
    {
      path = default_path;
    }
  /* We need to decode it, to see what path the user really wanted. */
  decoded_path = evhttp_uridecode (path, 0, NULL);

  if (decoded_path == NULL)
    {
      http_error_404 (req, fd);
      LOG_WARN ("-- %s -- %s -- Web server: bad request for [%s]", req->remote_host, userAgent, uri);
      goto done;
    }

  /* Don't allow any ".."s in the path, to avoid exposing stuff outside
   * of the docroot.  This test is both overzealous and underzealous:
   * it forbids aceptable paths like "/this/one..here", but it doesn't
   * do anything to prevent symlink following."
   */
  if (strstr (decoded_path, ".."))
    {
      http_error_404 (req, fd);
      goto done;
    }

  len = strlen (decoded_path) + strlen (docroot) + 2;

  if (! (whole_path = (char *)malloc (len)))
    {
      http_error_404 (req, fd);
      LOG_WARN ("-- %s -- %s -- Web server: bad request for [%s]", req->remote_host, userAgent, uri);
      goto done;
    }
  evutil_snprintf (whole_path, len, "%s%s", docroot, decoded_path);
  if (stat (whole_path, &st) < 0 )
    {
      http_error_404 (req, fd);
      LOG_WARN ("-- %s -- %s -- Web server: bad request for [%s]", req->remote_host, userAgent, uri);
      goto done;
    }

  /* This holds the content we're sending. */
  evb = evbuffer_new ();
#ifdef WINDOWS
  const char *name = "unknown";
  handle = FindFirstFile (whole_path, &FileData);
  if (handle == INVALID_HANDLE_VALUE)
    {
      goto done;
    }

  if (isDirectory (whole_path))
    {
      const char *trailing_slash = "";
      if (!strlen (path) || path[strlen (path)-1] != '/')
        {
          trailing_slash = "/";
        }

      evbuffer_add_printf (evb, "<html>\n <head>\n"
                           "  <title>%s</title>\n"
                           "  <base href='%s%s%s'>\n"
                           " </head>\n"
                           " <body>\n"
                           "  <h1>%s</h1>\n"
                           "  <ul>\n",
                           decoded_path, /* XXX html-escape this. */
                           uri_root, path, /* XXX html-escape this? */
                           trailing_slash,
                           decoded_path /* XXX html-escape this */);

      while (FindNextFile (handle, &FileData))
        {
          name = FileData.cFileName;
          evbuffer_add_printf (evb,
                               "    <li><a href=\"%s\">%s</a>\n",
                               name, name);/* XXX escape this */
        }
      FindClose (handle);
      evbuffer_add_printf (evb, "</ul></body></html>\n");
      evhttp_add_header (evhttp_request_get_output_headers (req),
                         "Content-Type", "text/html");
    }
#else
  // directory listing security
  if (S_ISDIR (st.st_mode) && disable_directrory_listing)
    {
      http_error_404 (req, fd);
      LOG_WARN ("-- %s -- %s -- Web server: bad request for [%s]", req->remote_host, userAgent, uri);
      goto done;
    }

  if (S_ISDIR (st.st_mode))
    {
      /* If it's a directory, read the comments and make a little
       * index page
       */
      DIR *d;
      struct dirent *ent;
      const char *trailing_slash = "";
      if (!strlen (path) || path[strlen (path)-1] != '/')
        {
          trailing_slash = "/";
        }

      if (! (d = opendir (whole_path)))
        {
          http_error_404 (req, fd);
          LOG_WARN ("-- %s -- %s -- Web server: bad request for [%s]", req->remote_host, userAgent, uri);
          goto done;
        }

      evbuffer_add_printf (evb, "<html>\n <head>\n"
                           "  <title>%s</title>\n"
                           "  <base href='%s%s%s'>\n"
                           " </head>\n"
                           " <body>\n"
                           "  <h1>%s</h1>\n"
                           "  <ul>\n",
                           decoded_path, /* XXX html-escape this. */
                           uri_root, path, /* XXX html-escape this? */
                           trailing_slash,
                           decoded_path /* XXX html-escape this */);

      while ((ent = readdir (d)))
        {
          const char *name = ent->d_name;
          evbuffer_add_printf (evb,
                               "    <li><a href=\"%s\">%s</a>\n",
                               name, name);/* XXX escape this */
        }
      evbuffer_add_printf (evb, "</ul></body></html>\n");
      closedir (d);
      evhttp_add_header (evhttp_request_get_output_headers (req),
                         "Content-Type", "text/html");
    }
#endif
  else
    {
      /* Otherwise it's a file; add it to the buffer to get
       * sent via sendfile
       */
      type = guess_content_type (decoded_path);
      /* O_BINARY is used to open the files that
       * contains unicode. otherwise,open files will be failed.
       */
      if ((fd = open (whole_path, O_RDONLY|O_BINARY)) < 0)
        {
          http_error_404 (req, fd);
          LOG_WARN ("-- %s -- %s -- Web server: bad request for [%s]", req->remote_host, userAgent, uri);
          goto done;
        }

      if (fstat (fd, &st) < 0)
        {
          /* Make sure the length still matches, now that we
           * opened the file :/
           */
          http_error_404 (req, fd);
          LOG_WARN ("-- %s -- %s -- Web server: bad request for [%s]", req->remote_host, userAgent, uri);
          goto done;
        }
      evhttp_add_header (evhttp_request_get_output_headers (req),
                         "Content-Type", type);
      evbuffer_add_file (evb, fd, 0, st.st_size);
    }

  evhttp_send_reply (req, 200, "OK", evb);

done:
  if (decoded)
    {
      evhttp_uri_free (decoded);
    }
  if (decoded_path)
    {
      free (decoded_path);
    }
  if (whole_path)
    {
      free (whole_path);
    }
  if (evb)
    {
      evbuffer_free (evb);
    }
}

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
struct bufferevent *create_sslconn_cb (struct event_base *base, void *arg)
{
  struct bufferevent *r = NULL;
  SSL_CTX *ctx = (SSL_CTX *) arg;

  r = bufferevent_openssl_socket_new (base,
                                      -1,
                                      SSL_new (ctx),
                                      BUFFEREVENT_SSL_ACCEPTING,
                                      BEV_OPT_CLOSE_ON_FREE);
  if (r == NULL)
    {
      LOG_ERROR ("-- Web server: Failed to create SSL connection.");
    }
  return r;
}

/**
 * @brief server_setup_certs
 * Used to init SSL certificate and private key.
 * @param ctx
 * Used to generate SSL_CTX
 * @param certificate_chain
 * certificate chain file. It can be full path,also can be the name of file.
 * @param private_key
 * private key file. It can be full path,also can be the name of file.
 * @return
 */
static void server_setup_certs (SSL_CTX *ctx,
                                const char *certificate_chain,
                                const char *private_key)
{
  if (1 != SSL_CTX_use_certificate_chain_file (ctx, certificate_chain))
    {
      LOG_ERROR ("-- Web server: OpenSSL error: Cannot initialize certificate file.");
      exit (-1);
    }
  if (1 != SSL_CTX_use_PrivateKey_file (ctx, private_key, SSL_FILETYPE_PEM))
    {
      LOG_ERROR ("-- Web server: OpenSSL error: Cannot initialize private key file.");
      exit (-1);
    }
  if (1 != SSL_CTX_check_private_key (ctx))
    {
      LOG_ERROR ("-- Web server: OpenSSL error: Invalid CTX private key.");
      exit (-1);
    }
}

/**
 * @brief thread_setup_SSL
 * Setup the necessary resources to ensure that OpenSSL can safely
 * be used in multi-threaded environment.
 * @return
 */
void thread_setup_SSL (void)
{
  int total_locks, i;

  total_locks = CRYPTO_num_locks ();

  lock_array = (MUTEX_T *) OPENSSL_malloc (total_locks * sizeof (MUTEX_T));

  for (i = 0; i < total_locks; i++)
    {
      MUTEX_INIT (lock_array[i]);
    }

#if !defined(WINDOWS) && !defined(__BEOS__)
  /* It's unnecessary to define or set the thread-id callback functions for
   * WINDOWS and BEOS platform, since they have been defined in OpenSSL kernel.
   * Please refer to the source code implemented CRYPTO_THREADID_current()
   * function in crypto/cryptlib.c from OpenSSL.
   */
  CRYPTO_THREADID_set_callback (thread_id_callback);
#endif

  CRYPTO_set_locking_callback (locking_callback);
}

#if !defined(WINDOWS) && !defined(__BEOS__)
/**
 * @brief thread_id_callback
 * Callback function to get thread id for OpenSSL thread safety.
 * @param tid
 * The thread id to be set.
 * @return
 */
static void thread_id_callback (CRYPTO_THREADID *tid)
{
  CRYPTO_THREADID_set_numeric (tid, (unsigned long) pthread_self ());
}
#endif

/**
 * @brief locking_callback
 * Callback function to get lock for OpenSSL thread safety.
 * @param mode
 * The lock mode (lock or unlock) as required by OpenSSL.
 * @param type
 * The lock type as required and internally used by OpenSSL.
 * @param file
 * The source code file name as required and internally used by OpenSSL.
 * @param line
 * The source code line number as required and internally used by OpenSSL.
 * @return
 */
static void locking_callback (int mode, int type, const char *file, int line)
{
  if (mode & CRYPTO_LOCK)
    {
      MUTEX_LOCK (lock_array[type]);
    }
  else
    {
      MUTEX_UNLOCK (lock_array[type]);
    }
}

/**
 * @brief thread_cleanup_SSL
 * Cleanup the allocated resources which is used for OpenSSL thread safety.
 * @return
 */
void thread_cleanup_SSL (void)
{
  int total_locks, i;

  CRYPTO_set_locking_callback (NULL);

  if (lock_array != NULL)
    {
      total_locks = CRYPTO_num_locks ();

      for (i = 0; i < total_locks; i++)
        {
          MUTEX_DESTROY (lock_array[i]);
        }

      OPENSSL_free (lock_array);
      lock_array = NULL;
    }
}

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
SSL_CTX *init_SSL (const char *certificate_chain,const char *private_key)
{

  SSL_CTX *ctx = NULL;
  /* init SSL libray is must. */
  SSL_library_init ();
  /* We just use SSLv3,do not support SSLv2. */

  ctx = SSL_CTX_new (SSLv23_server_method ());
  if (!ctx)
    {
      LOG_ERROR ("-- Web server: Fail to generate CTX for openSSL.");
    }
  SSL_CTX_set_options (ctx,
                       SSL_OP_SINGLE_DH_USE |
                       SSL_OP_SINGLE_ECDH_USE |
                       SSL_OP_NO_SSLv2);

  /* Find and set up our server certificate. */
  server_setup_certs (ctx, certificate_chain, private_key);
  return ctx;
}

/**
 * @brief http_error_404
 * Used to report 404 error to browser using libevent.and close fd
 * @param req
 * http request
 * See also: struct evhttp_request
 * @param fd
 * if fd >= 0, close it.
 * @return
 * See also: evhttp_send_error
 */

static void http_error_404 (struct evhttp_request *req, int fd)
{
  const char *uri = evhttp_request_get_uri (req);
#define ERROR_FORMAT "<html><head>" \
            "<title>404 Not Found</title>" \
            "</head><body>" \
            "<center><h1>404 Not Found</h1></center>" \
            "<center><p>Request: %s not found</p></center>"\
            "<hr>"\
            "<center><address>Cubrid Manager Server</address></center>"\
            "</body></html>\n"

  struct evbuffer *buf = evbuffer_new ();
  if (buf == NULL)
    {
      /* if we cannot allocate memory; we just drop the connection */
      LOG_WARN ("-- Web server: http_error_404 cannot create a buffer.");
      return;
    }
  evbuffer_add_printf (buf, ERROR_FORMAT, uri);
  evhttp_send_reply (req, 404, "404 Not Found", buf);
  evbuffer_free (buf);
#undef ERROR_FORMAT
  if (fd >= 0)
    {
      close (fd);
    }
}

/**
 * @brief web_error_404
 * Used to report 404 error to browser when use did not start web server:  in cm.conf
 * @param
 * @return
 * See also: evhttp_send_error
 */

static void web_error_404 (struct evhttp_request *req)
{

#define ERROR_FORMAT "<html><head>" \
            "<title>404 Not Found</title>" \
            "</head><body>" \
            "<center><h1>404 Not Found</h1></center>" \
            "<center><p>Web Manager was not started, please configure it rightly</p></center>"\
            "<hr>"\
            "<center><address>Cubrid Manager Server</address></center>"\
            "</body></html>\n"

  struct evbuffer *buf = evbuffer_new ();

  evbuffer_add_printf (buf, ERROR_FORMAT);
  evhttp_send_reply (req, 404, "Not Found", buf);
  evbuffer_free (buf);
#undef ERROR_FORMAT
}
