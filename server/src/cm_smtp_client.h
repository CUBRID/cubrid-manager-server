/*
 *
 * Copyright 2016 CUBRID Corporation
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

/*
 * cm_smtp_client.h - a minimal SMTP client for sendmail and the automatic
 *   mail report. See cm_smtp_client.cpp.
 */

#ifndef _CM_SMTP_CLIENT_H_
#define _CM_SMTP_CLIENT_H_

#include <time.h>

#include <string>

#define SMTP_DEFAULT_PORT 25
#define SMTP_DEFAULT_TIMEOUT_MS 30000

/* result of smtp_send_mail () */
typedef enum
{
  SMTP_SEND_OK,
  SMTP_SEND_INVALID_ARGUMENT,	/* bad host, address or header field; nothing is sent */
  SMTP_SEND_RESOLVE_FAILED,	/* the host name cannot be resolved */
  SMTP_SEND_CONNECT_FAILED,	/* no address of the host accepted the connection */
  SMTP_SEND_TIMEOUT,		/* connecting or a wait for the server took too long */
  SMTP_SEND_CONNECTION_LOST,	/* closed by the server, socket error or not an SMTP reply */
  SMTP_SEND_REJECTED		/* the server answered a command with an error */
} T_SMTP_SEND_RESULT;

/* how to authenticate; the values are those of authtype in the sendmail request */
typedef enum
{
  SMTP_AUTH_LOGIN = 1,
  SMTP_AUTH_PLAIN = 2
} T_SMTP_AUTH;

typedef enum
{
  SMTP_BODY_TEXT,
  SMTP_BODY_HTML
} T_SMTP_BODY_TYPE;

typedef struct
{
  std::string host;		/* host name, IPv4 address or IPv6 address without [] */
  unsigned short port;
  int timeout_ms;		/* for connecting to each address and for each wait */
  std::string username;		/* empty: no authentication */
  std::string password;
  T_SMTP_AUTH auth;
} T_SMTP_SERVER;

typedef struct
{
  std::string sender;		/* "user@host" or "name <user@host>" */
  std::string receiver;		/* likewise */
  std::string subject;		/* UTF-8 */
  std::string body;		/* UTF-8 */
  T_SMTP_BODY_TYPE body_type;
} T_SMTP_MAIL;

T_SMTP_SEND_RESULT smtp_send_mail (const T_SMTP_SERVER &server, const T_SMTP_MAIL &mail, std::string &detail);
const char *smtp_send_result_name (T_SMTP_SEND_RESULT result);
std::string smtp_printable (const std::string &text);

std::string smtp_base64_encode (const std::string &data);
bool smtp_mailbox_address (const std::string &mailbox, std::string &address);
bool smtp_build_message (const T_SMTP_MAIL &mail, time_t now, std::string &message);

#endif /* _CM_SMTP_CLIENT_H_ */
