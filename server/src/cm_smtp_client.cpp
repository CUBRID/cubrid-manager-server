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
 * cm_smtp_client.cpp - a minimal SMTP client (RFC 5321) for sendmail and the
 *   automatic mail report. It replaces the jwSMTP library (cm_mailer.h).
 *
 *   It sends one mail to one receiver through the one server it is given:
 *   no MX lookup, no TLS. It authenticates with AUTH LOGIN or AUTH PLAIN
 *   (RFC 4954) when a user name is given. The body is UTF-8 text or HTML,
 *   sent in base64, so that long lines and lines starting with '.' need no
 *   special handling.
 *
 *   Every connect, send and receive waits at most the timeout of the
 *   server. The resolution of the host name (getaddrinfo ()) is not bounded
 *   by it.
 *
 *   No CUBRID or CMS dependency, so that it can be tested against a fake
 *   server (server/test/unit/test_smtp_client.cpp). It does not log: the
 *   caller logs the result and the detail it returns. The detail never holds
 *   the password.
 */

#if defined (WINDOWS)
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <poll.h>
#include <unistd.h>
#include <errno.h>
#endif

#include <stdio.h>
#include <string.h>

#include <chrono>
#include <string>

#include "cm_smtp_client.h"

#if defined (WINDOWS)
typedef SOCKET T_SMTP_SOCKET;
#define SMTP_INVALID_SOCKET INVALID_SOCKET
#define SMTP_SEND_FLAGS 0
#else
typedef int T_SMTP_SOCKET;
#define SMTP_INVALID_SOCKET (-1)
#define SMTP_SEND_FLAGS MSG_NOSIGNAL
#endif

/* longest reply (all lines) accepted from the server */
#define SMTP_REPLY_MAX 65536
/* longest server text kept in the detail */
#define SMTP_DETAIL_TEXT_MAX 200
/* base64 characters in one line of the body */
#define SMTP_BASE64_LINE 76
/* bytes of the subject in one encoded word: 60 base64 characters */
#define SMTP_ENCODED_WORD_BYTES 45
/* longest subject sent as it is */
#define SMTP_PLAIN_SUBJECT_MAX 900

typedef enum
{
  SMTP_WAIT_READ,
  SMTP_WAIT_WRITE
} T_SMTP_WAIT;

static const char *smtp_day_names[] = { "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat" };

static const char *smtp_month_names[] =
{
  "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
};

/*
 * smtp_last_socket_error () - the error code of the last failed socket call.
 */
static int
smtp_last_socket_error (void)
{
#if defined (WINDOWS)
  return WSAGetLastError ();
#else
  return errno;
#endif
}

/*
 * smtp_socket_error_text () - an error code of a socket call as text.
 */
static std::string
smtp_socket_error_text (int error)
{
#if defined (WINDOWS)
  char text[64];

  snprintf (text, sizeof (text), "socket error %d", error);
  return text;
#else
  return strerror (error);
#endif
}

/*
 * smtp_close_socket () - close a socket.
 */
static void
smtp_close_socket (T_SMTP_SOCKET sock)
{
#if defined (WINDOWS)
  closesocket (sock);
#else
  close (sock);
#endif
}

/*
 * smtp_set_nonblocking () - make a socket non-blocking, so that every wait
 *   goes through smtp_wait () and its timeout.
 *
 *   return: true on success
 */
static bool
smtp_set_nonblocking (T_SMTP_SOCKET sock)
{
#if defined (WINDOWS)
  u_long on = 1;

  return ioctlsocket (sock, FIONBIO, &on) == 0;
#else
  int flags = fcntl (sock, F_GETFL, 0);

  return flags != -1 && fcntl (sock, F_SETFL, flags | O_NONBLOCK) != -1;
#endif
}

/*
 * smtp_would_block () - whether a socket error means only that the call
 *   would have to wait (a non-blocking connect, send or recv).
 */
static bool
smtp_would_block (int error)
{
#if defined (WINDOWS)
  return error == WSAEWOULDBLOCK || error == WSAEINPROGRESS;
#else
  return error == EWOULDBLOCK || error == EAGAIN || error == EINPROGRESS;
#endif
}

/*
 * smtp_wait () - wait until a socket can be read or written, at most until
 *   the deadline.
 *
 *   return: SMTP_SEND_OK when it can, SMTP_SEND_TIMEOUT when the deadline
 *           passed, SMTP_SEND_CONNECTION_LOST when the wait failed (detail
 *           set)
 *   sock(in): the socket
 *   what(in): SMTP_WAIT_READ or SMTP_WAIT_WRITE
 *   deadline(in): when to stop waiting
 *   detail(out): the reason of a failure
 */
static T_SMTP_SEND_RESULT
smtp_wait (T_SMTP_SOCKET sock, T_SMTP_WAIT what, std::chrono::steady_clock::time_point deadline,
	   std::string &detail)
{
  struct pollfd pfd;
  int rc;

  for (;;)
    {
      std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now ();
      long long left_ms;

      if (now >= deadline)
	{
	  return SMTP_SEND_TIMEOUT;
	}
      left_ms = std::chrono::duration_cast<std::chrono::milliseconds> (deadline - now).count () + 1;

      memset (&pfd, 0, sizeof (pfd));
      pfd.fd = sock;
      pfd.events = (what == SMTP_WAIT_READ) ? POLLIN : POLLOUT;
#if defined (WINDOWS)
      rc = WSAPoll (&pfd, 1, (int) left_ms);
#else
      rc = poll (&pfd, 1, (int) left_ms);
#endif
      if (rc > 0)
	{
	  return SMTP_SEND_OK;
	}
      if (rc == 0)
	{
	  continue;		/* checked against the deadline above */
	}
#if !defined (WINDOWS)
      if (errno == EINTR)
	{
	  continue;
	}
#endif
      detail = "waiting for the server failed: " + smtp_socket_error_text (smtp_last_socket_error ());
      return SMTP_SEND_CONNECTION_LOST;
    }
}

/*
 * smtp_printable () - text made safe for one log line: characters other
 *   than printable ASCII (CR and LF among them) become '?', and text longer
 *   than SMTP_DETAIL_TEXT_MAX is cut and ends with "...". Used for the
 *   replies of the server in the detail, and by the callers for values of
 *   a request they log.
 */
std::string
smtp_printable (const std::string &text)
{
  std::string out;
  size_t i;

  for (i = 0; i < text.size () && out.size () < SMTP_DETAIL_TEXT_MAX; ++i)
    {
      unsigned char c = (unsigned char) text[i];

      out += (c >= 0x20 && c <= 0x7e) ? (char) c : '?';
    }
  if (i < text.size ())
    {
      out += "...";
    }
  return out;
}

/*
 * smtp_has_line_break () - whether text holds CR, LF or NUL, which would end
 *   an SMTP command or a header line early.
 */
static bool
smtp_has_line_break (const std::string &text)
{
  return text.find_first_of (std::string ("\r\n\0", 3)) != std::string::npos;
}

/*
 * smtp_is_printable_ascii () - whether every character of text is printable
 *   ASCII, so that it can be a header value as it is.
 */
static bool
smtp_is_printable_ascii (const std::string &text)
{
  for (size_t i = 0; i < text.size (); ++i)
    {
      unsigned char c = (unsigned char) text[i];

      if (c < 0x20 || c > 0x7e)
	{
	  return false;
	}
    }
  return true;
}

/*
 * smtp_base64_char () - the base64 character of the 6 bits of v starting at
 *   bit shift.
 */
static char
smtp_base64_char (unsigned int v, int shift)
{
  static const char table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  unsigned int index = (v >> shift) & 0x3f;

  return table[index];
}

/*
 * smtp_base64_encode () - base64 (RFC 4648) of data, with padding and
 *   without line breaks.
 */
std::string
smtp_base64_encode (const std::string &data)
{
  std::string out;
  size_t i;

  out.reserve ((data.size () + 2) / 3 * 4);
  for (i = 0; i + 2 < data.size (); i += 3)
    {
      unsigned int v = ((unsigned char) data[i] << 16) | ((unsigned char) data[i + 1] << 8)
		       | (unsigned char) data[i + 2];

      out += smtp_base64_char (v, 18);
      out += smtp_base64_char (v, 12);
      out += smtp_base64_char (v, 6);
      out += smtp_base64_char (v, 0);
    }
  if (i + 1 == data.size ())
    {
      unsigned int v = (unsigned char) data[i] << 16;

      out += smtp_base64_char (v, 18);
      out += smtp_base64_char (v, 12);
      out += "==";
    }
  else if (i + 2 == data.size ())
    {
      unsigned int v = ((unsigned char) data[i] << 16) | ((unsigned char) data[i + 1] << 8);

      out += smtp_base64_char (v, 18);
      out += smtp_base64_char (v, 12);
      out += smtp_base64_char (v, 6);
      out += '=';
    }
  return out;
}

/*
 * smtp_mailbox_address () - the address of a mailbox written as
 *   "user@host" or "name <user@host>".
 *
 *   return: true if mailbox is one of these forms: the address has no space,
 *           '<', '>' or line break, and has a non-empty part on both sides
 *           of its last '@'. false otherwise, with address set to "".
 *   mailbox(in): the mailbox
 *   address(out): the address, without the name and the angle brackets
 */
bool
smtp_mailbox_address (const std::string &mailbox, std::string &address)
{
  const char *blank = " \t";
  std::string text;
  size_t first, last, lt, gt, at;

  address.clear ();
  if (smtp_has_line_break (mailbox))
    {
      return false;
    }

  first = mailbox.find_first_not_of (blank);
  if (first == std::string::npos)
    {
      return false;
    }
  last = mailbox.find_last_not_of (blank);
  text = mailbox.substr (first, last - first + 1);

  lt = text.find ('<');
  if (lt != std::string::npos)
    {
      gt = text.find ('>', lt);
      if (gt == std::string::npos || gt != text.size () - 1)
	{
	  return false;
	}
      text = text.substr (lt + 1, gt - lt - 1);
    }

  if (text.find_first_of (" \t<>") != std::string::npos)
    {
      return false;
    }
  at = text.rfind ('@');
  if (at == std::string::npos || at == 0 || at == text.size () - 1)
    {
      return false;
    }

  address = text;
  return true;
}

/*
 * smtp_utc_offset_minutes () - the difference between local time and UTC in
 *   minutes, from the two broken-down forms of the same time.
 */
static int
smtp_utc_offset_minutes (const struct tm &local, const struct tm &utc)
{
  int days = local.tm_yday - utc.tm_yday;

  if (local.tm_year != utc.tm_year)
    {
      days = (local.tm_year > utc.tm_year) ? 1 : -1;
    }
  return days * 24 * 60 + (local.tm_hour - utc.tm_hour) * 60 + (local.tm_min - utc.tm_min);
}

/*
 * smtp_date_header () - the Date header (RFC 5322) of a time, in local time
 *   with its offset from UTC. The names of days and months are always
 *   English, whatever the locale.
 *
 *   return: true on success
 */
static bool
smtp_date_header (time_t now, std::string &header)
{
  struct tm local, utc;
  char text[64];
  int offset;

  memset (&local, 0, sizeof (local));
  memset (&utc, 0, sizeof (utc));

#if defined (WINDOWS)
  if (localtime_s (&local, &now) != 0 || gmtime_s (&utc, &now) != 0)
    {
      return false;
    }
#else
  if (localtime_r (&now, &local) == NULL || gmtime_r (&now, &utc) == NULL)
    {
      return false;
    }
#endif

  offset = smtp_utc_offset_minutes (local, utc);
  snprintf (text, sizeof (text), "Date: %s, %02d %s %04d %02d:%02d:%02d %c%02d%02d\r\n",
	    smtp_day_names[local.tm_wday], local.tm_mday, smtp_month_names[local.tm_mon],
	    local.tm_year + 1900, local.tm_hour, local.tm_min, local.tm_sec,
	    (offset < 0) ? '-' : '+', ((offset < 0) ? -offset : offset) / 60,
	    ((offset < 0) ? -offset : offset) % 60);
  header = text;
  return true;
}

/*
 * smtp_subject_header () - the Subject header. Printable ASCII that is not
 *   too long is written as it is; anything else as UTF-8 encoded words
 *   (RFC 2047), each at most 75 characters and on its own folded line. A
 *   word never splits a UTF-8 character.
 */
static std::string
smtp_subject_header (const std::string &subject)
{
  std::string header = "Subject:";
  size_t pos = 0;

  if (smtp_is_printable_ascii (subject) && subject.size () <= SMTP_PLAIN_SUBJECT_MAX)
    {
      return header + " " + subject + "\r\n";
    }

  while (pos < subject.size ())
    {
      size_t len = subject.size () - pos;

      if (len > SMTP_ENCODED_WORD_BYTES)
	{
	  len = SMTP_ENCODED_WORD_BYTES;
	  /* do not start the next word on a continuation byte (10xxxxxx) */
	  while (len > 1 && ((unsigned char) subject[pos + len] & 0xc0) == 0x80)
	    {
	      --len;
	    }
	}
      if (pos > 0)
	{
	  header += "\r\n";
	}
      header += " =?UTF-8?B?" + smtp_base64_encode (subject.substr (pos, len)) + "?=";
      pos += len;
    }
  return header + "\r\n";
}

/*
 * smtp_mailbox_header () - a From or To header. The mailbox is written as
 *   it is if it is printable ASCII; otherwise (a name in another language)
 *   only its address is written.
 */
static std::string
smtp_mailbox_header (const char *name, const std::string &mailbox, const std::string &address)
{
  if (smtp_is_printable_ascii (mailbox))
    {
      return std::string (name) + ": " + mailbox + "\r\n";
    }
  return std::string (name) + ": <" + address + ">\r\n";
}

/*
 * smtp_build_message () - the message (RFC 5322) sent after DATA: the
 *   headers, an empty line and the body in base64 lines. It ends with CRLF,
 *   and holds no line that is only ".".
 *
 *   return: true on success; false if the sender or receiver is not a
 *           mailbox, the subject has a line break or the time cannot be
 *           converted
 *   mail(in): the mail
 *   now(in): the time of the Date header
 *   message(out): the message
 */
bool
smtp_build_message (const T_SMTP_MAIL &mail, time_t now, std::string &message)
{
  std::string sender, receiver, date, body;

  message.clear ();
  if (!smtp_mailbox_address (mail.sender, sender) || !smtp_mailbox_address (mail.receiver, receiver)
      || smtp_has_line_break (mail.subject) || !smtp_date_header (now, date))
    {
      return false;
    }

  message = date;
  message += smtp_mailbox_header ("From", mail.sender, sender);
  message += smtp_mailbox_header ("To", mail.receiver, receiver);
  message += smtp_subject_header (mail.subject);
  message += "MIME-Version: 1.0\r\n";
  message += (mail.body_type == SMTP_BODY_HTML) ? "Content-Type: text/html; charset=UTF-8\r\n"
	     : "Content-Type: text/plain; charset=UTF-8\r\n";
  message += "Content-Transfer-Encoding: base64\r\n";
  message += "\r\n";

  body = smtp_base64_encode (mail.body);
  for (size_t pos = 0; pos < body.size (); pos += SMTP_BASE64_LINE)
    {
      message += body.substr (pos, SMTP_BASE64_LINE) + "\r\n";
    }
  return true;
}

/*
 * smtp_client_name () - the name the client gives in EHLO and HELO: the
 *   host name if it is a valid domain name, "localhost" otherwise.
 */
static std::string
smtp_client_name (void)
{
  char name[256];

  if (gethostname (name, sizeof (name)) != 0)
    {
      return "localhost";
    }
  name[sizeof (name) - 1] = '\0';
  if (name[0] == '\0' || strspn (name, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-.")
      != strlen (name))
    {
      return "localhost";
    }
  return name;
}

/*
 * smtp_session - one connection to the server: the socket, the bytes
 *   received but not yet read, and the timeout of each wait.
 */
class smtp_session
{
  public:
    smtp_session (int timeout_ms, std::string &detail)
      : m_sock (SMTP_INVALID_SOCKET), m_timeout (timeout_ms), m_last_code (0), m_detail (detail)
    {
    }

    ~smtp_session ()
    {
      if (m_sock != SMTP_INVALID_SOCKET)
	{
	  smtp_close_socket (m_sock);
	}
    }

    T_SMTP_SEND_RESULT connect_to (const std::string &host, unsigned short port);
    T_SMTP_SEND_RESULT send_text (const std::string &text);
    T_SMTP_SEND_RESULT read_reply (int &code, std::string &text);
    T_SMTP_SEND_RESULT command (const char *step, const std::string &line, int expected,
				int also_expected = 0);
    void quit ();
    int last_code () const
    {
      return m_last_code;
    }

  private:
    T_SMTP_SEND_RESULT connect_address (const struct addrinfo *ai, const std::string &where);
    std::chrono::steady_clock::time_point deadline () const
    {
      return std::chrono::steady_clock::now () + m_timeout;
    }

    T_SMTP_SOCKET m_sock;
    std::chrono::milliseconds m_timeout;
    int m_last_code;		/* code of the last reply command () read; 0 if none */
    std::string m_received;
    std::string &m_detail;
};

/*
 * smtp_session::connect_address () - connect to one address of the server,
 *   waiting at most the timeout.
 *
 *   return: SMTP_SEND_OK, SMTP_SEND_TIMEOUT or SMTP_SEND_CONNECT_FAILED
 *           (detail set)
 *   ai(in): the address
 *   where(in): the address and port as text, for the detail
 */
T_SMTP_SEND_RESULT
smtp_session::connect_address (const struct addrinfo *ai, const std::string &where)
{
  T_SMTP_SEND_RESULT result;
  int error = 0;
  socklen_t len = sizeof (error);

  m_sock = socket (ai->ai_family, ai->ai_socktype, ai->ai_protocol);
  if (m_sock == SMTP_INVALID_SOCKET)
    {
      m_detail = "socket for " + where + ": " + smtp_socket_error_text (smtp_last_socket_error ());
      return SMTP_SEND_CONNECT_FAILED;
    }
  if (!smtp_set_nonblocking (m_sock))
    {
      m_detail = "non-blocking socket for " + where + ": " + smtp_socket_error_text (smtp_last_socket_error ());
      return SMTP_SEND_CONNECT_FAILED;
    }

  if (connect (m_sock, ai->ai_addr, (socklen_t) ai->ai_addrlen) == 0)
    {
      return SMTP_SEND_OK;
    }
  error = smtp_last_socket_error ();
  if (!smtp_would_block (error))
    {
      m_detail = "connect to " + where + ": " + smtp_socket_error_text (error);
      return SMTP_SEND_CONNECT_FAILED;
    }

  result = smtp_wait (m_sock, SMTP_WAIT_WRITE, deadline (), m_detail);
  if (result == SMTP_SEND_TIMEOUT)
    {
      m_detail = "connect to " + where + ": timed out";
      return SMTP_SEND_TIMEOUT;
    }
  if (result != SMTP_SEND_OK)
    {
      return SMTP_SEND_CONNECT_FAILED;
    }

  error = 0;
  if (getsockopt (m_sock, SOL_SOCKET, SO_ERROR, (char *) &error, &len) != 0)
    {
      error = smtp_last_socket_error ();
    }
  if (error != 0)
    {
      m_detail = "connect to " + where + ": " + smtp_socket_error_text (error);
      return SMTP_SEND_CONNECT_FAILED;
    }
  return SMTP_SEND_OK;
}

/*
 * smtp_session::connect_to () - resolve the server and connect to its
 *   addresses in the order getaddrinfo () gives them, until one accepts.
 *
 *   return: SMTP_SEND_OK, SMTP_SEND_RESOLVE_FAILED, or the result of the
 *           last address tried (detail set)
 *   host(in): host name or IP address (an IPv6 address without [])
 *   port(in): port
 */
T_SMTP_SEND_RESULT
smtp_session::connect_to (const std::string &host, unsigned short port)
{
  struct addrinfo hints, *list = NULL, *ai;
  char port_text[16];
  T_SMTP_SEND_RESULT result = SMTP_SEND_CONNECT_FAILED;
  int rc;

  memset (&hints, 0, sizeof (hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;
  snprintf (port_text, sizeof (port_text), "%u", (unsigned int) port);

  rc = getaddrinfo (host.c_str (), port_text, &hints, &list);
  if (rc != 0 || list == NULL)
    {
      m_detail = "cannot resolve " + host + ": " + ((rc != 0) ? gai_strerror (rc) : "no address");
      if (list != NULL)
	{
	  freeaddrinfo (list);
	}
      return SMTP_SEND_RESOLVE_FAILED;
    }

  for (ai = list; ai != NULL; ai = ai->ai_next)
    {
      char addr_text[NI_MAXHOST];
      std::string where;

      if (getnameinfo (ai->ai_addr, (socklen_t) ai->ai_addrlen, addr_text, sizeof (addr_text), NULL, 0,
		       NI_NUMERICHOST) != 0)
	{
	  snprintf (addr_text, sizeof (addr_text), "%s", host.c_str ());
	}
      where = (ai->ai_family == AF_INET6) ? "[" + std::string (addr_text) + "]:" + port_text
	      : std::string (addr_text) + ":" + port_text;

      if (m_sock != SMTP_INVALID_SOCKET)
	{
	  smtp_close_socket (m_sock);
	  m_sock = SMTP_INVALID_SOCKET;
	}
      result = connect_address (ai, where);
      if (result == SMTP_SEND_OK)
	{
	  break;
	}
    }

  freeaddrinfo (list);
  return result;
}

/*
 * smtp_session::send_text () - send all of text, waiting at most the
 *   timeout each time the socket cannot take more.
 *
 *   return: SMTP_SEND_OK, SMTP_SEND_TIMEOUT or SMTP_SEND_CONNECTION_LOST
 *           (detail set)
 */
T_SMTP_SEND_RESULT
smtp_session::send_text (const std::string &text)
{
  size_t sent = 0;

  while (sent < text.size ())
    {
      int n = send (m_sock, text.data () + sent, (int) (text.size () - sent), SMTP_SEND_FLAGS);
      int error;
      T_SMTP_SEND_RESULT result;

      if (n > 0)
	{
	  sent += (size_t) n;
	  continue;
	}
      error = smtp_last_socket_error ();
#if !defined (WINDOWS)
      if (n < 0 && error == EINTR)
	{
	  continue;
	}
#endif
      if (n < 0 && smtp_would_block (error))
	{
	  result = smtp_wait (m_sock, SMTP_WAIT_WRITE, deadline (), m_detail);
	  if (result == SMTP_SEND_TIMEOUT)
	    {
	      m_detail = "sending to the server timed out";
	    }
	  if (result != SMTP_SEND_OK)
	    {
	      return result;
	    }
	  continue;
	}
      m_detail = "sending to the server failed: " + smtp_socket_error_text (error);
      return SMTP_SEND_CONNECTION_LOST;
    }
  return SMTP_SEND_OK;
}

/*
 * smtp_session::read_reply () - read one reply of the server: lines
 *   "ddd-text" and a last line "ddd text" or "ddd".
 *
 *   return: SMTP_SEND_OK, SMTP_SEND_TIMEOUT or SMTP_SEND_CONNECTION_LOST
 *           (detail set; also for a line that is not a reply line and for a
 *           reply longer than SMTP_REPLY_MAX)
 *   code(out): the reply code of the last line
 *   text(out): the text of the last line
 */
T_SMTP_SEND_RESULT
smtp_session::read_reply (int &code, std::string &text)
{
  size_t total = 0;

  for (;;)
    {
      size_t eol = m_received.find ('\n');

      if (eol != std::string::npos)
	{
	  std::string line = m_received.substr (0, eol);

	  m_received.erase (0, eol + 1);
	  total += eol + 1;
	  if (!line.empty () && line[line.size () - 1] == '\r')
	    {
	      line.erase (line.size () - 1);
	    }

	  if (line.size () < 3 || strspn (line.substr (0, 3).c_str (), "0123456789") != 3
	      || (line.size () > 3 && line[3] != ' ' && line[3] != '-'))
	    {
	      m_detail = "not an SMTP reply: " + smtp_printable (line);
	      return SMTP_SEND_CONNECTION_LOST;
	    }
	  if (line.size () > 3 && line[3] == '-')
	    {
	      if (total > SMTP_REPLY_MAX)
		{
		  m_detail = "the reply of the server is too long";
		  return SMTP_SEND_CONNECTION_LOST;
		}
	      continue;
	    }
	  code = (line[0] - '0') * 100 + (line[1] - '0') * 10 + (line[2] - '0');
	  text = (line.size () > 4) ? line.substr (4) : "";
	  return SMTP_SEND_OK;
	}

      if (total + m_received.size () > SMTP_REPLY_MAX)
	{
	  m_detail = "the reply of the server is too long";
	  return SMTP_SEND_CONNECTION_LOST;
	}

      T_SMTP_SEND_RESULT result = smtp_wait (m_sock, SMTP_WAIT_READ, deadline (), m_detail);
      if (result == SMTP_SEND_TIMEOUT)
	{
	  m_detail = "waiting for the reply of the server timed out";
	}
      if (result != SMTP_SEND_OK)
	{
	  return result;
	}

      char buf[4096];
      int n = recv (m_sock, buf, (int) sizeof (buf), 0);
      if (n > 0)
	{
	  m_received.append (buf, (size_t) n);
	  continue;
	}
      if (n == 0)
	{
	  m_detail = "the server closed the connection";
	  return SMTP_SEND_CONNECTION_LOST;
	}

      int error = smtp_last_socket_error ();
#if !defined (WINDOWS)
      if (error == EINTR)
	{
	  continue;
	}
#endif
      if (!smtp_would_block (error))
	{
	  m_detail = "receiving from the server failed: " + smtp_socket_error_text (error);
	  return SMTP_SEND_CONNECTION_LOST;
	}
    }
}

/*
 * smtp_session::command () - send a command line (if any) and read its
 *   reply, which must have one of the expected codes.
 *
 *   return: SMTP_SEND_OK; SMTP_SEND_REJECTED for another code, with the
 *           step and the reply in the detail; or the failure of sending or
 *           reading
 *   step(in): what the command does, for the detail. Never the line itself,
 *             which can hold the password.
 *   line(in): the command without CRLF; empty to only read a reply
 *   expected(in), also_expected(in): accepted codes; also_expected 0 if
 *                                    only one
 */
T_SMTP_SEND_RESULT
smtp_session::command (const char *step, const std::string &line, int expected, int also_expected)
{
  T_SMTP_SEND_RESULT result;
  std::string text;
  int code = 0;
  char code_text[8];

  m_last_code = 0;
  if (!line.empty ())
    {
      result = send_text (line + "\r\n");
      if (result != SMTP_SEND_OK)
	{
	  m_detail = std::string (step) + ": " + m_detail;
	  return result;
	}
    }

  result = read_reply (code, text);
  if (result != SMTP_SEND_OK)
    {
      m_detail = std::string (step) + ": " + m_detail;
      return result;
    }

  m_last_code = code;
  snprintf (code_text, sizeof (code_text), "%d", code);
  m_detail = std::string (step) + ": server replied " + code_text + " " + smtp_printable (text);
  if (code == expected || (also_expected != 0 && code == also_expected))
    {
      return SMTP_SEND_OK;
    }
  return SMTP_SEND_REJECTED;
}

/*
 * smtp_session::quit () - end the session politely. Errors are ignored: the
 *   mail was already sent or the session already failed.
 */
void
smtp_session::quit ()
{
  std::string saved = m_detail;
  std::string text;
  int code;

  if (send_text ("QUIT\r\n") == SMTP_SEND_OK)
    {
      read_reply (code, text);
    }
  m_detail = saved;
}

/*
 * smtp_authenticate () - AUTH LOGIN or AUTH PLAIN with the user and
 *   password of the server.
 *
 *   return: the result of the failed step, or SMTP_SEND_OK
 */
static T_SMTP_SEND_RESULT
smtp_authenticate (smtp_session &session, const T_SMTP_SERVER &server)
{
  T_SMTP_SEND_RESULT result;

  if (server.auth == SMTP_AUTH_LOGIN)
    {
      result = session.command ("AUTH LOGIN", "AUTH LOGIN", 334);
      if (result == SMTP_SEND_OK)
	{
	  result = session.command ("AUTH LOGIN user name", smtp_base64_encode (server.username), 334);
	}
      if (result == SMTP_SEND_OK)
	{
	  result = session.command ("AUTH LOGIN password", smtp_base64_encode (server.password), 235);
	}
      return result;
    }

  return session.command ("AUTH PLAIN", "AUTH PLAIN "
			  + smtp_base64_encode (std::string (1, '\0') + server.username
			      + std::string (1, '\0') + server.password), 235);
}

/*
 * smtp_send_mail () - send one mail through one SMTP server.
 *
 *   The session is: greeting (220), EHLO (250; HELO if EHLO is refused with
 *   5xx), AUTH when a user name is given, MAIL FROM (250), RCPT TO (250 or
 *   251), DATA (354), the message and "." (250), QUIT.
 *
 *   return: SMTP_SEND_OK when the server accepted the mail; otherwise what
 *           went wrong. SMTP_SEND_INVALID_ARGUMENT before any connection.
 *   server(in): the server, the timeout and how to authenticate
 *   mail(in): the mail
 *   detail(out): for the log: the step and the reply or error that ended
 *                the session; on success, the reply to the message. Never
 *                the password.
 */
T_SMTP_SEND_RESULT
smtp_send_mail (const T_SMTP_SERVER &server, const T_SMTP_MAIL &mail, std::string &detail)
{
  std::string sender, receiver, message;
  T_SMTP_SEND_RESULT result;

  detail.clear ();
  if (server.host.empty () || smtp_has_line_break (server.host) || server.port == 0 || server.timeout_ms <= 0)
    {
      detail = "invalid server, port or timeout";
      return SMTP_SEND_INVALID_ARGUMENT;
    }
  if (server.auth != SMTP_AUTH_LOGIN && server.auth != SMTP_AUTH_PLAIN)
    {
      detail = "invalid authentication type";
      return SMTP_SEND_INVALID_ARGUMENT;
    }
  if (server.username.find ('\0') != std::string::npos || server.password.find ('\0') != std::string::npos)
    {
      detail = "invalid user name or password";
      return SMTP_SEND_INVALID_ARGUMENT;
    }
  if (!smtp_mailbox_address (mail.sender, sender))
    {
      detail = "invalid sender: " + smtp_printable (mail.sender);
      return SMTP_SEND_INVALID_ARGUMENT;
    }
  if (!smtp_mailbox_address (mail.receiver, receiver))
    {
      detail = "invalid receiver: " + smtp_printable (mail.receiver);
      return SMTP_SEND_INVALID_ARGUMENT;
    }
  if (!smtp_build_message (mail, time (NULL), message))
    {
      detail = "invalid subject";
      return SMTP_SEND_INVALID_ARGUMENT;
    }

  smtp_session session (server.timeout_ms, detail);

  result = session.connect_to (server.host, server.port);
  if (result != SMTP_SEND_OK)
    {
      return result;
    }

  result = session.command ("greeting", "", 220);
  if (result == SMTP_SEND_OK)
    {
      result = session.command ("EHLO", "EHLO " + smtp_client_name (), 250);
      if (result == SMTP_SEND_REJECTED && session.last_code () / 100 == 5)
	{
	  result = session.command ("HELO", "HELO " + smtp_client_name (), 250);
	}
    }
  if (result == SMTP_SEND_OK && !server.username.empty ())
    {
      result = smtp_authenticate (session, server);
    }
  if (result == SMTP_SEND_OK)
    {
      result = session.command ("MAIL FROM", "MAIL FROM:<" + sender + ">", 250);
    }
  if (result == SMTP_SEND_OK)
    {
      result = session.command ("RCPT TO", "RCPT TO:<" + receiver + ">", 250, 251);
    }
  if (result == SMTP_SEND_OK)
    {
      result = session.command ("DATA", "DATA", 354);
    }
  if (result == SMTP_SEND_OK)
    {
      result = session.send_text (message);
      if (result != SMTP_SEND_OK)
	{
	  detail = "message: " + detail;
	}
    }
  if (result == SMTP_SEND_OK)
    {
      result = session.command ("end of message", ".", 250);
    }

  if (result == SMTP_SEND_OK || result == SMTP_SEND_REJECTED)
    {
      session.quit ();
    }
  return result;
}

/*
 * smtp_send_result_name () - a result of smtp_send_mail () as text, for the
 *   log.
 */
const char *
smtp_send_result_name (T_SMTP_SEND_RESULT result)
{
  switch (result)
    {
    case SMTP_SEND_OK:
      return "sent";
    case SMTP_SEND_INVALID_ARGUMENT:
      return "invalid argument";
    case SMTP_SEND_RESOLVE_FAILED:
      return "name resolution failed";
    case SMTP_SEND_CONNECT_FAILED:
      return "connection failed";
    case SMTP_SEND_TIMEOUT:
      return "timed out";
    case SMTP_SEND_CONNECTION_LOST:
      return "connection lost";
    case SMTP_SEND_REJECTED:
      return "rejected by the server";
    }
  return "unknown";
}
