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
 * test_smtp_client.cpp - unit tests of server/src/cm_smtp_client.cpp, the
 *   SMTP client that replaces jwSMTP.
 *
 *   The helpers (base64, mailbox address, message) are checked with fixed
 *   input. smtp_send_mail () is checked against a fake server: a child
 *   process listening on a loopback port that follows a script of expected
 *   client lines and replies, and exits non-zero if the client sent
 *   something else.
 *
 *   Build and run with run_unit_tests.sh in this directory; it needs no
 *   CUBRID build. Linux only (fork ()).
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <chrono>
#include <string>
#include <vector>

#include "cm_smtp_client.h"

static int failures = 0;
static int checks = 0;

static void
check (bool ok, const std::string &what)
{
  ++checks;
  if (!ok)
    {
      ++failures;
      printf ("FAIL: %s\n", what.c_str ());
    }
}

/* how the fake server reads the next client line */
typedef enum
{
  EXPECT_NOTHING,		/* send the reply only */
  EXPECT_EXACT,			/* the line must be the text */
  EXPECT_PREFIX,		/* the line must start with the text */
  EXPECT_MESSAGE		/* lines up to "."; the message must hold the text */
} T_EXPECT;

typedef enum
{
  AFTER_REPLY_CONTINUE,
  AFTER_REPLY_CLOSE,		/* close the connection */
  AFTER_REPLY_STALL		/* keep the connection open and send nothing */
} T_AFTER_REPLY;

struct fake_step
{
  T_EXPECT expect;
  std::string text;
  std::string reply;
  T_AFTER_REPLY after;
  int drip_ms;			/* > 0: send the reply one byte at a time, this far apart */
};

static fake_step
step (T_EXPECT expect, const std::string &text, const std::string &reply,
      T_AFTER_REPLY after = AFTER_REPLY_CONTINUE)
{
  fake_step s;

  s.expect = expect;
  s.text = text;
  s.reply = reply;
  s.after = after;
  s.drip_ms = 0;
  return s;
}

struct fake_server
{
  pid_t pid;
  unsigned short port;
};

/*
 * fake_read_line () - one line from the client, without CRLF; false on EOF.
 */
static bool
fake_read_line (int fd, std::string &line)
{
  char c;

  line.clear ();
  for (;;)
    {
      ssize_t n = read (fd, &c, 1);

      if (n <= 0)
	{
	  return false;
	}
      if (c == '\n')
	{
	  if (!line.empty () && line[line.size () - 1] == '\r')
	    {
	      line.erase (line.size () - 1);
	    }
	  return true;
	}
      line += c;
    }
}

/*
 * fake_run () - the child: accept one client and follow the script.
 */
static int
fake_run (int listen_fd, const std::vector<fake_step> &script)
{
  int fd = accept (listen_fd, NULL, NULL);

  if (fd < 0)
    {
      return 2;
    }
  for (size_t i = 0; i < script.size (); ++i)
    {
      const fake_step &s = script[i];
      std::string line;

      if (s.expect == EXPECT_EXACT || s.expect == EXPECT_PREFIX)
	{
	  if (!fake_read_line (fd, line))
	    {
	      fprintf (stderr, "fake server: step %zu: client closed, expected '%s'\n", i, s.text.c_str ());
	      return 1;
	    }
	  if ((s.expect == EXPECT_EXACT && line != s.text)
	      || (s.expect == EXPECT_PREFIX && line.compare (0, s.text.size (), s.text) != 0))
	    {
	      fprintf (stderr, "fake server: step %zu: got '%s', expected '%s'\n", i, line.c_str (), s.text.c_str ());
	      return 1;
	    }
	}
      else if (s.expect == EXPECT_MESSAGE)
	{
	  std::string message;

	  for (;;)
	    {
	      if (!fake_read_line (fd, line))
		{
		  fprintf (stderr, "fake server: client closed in the message\n");
		  return 1;
		}
	      if (line == ".")
		{
		  break;
		}
	      message += line + "\r\n";
	    }
	  if (message.find (s.text) == std::string::npos)
	    {
	      fprintf (stderr, "fake server: the message has no '%s'\n", s.text.c_str ());
	      return 1;
	    }
	}

      if (s.drip_ms > 0)
	{
	  for (size_t b = 0; b < s.reply.size (); ++b)
	    {
	      if (write (fd, s.reply.data () + b, 1) != 1)
		{
		  break;	/* the client gave up */
		}
	      usleep ((useconds_t) s.drip_ms * 1000);
	    }
	}
      else if (!s.reply.empty () && write (fd, s.reply.data (), s.reply.size ()) != (ssize_t) s.reply.size ())
	{
	  return 2;
	}
      if (s.after == AFTER_REPLY_CLOSE)
	{
	  break;
	}
      if (s.after == AFTER_REPLY_STALL)
	{
	  sleep (5);
	  break;
	}
    }
  close (fd);
  return 0;
}

/*
 * fake_listen () - a socket listening on a free loopback port.
 */
static int
fake_listen (int family, unsigned short &port)
{
  int fd = socket (family, SOCK_STREAM, 0);
  int on = 1;

  if (fd < 0)
    {
      return -1;
    }
  setsockopt (fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof (on));
  if (family == AF_INET6)
    {
      struct sockaddr_in6 a;
      socklen_t len = sizeof (a);

      memset (&a, 0, sizeof (a));
      a.sin6_family = AF_INET6;
      a.sin6_addr = in6addr_loopback;
      if (bind (fd, (struct sockaddr *) &a, sizeof (a)) != 0 || listen (fd, 4) != 0
	  || getsockname (fd, (struct sockaddr *) &a, &len) != 0)
	{
	  close (fd);
	  return -1;
	}
      port = ntohs (a.sin6_port);
    }
  else
    {
      struct sockaddr_in a;
      socklen_t len = sizeof (a);

      memset (&a, 0, sizeof (a));
      a.sin_family = AF_INET;
      a.sin_addr.s_addr = htonl (INADDR_LOOPBACK);
      if (bind (fd, (struct sockaddr *) &a, sizeof (a)) != 0 || listen (fd, 4) != 0
	  || getsockname (fd, (struct sockaddr *) &a, &len) != 0)
	{
	  close (fd);
	  return -1;
	}
      port = ntohs (a.sin_port);
    }
  return fd;
}

static bool
fake_start (int family, const std::vector<fake_step> &script, fake_server &server)
{
  int fd = fake_listen (family, server.port);

  if (fd < 0)
    {
      return false;
    }
  fflush (stdout);
  server.pid = fork ();
  if (server.pid == 0)
    {
      alarm (10);		/* never outlive a broken test */
      _exit (fake_run (fd, script));
    }
  close (fd);
  return server.pid > 0;
}

/*
 * fake_finish () - wait for the fake server; true if it saw what it
 *   expected.
 */
static bool
fake_finish (fake_server &server, bool kill_it = false)
{
  int status = 0;

  if (kill_it)
    {
      kill (server.pid, SIGKILL);
    }
  if (waitpid (server.pid, &status, 0) != server.pid)
    {
      return false;
    }
  return kill_it || (WIFEXITED (status) && WEXITSTATUS (status) == 0);
}

static T_SMTP_SERVER
make_server (const char *host, unsigned short port)
{
  T_SMTP_SERVER s;

  s.host = host;
  s.port = port;
  s.timeout_ms = 2000;
  s.auth = SMTP_AUTH_PLAIN;
  return s;
}

static T_SMTP_MAIL
make_mail (void)
{
  T_SMTP_MAIL m;

  m.sender = "CMS <from@example.com>";
  m.receiver = "to@example.com";
  m.subject = "Log Report for CUBRID";
  m.body = "<html><body>report</body></html>";
  m.body_type = SMTP_BODY_HTML;
  return m;
}

/* the script after the greeting and EHLO: MAIL, RCPT, DATA, message, QUIT */
static void
add_transaction (std::vector<fake_step> &script, const std::string &in_message)
{
  script.push_back (step (EXPECT_EXACT, "MAIL FROM:<from@example.com>", "250 ok\r\n"));
  script.push_back (step (EXPECT_EXACT, "RCPT TO:<to@example.com>", "250 ok\r\n"));
  script.push_back (step (EXPECT_EXACT, "DATA", "354 go ahead\r\n"));
  script.push_back (step (EXPECT_MESSAGE, in_message, "250 2.0.0 queued as 42\r\n"));
  script.push_back (step (EXPECT_EXACT, "QUIT", "221 bye\r\n"));
}

static std::string
base64_decode (const std::string &in)
{
  static const std::string table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  std::string out;
  unsigned int v = 0;
  int bits = 0;

  for (size_t i = 0; i < in.size () && in[i] != '='; ++i)
    {
      size_t p = table.find (in[i]);

      if (p == std::string::npos)
	{
	  continue;
	}
      v = (v << 6) | (unsigned int) p;
      bits += 6;
      if (bits >= 8)
	{
	  bits -= 8;
	  out += (char) ((v >> bits) & 0xff);
	}
    }
  return out;
}

static void
test_base64 (void)
{
  const char *vectors[][2] =
  {
    {"", ""}, {"f", "Zg=="}, {"fo", "Zm8="}, {"foo", "Zm9v"},
    {"foob", "Zm9vYg=="}, {"fooba", "Zm9vYmE="}, {"foobar", "Zm9vYmFy"}
  };

  for (size_t i = 0; i < sizeof (vectors) / sizeof (vectors[0]); ++i)
    {
      check (smtp_base64_encode (vectors[i][0]) == vectors[i][1], std::string ("base64 of '") + vectors[i][0] + "'");
    }
  check (smtp_base64_encode (std::string ("\xff\xfe\0", 3)) == "//4A", "base64 of bytes with NUL");
}

static void
test_mailbox (void)
{
  const char *valid[][2] =
  {
    {"a@b", "a@b"}, {"  user@example.com\t", "user@example.com"},
    {"CMS <from@example.com>", "from@example.com"}, {"<x@y>", "x@y"},
    {"\"Name, Jr\" <a.b+c@sub.example.com>", "a.b+c@sub.example.com"}
  };
  const char *invalid[] =
  {
    "", "   ", "a", "@b", "a@", "a b@c", "<>", "Name <a@b", "Name <a@b> x", "Name a@b>",
    "a@b\r\nRCPT TO:<x@y>", "a@b\n", "<a@b>\r"
  };
  std::string address;

  for (size_t i = 0; i < sizeof (valid) / sizeof (valid[0]); ++i)
    {
      check (smtp_mailbox_address (valid[i][0], address) && address == valid[i][1],
	     std::string ("mailbox '") + valid[i][0] + "'");
    }
  for (size_t i = 0; i < sizeof (invalid) / sizeof (invalid[0]); ++i)
    {
      check (!smtp_mailbox_address (invalid[i], address) && address.empty (),
	     std::string ("not a mailbox: '") + invalid[i] + "'");
    }
  check (!smtp_mailbox_address (std::string ("a@b\0c", 5), address), "not a mailbox: NUL");
}

static void
test_printable (void)
{
  std::string long_text (250, 'a');

  check (smtp_printable ("250 2.0.0 ok") == "250 2.0.0 ok", "printable text is kept");
  check (smtp_printable ("a@b>\r\nRCPT TO:<c@d") == "a@b>??RCPT TO:<c@d", "CR and LF become '?'");
  check (smtp_printable (std::string ("x\0y\x7f\xed\x95\x9c", 7)) == "x?y????", "NUL, DEL and UTF-8 become '?'");
  check (smtp_printable (long_text) == std::string (200, 'a') + "...", "long text is cut");
  check (smtp_printable (std::string (200, 'a')) == std::string (200, 'a'), "200 characters are not cut");
}

static void
test_server_address (void)
{
  struct
  {
    const char *text;
    const char *host;
    unsigned short port;
  } valid[] =
  {
    {"smtp.example.com", "smtp.example.com", 25},
    {"smtp.example.com:587", "smtp.example.com", 587},
    {"localhost", "localhost", 25},
    {"mail-1.EXAMPLE.org:2525", "mail-1.EXAMPLE.org", 2525},
    {"192.168.0.10", "192.168.0.10", 25},
    {"192.168.0.10:1", "192.168.0.10", 1},
    {"10.0.0.1:65535", "10.0.0.1", 65535},
    {"[::1]", "::1", 25},
    {"[2001:db8::25]:587", "2001:db8::25", 587},
    {"[::ffff:192.0.2.1]:25", "::ffff:192.0.2.1", 25},
    {"a", "a", 25}
  };
  struct
  {
    const char *text;
    T_SMTP_ADDRESS_PARSE result;
  } invalid[] =
  {
    {"", SMTP_ADDRESS_EMPTY},
    {":25", SMTP_ADDRESS_BAD_HOST},
    {"::1", SMTP_ADDRESS_BAD_HOST},
    {"2001:db8::25:587", SMTP_ADDRESS_BAD_HOST},
    {"[::1", SMTP_ADDRESS_BAD_HOST},
    {"[]:25", SMTP_ADDRESS_BAD_HOST},
    {"[::1]587", SMTP_ADDRESS_BAD_HOST},
    {"[fe80::1%eth0]:25", SMTP_ADDRESS_BAD_HOST},
    {"[192.168.0.1]:25", SMTP_ADDRESS_BAD_HOST},
    {"[smtp.example.com]", SMTP_ADDRESS_BAD_HOST},
    {"smtp example.com", SMTP_ADDRESS_BAD_HOST},
    {" smtp.example.com", SMTP_ADDRESS_BAD_HOST},
    {"smtp_1.example.com", SMTP_ADDRESS_BAD_HOST},
    {"-smtp.example.com", SMTP_ADDRESS_BAD_HOST},
    {"smtp-.example.com", SMTP_ADDRESS_BAD_HOST},
    {"smtp..example.com", SMTP_ADDRESS_BAD_HOST},
    {".example.com", SMTP_ADDRESS_BAD_HOST},
    {"example.com.", SMTP_ADDRESS_BAD_HOST},
    {"999.1.1.1", SMTP_ADDRESS_BAD_HOST},
    {"192.168.0", SMTP_ADDRESS_BAD_HOST},
    {"http://smtp.example.com", SMTP_ADDRESS_BAD_PORT},
    {"smtp.example.com\r\n", SMTP_ADDRESS_BAD_HOST},
    {"smtp.example.com:", SMTP_ADDRESS_BAD_PORT},
    {"smtp.example.com:0", SMTP_ADDRESS_BAD_PORT},
    {"smtp.example.com:65536", SMTP_ADDRESS_BAD_PORT},
    {"smtp.example.com:100000", SMTP_ADDRESS_BAD_PORT},
    {"smtp.example.com:-25", SMTP_ADDRESS_BAD_PORT},
    {"smtp.example.com:+25", SMTP_ADDRESS_BAD_PORT},
    {"smtp.example.com:25 ", SMTP_ADDRESS_BAD_PORT},
    {"smtp.example.com:2a", SMTP_ADDRESS_BAD_PORT},
    {"[::1]:", SMTP_ADDRESS_BAD_PORT},
    {"[::1]:70000", SMTP_ADDRESS_BAD_PORT}
  };
  std::string host;
  unsigned short port;

  for (size_t i = 0; i < sizeof (valid) / sizeof (valid[0]); ++i)
    {
      host = "unchanged";
      port = 0;
      check (smtp_parse_server_address (valid[i].text, host, port) == SMTP_ADDRESS_OK && host == valid[i].host
	     && port == valid[i].port, std::string ("server address '") + valid[i].text + "'");
    }
  for (size_t i = 0; i < sizeof (invalid) / sizeof (invalid[0]); ++i)
    {
      host = "unchanged";
      port = 7;
      check (smtp_parse_server_address (invalid[i].text, host, port) == invalid[i].result && host == "unchanged"
	     && port == 7, std::string ("not a server address: '") + invalid[i].text + "'");
    }

  /* the longest host name: 253 characters in labels of 63 */
  std::string longest = std::string (63, 'a') + "." + std::string (63, 'b') + "." + std::string (63, 'c') + "."
			+ std::string (61, 'd');
  check (longest.size () == 253 && smtp_parse_server_address (longest + ":25", host, port) == SMTP_ADDRESS_OK,
	 "host name of 253 characters");
  check (smtp_parse_server_address (longest + "d", host, port) == SMTP_ADDRESS_BAD_HOST, "host name of 254 characters");
  check (smtp_parse_server_address (std::string (64, 'a') + ".com", host, port) == SMTP_ADDRESS_BAD_HOST,
	 "label of 64 characters");
}

static void
set_tz (const char *tz)
{
  setenv ("TZ", tz, 1);
  tzset ();
}

static std::string
header_of (const std::string &message, const std::string &name)
{
  size_t pos = message.find ("\r\n" + name + ": ");

  if (message.compare (0, name.size () + 2, name + ": ") == 0)
    {
      pos = 0;
    }
  else if (pos == std::string::npos)
    {
      return "";
    }
  else
    {
      pos += 2;
    }
  return message.substr (pos, message.find ("\r\n", pos) - pos);
}

static void
test_message (void)
{
  T_SMTP_MAIL mail = make_mail ();
  std::string message, body, subject;
  size_t pos;

  set_tz ("UTC0");
  check (smtp_build_message (mail, 0, message), "message is built");
  check (header_of (message, "Date") == "Date: Thu, 01 Jan 1970 00:00:00 +0000", "Date in UTC");
  check (header_of (message, "From") == "From: CMS <from@example.com>", "From as given");
  check (header_of (message, "To") == "To: to@example.com", "To as given");
  check (header_of (message, "Subject") == "Subject: Log Report for CUBRID", "ASCII subject as it is");
  check (header_of (message, "Content-Type") == "Content-Type: text/html; charset=UTF-8", "HTML body");
  check (header_of (message, "Content-Transfer-Encoding") == "Content-Transfer-Encoding: base64", "base64 body");
  check (message.size () >= 2 && message.compare (message.size () - 2, 2, "\r\n") == 0, "message ends with CRLF");

  set_tz ("KST-9");
  smtp_build_message (mail, 0, message);
  check (header_of (message, "Date") == "Date: Thu, 01 Jan 1970 09:00:00 +0900", "Date east of UTC");
  set_tz ("EST5");
  smtp_build_message (mail, 0, message);
  check (header_of (message, "Date") == "Date: Wed, 31 Dec 1969 19:00:00 -0500", "Date west of UTC, the day before");
  set_tz ("IST-5:30");
  smtp_build_message (mail, 0, message);
  check (header_of (message, "Date") == "Date: Thu, 01 Jan 1970 05:30:00 +0530", "Date with half an hour");
  set_tz ("UTC0");

  /* the body: base64 lines of at most 76, decoding to the body */
  mail.body_type = SMTP_BODY_TEXT;
  mail.body = ".\r\n.\r\nline starting with a dot\r\n" + std::string (3000, 'x') + "\r\n\xed\x95\x9c\xea\xb8\x80";
  check (smtp_build_message (mail, 0, message), "text message is built");
  check (header_of (message, "Content-Type") == "Content-Type: text/plain; charset=UTF-8", "text body");
  pos = message.find ("\r\n\r\n") + 4;
  body.clear ();
  bool short_lines = true, no_dot_line = true;
  while (pos < message.size ())
    {
      size_t eol = message.find ("\r\n", pos);
      std::string line = message.substr (pos, eol - pos);

      short_lines = short_lines && line.size () <= 76;
      no_dot_line = no_dot_line && line != ".";
      body += line;
      pos = eol + 2;
    }
  check (short_lines, "body lines are at most 76 characters");
  check (no_dot_line, "no body line is a lone dot");
  check (base64_decode (body) == mail.body, "body decodes to the mail body");

  /* a non-ASCII subject: encoded words of at most 75 characters that do not split a character */
  std::string korean;
  for (int i = 0; i < 40; ++i)
    {
      korean += "\xed\x95\x9c";	/* U+D55C */
    }
  mail.subject = "CUBRID " + korean;
  smtp_build_message (mail, 0, message);
  pos = message.find ("Subject:");
  std::string decoded;
  bool word_ok = true;
  size_t words = 0;
  for (;;)
    {
      size_t begin = message.find ("=?UTF-8?B?", pos);
      size_t end;
      std::string raw;

      if (begin == std::string::npos || begin > message.find ("MIME-Version:"))
	{
	  break;
	}
      end = message.find ("?=", begin + 10);
      word_ok = word_ok && end - begin + 2 <= 75;
      raw = base64_decode (message.substr (begin + 10, end - begin - 10));
      word_ok = word_ok && !raw.empty () && ((unsigned char) raw[0] & 0xc0) != 0x80;
      decoded += raw;
      pos = end + 2;
      ++words;
    }
  check (words > 1, "a long non-ASCII subject is several encoded words");
  check (word_ok, "encoded words are short and start on a character");
  check (decoded == mail.subject, "encoded words decode to the subject");

  mail.subject = "a\r\nBcc: x@y";
  check (!smtp_build_message (mail, 0, message), "a subject with a line break is refused");
  mail = make_mail ();
  mail.sender = "\xea\xb4\x80\xeb\xa6\xac\xec\x9e\x90 <from@example.com>";
  smtp_build_message (mail, 0, message);
  check (header_of (message, "From") == "From: <from@example.com>", "non-ASCII name: From is the address");
}

/* run one session against a fake server */
static T_SMTP_SEND_RESULT
run_session (int family, const char *host, const std::vector<fake_step> &script, T_SMTP_SERVER server,
	     const T_SMTP_MAIL &mail, std::string &detail, bool &server_ok)
{
  fake_server fake;
  T_SMTP_SEND_RESULT result;

  if (!fake_start (family, script, fake))
    {
      server_ok = false;
      detail = "fake server did not start";
      return SMTP_SEND_INVALID_ARGUMENT;
    }
  server.host = host;
  server.port = fake.port;
  result = smtp_send_mail (server, mail, detail);
  server_ok = fake_finish (fake);
  return result;
}

static std::vector<fake_step>
greeting_and_ehlo (void)
{
  std::vector<fake_step> script;

  script.push_back (step (EXPECT_NOTHING, "", "220 fake.example.com ESMTP\r\n"));
  script.push_back (step (EXPECT_PREFIX, "EHLO ", "250-fake.example.com\r\n250-AUTH LOGIN PLAIN\r\n250 8BITMIME\r\n"));
  return script;
}

static void
test_send (void)
{
  T_SMTP_SERVER server = make_server ("127.0.0.1", 0);
  T_SMTP_MAIL mail = make_mail ();
  std::vector<fake_step> script;
  std::string detail;
  bool server_ok;
  T_SMTP_SEND_RESULT result;

  /* no authentication */
  script = greeting_and_ehlo ();
  add_transaction (script, "Subject: Log Report for CUBRID");
  result = run_session (AF_INET, "127.0.0.1", script, server, mail, detail, server_ok);
  check (result == SMTP_SEND_OK && server_ok, "send without authentication: " + detail);
  check (detail.find ("250 2.0.0 queued as 42") != std::string::npos, "detail of success is the last reply");

  /* host name */
  result = run_session (AF_INET, "localhost", script, server, mail, detail, server_ok);
  check (result == SMTP_SEND_OK && server_ok, "send to localhost: " + detail);

  /* AUTH LOGIN */
  server.username = "user";
  server.password = "secret";
  server.auth = SMTP_AUTH_LOGIN;
  script = greeting_and_ehlo ();
  script.push_back (step (EXPECT_EXACT, "AUTH LOGIN", "334 VXNlcm5hbWU6\r\n"));
  script.push_back (step (EXPECT_EXACT, smtp_base64_encode ("user"), "334 UGFzc3dvcmQ6\r\n"));
  script.push_back (step (EXPECT_EXACT, smtp_base64_encode ("secret"), "235 2.7.0 ok\r\n"));
  add_transaction (script, "To: to@example.com");
  result = run_session (AF_INET, "127.0.0.1", script, server, mail, detail, server_ok);
  check (result == SMTP_SEND_OK && server_ok, "send with AUTH LOGIN: " + detail);

  /* AUTH LOGIN with an empty password: the answer to the second 334 is an empty line */
  server.password.clear ();
  script = greeting_and_ehlo ();
  script.push_back (step (EXPECT_EXACT, "AUTH LOGIN", "334 VXNlcm5hbWU6\r\n"));
  script.push_back (step (EXPECT_EXACT, smtp_base64_encode ("user"), "334 UGFzc3dvcmQ6\r\n"));
  script.push_back (step (EXPECT_EXACT, "", "235 2.7.0 ok\r\n"));
  add_transaction (script, "To: to@example.com");
  result = run_session (AF_INET, "127.0.0.1", script, server, mail, detail, server_ok);
  check (result == SMTP_SEND_OK && server_ok, "send with AUTH LOGIN and an empty password: " + detail);
  server.password = "secret";

  /* AUTH PLAIN */
  server.auth = SMTP_AUTH_PLAIN;
  script = greeting_and_ehlo ();
  script.push_back (step (EXPECT_EXACT, "AUTH PLAIN " + smtp_base64_encode (std::string ("\0user\0secret", 12)),
			  "235 2.7.0 ok\r\n"));
  add_transaction (script, "From: CMS <from@example.com>");
  result = run_session (AF_INET, "127.0.0.1", script, server, mail, detail, server_ok);
  check (result == SMTP_SEND_OK && server_ok, "send with AUTH PLAIN: " + detail);

  /* authentication refused: rejected, and the detail holds no password */
  script = greeting_and_ehlo ();
  script.push_back (step (EXPECT_PREFIX, "AUTH PLAIN ", "535 5.7.8 authentication failed\r\n"));
  script.push_back (step (EXPECT_EXACT, "QUIT", "221 bye\r\n"));
  result = run_session (AF_INET, "127.0.0.1", script, server, mail, detail, server_ok);
  check (result == SMTP_SEND_REJECTED && server_ok, "refused authentication is rejected: " + detail);
  check (detail.find ("AUTH PLAIN") != std::string::npos && detail.find ("535") != std::string::npos,
	 "detail names the step and the reply: " + detail);
  check (detail.find ("secret") == std::string::npos
	 && detail.find (smtp_base64_encode (std::string ("\0user\0secret", 12))) == std::string::npos,
	 "detail holds no password");
  server.username.clear ();
  server.password.clear ();

  /* EHLO refused: HELO */
  script.clear ();
  script.push_back (step (EXPECT_NOTHING, "", "220 old ready\r\n"));
  script.push_back (step (EXPECT_PREFIX, "EHLO ", "502 5.5.1 command not implemented\r\n"));
  script.push_back (step (EXPECT_PREFIX, "HELO ", "250 old\r\n"));
  add_transaction (script, "MIME-Version: 1.0");
  result = run_session (AF_INET, "127.0.0.1", script, server, mail, detail, server_ok);
  check (result == SMTP_SEND_OK && server_ok, "HELO after EHLO is refused: " + detail);

  /* receiver refused */
  script = greeting_and_ehlo ();
  script.push_back (step (EXPECT_EXACT, "MAIL FROM:<from@example.com>", "250 ok\r\n"));
  script.push_back (step (EXPECT_EXACT, "RCPT TO:<to@example.com>", "550 5.1.1 no such user\r\n"));
  script.push_back (step (EXPECT_EXACT, "QUIT", "221 bye\r\n"));
  result = run_session (AF_INET, "127.0.0.1", script, server, mail, detail, server_ok);
  check (result == SMTP_SEND_REJECTED && server_ok, "refused receiver is rejected: " + detail);
  check (detail == "RCPT TO: server replied 550 5.1.1 no such user", "detail of a refused receiver: " + detail);

  /* greeting 554 */
  script.clear ();
  script.push_back (step (EXPECT_NOTHING, "", "554 no service\r\n"));
  script.push_back (step (EXPECT_EXACT, "QUIT", "221 bye\r\n"));
  result = run_session (AF_INET, "127.0.0.1", script, server, mail, detail, server_ok);
  check (result == SMTP_SEND_REJECTED && server_ok, "greeting 554 is rejected: " + detail);

  /* closed after the greeting */
  script.clear ();
  script.push_back (step (EXPECT_NOTHING, "", "220 ready\r\n"));
  script.push_back (step (EXPECT_PREFIX, "EHLO ", "", AFTER_REPLY_CLOSE));
  result = run_session (AF_INET, "127.0.0.1", script, server, mail, detail, server_ok);
  check (result == SMTP_SEND_CONNECTION_LOST && server_ok, "closed connection is lost: " + detail);

  /* not SMTP */
  script.clear ();
  script.push_back (step (EXPECT_NOTHING, "", "HTTP/1.1 400 Bad Request\r\n", AFTER_REPLY_CLOSE));
  result = run_session (AF_INET, "127.0.0.1", script, server, mail, detail, server_ok);
  check (result == SMTP_SEND_CONNECTION_LOST && server_ok, "a reply that is not SMTP: " + detail);

  /* no greeting: timed out within the timeout */
  {
    fake_server fake;
    std::chrono::steady_clock::time_point start;
    long long elapsed_ms;

    script.clear ();
    script.push_back (step (EXPECT_NOTHING, "", "", AFTER_REPLY_STALL));
    check (fake_start (AF_INET, script, fake), "fake server for the timeout");
    server.host = "127.0.0.1";
    server.port = fake.port;
    server.timeout_ms = 300;
    start = std::chrono::steady_clock::now ();
    result = smtp_send_mail (server, mail, detail);
    elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds> (std::chrono::steady_clock::now () - start).count ();
    fake_finish (fake, true);
    check (result == SMTP_SEND_TIMEOUT, "silent server times out: " + detail);
    check (elapsed_ms >= 250 && elapsed_ms < 2000, "timeout is the given one");
    server.timeout_ms = 2000;
  }

  /*
   * a reply sent a byte at a time, each well within the timeout: the reply as
   * a whole must still end at the timeout, not when the server stops
   */
  {
    fake_server fake;
    std::chrono::steady_clock::time_point start;
    long long elapsed_ms;
    fake_step drip = step (EXPECT_NOTHING, "", "220" + std::string (60, '-'), AFTER_REPLY_CLOSE);

    drip.drip_ms = 50;		/* 3 s for the whole reply */
    script.clear ();
    script.push_back (drip);
    check (fake_start (AF_INET, script, fake), "fake server for the slow reply");
    server.host = "127.0.0.1";
    server.port = fake.port;
    server.timeout_ms = 300;
    start = std::chrono::steady_clock::now ();
    result = smtp_send_mail (server, mail, detail);
    elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds> (std::chrono::steady_clock::now () - start).count ();
    fake_finish (fake, true);
    check (result == SMTP_SEND_TIMEOUT, "a reply a byte at a time times out: " + detail);
    check (elapsed_ms >= 250 && elapsed_ms < 1500, "the timeout is for the whole reply");
    server.timeout_ms = 2000;
  }

  /* connection refused: a port nobody listens on */
  {
    unsigned short port;
    int fd = fake_listen (AF_INET, port);

    close (fd);
    server.host = "127.0.0.1";
    server.port = port;
    result = smtp_send_mail (server, mail, detail);
    check (result == SMTP_SEND_CONNECT_FAILED, "refused connection: " + detail);
  }

  /* name resolution */
  server.host = "cms-smtp-test.invalid";
  server.port = 25;
  result = smtp_send_mail (server, mail, detail);
  check (result == SMTP_SEND_RESOLVE_FAILED, "unknown host: " + detail);

  /* IPv6, if the loopback has it */
  {
    unsigned short port;
    int fd = fake_listen (AF_INET6, port);

    if (fd < 0)
      {
	printf ("skip: no IPv6 loopback\n");
      }
    else
      {
	close (fd);
	script = greeting_and_ehlo ();
	add_transaction (script, "Subject:");
	result = run_session (AF_INET6, "::1", script, server, mail, detail, server_ok);
	check (result == SMTP_SEND_OK && server_ok, "send over IPv6: " + detail);
      }
  }
}

static void
test_invalid_argument (void)
{
  T_SMTP_MAIL mail = make_mail ();
  T_SMTP_SERVER server;
  std::string detail;
  unsigned short port;
  int fd = fake_listen (AF_INET, port);
  struct pollfd pfd;

  server = make_server ("127.0.0.1", port);
  mail.receiver = "to@example.com>\r\nRCPT TO:<other@example.com";
  check (smtp_send_mail (server, mail, detail) == SMTP_SEND_INVALID_ARGUMENT, "injected receiver is refused");
  mail = make_mail ();
  mail.sender = "";
  check (smtp_send_mail (server, mail, detail) == SMTP_SEND_INVALID_ARGUMENT, "empty sender is refused");
  mail = make_mail ();
  mail.subject = "x\nDATA";
  check (smtp_send_mail (server, mail, detail) == SMTP_SEND_INVALID_ARGUMENT, "subject with a line break");
  mail = make_mail ();
  server.username = std::string ("a\0b", 3);
  check (smtp_send_mail (server, mail, detail) == SMTP_SEND_INVALID_ARGUMENT, "user name with NUL");
  server.username.clear ();
  server.auth = (T_SMTP_AUTH) 3;
  check (smtp_send_mail (server, mail, detail) == SMTP_SEND_INVALID_ARGUMENT, "unknown authentication type");
  server = make_server ("", port);
  check (smtp_send_mail (server, mail, detail) == SMTP_SEND_INVALID_ARGUMENT, "empty host");
  server = make_server ("127.0.0.1", 0);
  check (smtp_send_mail (server, mail, detail) == SMTP_SEND_INVALID_ARGUMENT, "port 0");
  server = make_server ("127.0.0.1", port);
  server.timeout_ms = 0;
  check (smtp_send_mail (server, mail, detail) == SMTP_SEND_INVALID_ARGUMENT, "timeout 0");

  memset (&pfd, 0, sizeof (pfd));
  pfd.fd = fd;
  pfd.events = POLLIN;
  check (fd >= 0 && poll (&pfd, 1, 100) == 0, "invalid arguments make no connection");
  close (fd);
}

int
main (void)
{
  signal (SIGPIPE, SIG_IGN);

  test_base64 ();
  test_mailbox ();
  test_printable ();
  test_server_address ();
  test_message ();
  test_invalid_argument ();
  test_send ();

  printf ("%d of %d checks failed\n", failures, checks);
  return (failures == 0) ? 0 : 1;
}
