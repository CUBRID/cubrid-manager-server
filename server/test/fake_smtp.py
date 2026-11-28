#
#
# Copyright 2016 CUBRID Corporation
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
#
#

"""Fake SMTP servers for the sendmail cases (task_sendmail_check).

Each server listens on a fixed loopback port and behaves one way, so that a
case picks the behavior by the port it puts in cm.conf smtp_server:

    ACCEPT_PORT  answers like a mail server and accepts every mail, with or
                 without AUTH LOGIN / AUTH PLAIN (any user and password);
                 on 127.0.0.1 and, when the host has it, on ::1
    REJECT_PORT  greets with 554 and refuses the session
    SILENT_PORT  accepts the connection and never answers
    CLOSED_PORT  nobody listens: the connection is refused

Only Python 3 standard library, as rocky81 (Python 3.6) has it.
connections () counts the connections all servers accepted, so that a case
can check that a request connected, or did not.
"""

import socket
import socketserver
import threading

ACCEPT_PORT = 25251
REJECT_PORT = 25252
SILENT_PORT = 25253
CLOSED_PORT = 25254

# How long the silent server holds a connection: longer than the 30 s the
# client waits for a reply.
SILENT_HOLD_SEC = 40

_lock = threading.Lock()
_connections = 0
_servers = []


def connections():
    """The number of connections the fake servers accepted so far."""
    with _lock:
        return _connections


def _count_connection():
    global _connections
    with _lock:
        _connections += 1


class _Handler(socketserver.StreamRequestHandler):
    behavior = "accept"
    timeout = SILENT_HOLD_SEC + 5

    def send(self, text):
        self.wfile.write(text.encode("ascii"))
        self.wfile.flush()

    def read_line(self):
        line = self.rfile.readline(4096)
        if not line:
            return None
        return line.decode("utf-8", "replace").rstrip("\r\n")

    def handle(self):
        _count_connection()
        try:
            if self.behavior == "silent":
                # Hold the connection open without a greeting; the client
                # gives up first.
                self.request.settimeout(SILENT_HOLD_SEC)
                try:
                    self.request.recv(1)
                except OSError:
                    pass
                return
            if self.behavior == "reject":
                self.send("554 5.3.2 fake server refuses service\r\n")
                if self.read_line() is not None:
                    self.send("221 bye\r\n")
                return
            self.converse()
        except OSError:
            pass

    def converse(self):
        self.send("220 fake.smtp.test ESMTP\r\n")
        while True:
            line = self.read_line()
            if line is None:
                return
            verb = line.split(" ", 1)[0].upper()
            if verb in ("EHLO", "HELO"):
                self.send("250-fake.smtp.test\r\n250 AUTH LOGIN PLAIN\r\n")
            elif verb == "AUTH" and line.upper().startswith("AUTH LOGIN"):
                self.send("334 VXNlcm5hbWU6\r\n")
                if self.read_line() is None:
                    return
                self.send("334 UGFzc3dvcmQ6\r\n")
                if self.read_line() is None:
                    return
                self.send("235 2.7.0 accepted\r\n")
            elif verb == "AUTH":
                self.send("235 2.7.0 accepted\r\n")
            elif verb in ("MAIL", "RCPT", "RSET", "NOOP"):
                self.send("250 ok\r\n")
            elif verb == "DATA":
                self.send("354 end with .\r\n")
                while True:
                    data = self.read_line()
                    if data is None:
                        return
                    if data == ".":
                        break
                self.send("250 2.0.0 queued\r\n")
            elif verb == "QUIT":
                self.send("221 bye\r\n")
                return
            else:
                self.send("502 5.5.2 not implemented\r\n")


class _Server(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True


class _Server6(_Server):
    address_family = socket.AF_INET6


def _start(server_class, host, port, behavior):
    handler = type("_Handler_%s" % behavior, (_Handler,), {"behavior": behavior})
    server = server_class((host, port), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    _servers.append(server)


def start():
    """Start the servers. Returns a list of warnings (no IPv6 loopback).

    Raises OSError when a port of 127.0.0.1 is taken, so that the run stops
    rather than testing someone else's server.
    """
    warnings = []
    _start(_Server, "127.0.0.1", ACCEPT_PORT, "accept")
    _start(_Server, "127.0.0.1", REJECT_PORT, "reject")
    _start(_Server, "127.0.0.1", SILENT_PORT, "silent")
    try:
        _start(_Server6, "::1", ACCEPT_PORT, "accept")
    except OSError as e:
        warnings.append("no fake SMTP server on [::1]:%d (%s); the IPv6 case "
                        "fails" % (ACCEPT_PORT, e))
    return warnings


def stop():
    """Stop the servers started by start()."""
    while _servers:
        server = _servers.pop()
        server.shutdown()
        server.server_close()
