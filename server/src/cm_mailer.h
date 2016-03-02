// Note that the only valid version of the GPL as far as jwSMTP
// is concerned is v2 of the license (ie v2, not v2.2 or v3.x or whatever),
// unless explicitly otherwise stated.
//
// This file is part of the jwSMTP library.
//
//  jwSMTP library is free software; you can redistribute it and/or modify
//  it under the terms of the GNU General Public License as published by
//  the Free Software Foundation; version 2 of the License.
//
//  jwSMTP library is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//  GNU General Public License for more details.
//
//  You should have received a copy of the GNU General Public License
//  along with jwSMTP library; if not, write to the Free Software
//  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
//
// jwSMTP library
//   http://johnwiggins.net
//   smtplib@johnwiggins.net
//
#ifndef __CM_MAILER_H__
#define __CM_MAILER_H__
#ifdef WIN32
// std::vector<std::string> This gives this warning in VC..
// bloody annoying, there is a way round it according to MS.
// The debugger basically cannot browse anything with a name
// longer than 256 characters, "get with the template program MS".
#pragma warning( disable : 4786 )
// tell the linker which libraries to find functions in
#include <winsock2.h>
#else
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
typedef int SOCKET; // get round windows definitions.
#endif
#include <fstream>
#include <sstream>   // ostrstream
#include <ctime>     // for localtime
#include <cassert>
#include <string>
#include <vector>

namespace jwsmtp {

// added the B64 to all members of the enum for SunOS (thanks Ken Weinert)
enum BASE64
{
	B64_A, B64_B, B64_C, B64_D, B64_E, B64_F, B64_G, B64_H, B64_I, B64_J, B64_K, B64_L, B64_M, B64_N, B64_O, B64_P, B64_Q, B64_R, B64_S, B64_T, B64_U, B64_V, B64_W, B64_X, B64_Y, B64_Z,
	B64_a, B64_b, B64_c, B64_d, B64_e, B64_f, B64_g, B64_h, B64_i, B64_j, B64_k, B64_l, B64_m, B64_n, B64_o, B64_p, B64_q, B64_r, B64_s, B64_t, B64_u, B64_v, B64_w, B64_x, B64_y, B64_z,
	B64_0, B64_1, B64_2, B64_3, B64_4, B64_5, B64_6, B64_7, B64_8, B64_9, plus, slash, padding
};

char getbase64character(const char& in)
{
	switch(in) {
		case B64_A:
			return 'A';
		case B64_B:
			return 'B';
		case B64_C:
			return 'C';
		case B64_D:
			return 'D';
		case B64_E:
			return 'E';
		case B64_F:
			return 'F';
		case B64_G:
			return 'G';
		case B64_H:
			return 'H';
		case B64_I:
			return 'I';
		case B64_J:
			return 'J';
		case B64_K:
			return 'K';
		case B64_L:
			return 'L';
		case B64_M:
			return 'M';
		case B64_N:
			return 'N';
		case B64_O:
			return 'O';
		case B64_P:
			return 'P';
		case B64_Q:
			return 'Q';
		case B64_R:
			return 'R';
		case B64_S:
			return 'S';
		case B64_T:
			return 'T';
		case B64_U:
			return 'U';
		case B64_V:
			return 'V';
		case B64_W:
			return 'W';
		case B64_X:
			return 'X';
		case B64_Y:
			return 'Y';
		case B64_Z:
			return 'Z';
		case B64_a:
			return 'a';
		case B64_b:
			return 'b';
		case B64_c:
			return 'c';
		case B64_d:
			return 'd';
		case B64_e:
			return 'e';
		case B64_f:
			return 'f';
		case B64_g:
			return 'g';
		case B64_h:
			return 'h';
		case B64_i:
			return 'i';
		case B64_j:
			return 'j';
		case B64_k:
			return 'k';
		case B64_l:
			return 'l';
		case B64_m:
			return 'm';
		case B64_n:
			return 'n';
		case B64_o:
			return 'o';
		case B64_p:
			return 'p';
		case B64_q:
			return 'q';
		case B64_r:
			return 'r';
		case B64_s:
			return 's';
		case B64_t:
			return 't';
		case B64_u:
			return 'u';
		case B64_v:
			return 'v';
		case B64_w:
			return 'w';
		case B64_x:
			return 'x';
		case B64_y:
			return 'y';
		case B64_z:
			return 'z';
		case B64_0:
			return '0';
		case B64_1:
			return '1';
		case B64_2:
			return '2';
		case B64_3:
			return '3';
		case B64_4:
			return '4';
		case B64_5:
			return '5';
		case B64_6:
			return '6';
		case B64_7:
			return '7';
		case B64_8:
			return '8';
		case B64_9:
			return '9';
		case plus:
			return '+';
		case slash:
			return '/';
		case padding:
			return '=';
	}
	return '\0'; // ?????? yikes
}

std::vector<char> base64encode(const std::vector<char>& input, const bool returns = true) {
   std::vector<char> output;

   // add a newline (SMTP demands less than 1000 characters in a message line).
   long count = 0;
   for(std::vector<char>::size_type p = 0; p < input.size(); p+=3) {
      output.push_back(getbase64character((input[p] & 0xFC) >> 2));
      ++count;

      if(p+1 < input.size()) {
         output.push_back(getbase64character(((input[p] & 0x03) <<4) | ((input[p+1] & 0xF0) >> 4)));
         ++count;
      }
      if(p+2 < input.size()) {
         output.push_back(getbase64character(((input[p+1] & 0x0F) <<2) | ((input[p+2] & 0xC0) >>6)));
         output.push_back(getbase64character((input[p+2] & 0x3F)));
         ++count;
      }

      if(p+1 == input.size()) {
         output.push_back(getbase64character(((input[p] & 0x03) <<4)));
      }
      else if(p+2 == input.size()) {
         output.push_back(getbase64character(((input[p+1] & 0x0F) <<2)));
      }

      if(returns) {
         // 79 characters on a line.
         if(count > 75) {
            output.push_back('\r');
            output.push_back('\n');
            count = 0;
         }
      }
   }

   int pad(input.size() % 3);
   if(pad) {
      if(pad == 1)
         pad = 2;
      else
         pad = 1;
   }
   for(int i = 0; i < pad; ++i)
      output.push_back('=');

   return output;
}

std::string base64encode(const std::string& input, const bool returns = true) {
   std::vector<char> in, out;
   for(std::string::const_iterator it = input.begin(); it != input.end(); ++it) {
      in.push_back(*it);
   }
   out = base64encode(in, returns);
   std::string ret;
   for(std::vector<char>::const_iterator it1 = out.begin(); it1 != out.end(); ++it1) {
      ret += *it1;
   }
   return ret;
}

struct SOCKADDR_IN {
  sockaddr_in ADDR; // we are wrapping this structure.

  // this is bad as we just assume that the address "addr" is valid here.
  // need a real check and set ok appropriately
//  SOCKADDR_IN(sockaddr_in addr):ADDR(addr), ok(true) {}

  SOCKADDR_IN(const std::string& address, unsigned short port, short family = AF_INET) {
    ADDR.sin_port = port;
    ADDR.sin_family = family;
#ifdef WIN32
    ADDR.sin_addr.S_un.S_addr = inet_addr(address.c_str());
    ok = (ADDR.sin_addr.S_un.S_addr != INADDR_NONE);
#else
    ok = (inet_aton(address.c_str(), &ADDR.sin_addr));
#endif
  }

  SOCKADDR_IN(const SOCKADDR_IN& addr) {
    ADDR = addr.ADDR;
    ok = addr.ok;
  }
  SOCKADDR_IN operator = (const SOCKADDR_IN& addr) {
    ADDR = addr.ADDR;
    ok = addr.ok;
    return *this;
  }

  operator bool() const {return ok;}

  operator const sockaddr_in () const {
    return ADDR;
  }
  operator const sockaddr () const {
    sockaddr addr;
    std::copy((char*)&ADDR, (char*)&ADDR + sizeof(ADDR), (char*)&addr);
    return addr;
  }

  size_t get_size() const {return sizeof(ADDR);}
  char* get_sin_addr() {
     return (char*)&ADDR.sin_addr;
  }
  void set_port(unsigned short newport) {ADDR.sin_port = newport;}
  void set_ip(const std::string& newip) {
#ifdef WIN32
    ADDR.sin_addr.S_un.S_addr = inet_addr(newip.c_str());
    ok = (ADDR.sin_addr.S_un.S_addr != INADDR_NONE);
#else
    ok = (inet_aton(newip.c_str(), &ADDR.sin_addr));
#endif
  }
  void zeroaddress() {
#ifdef WIN32
      ADDR.sin_addr.S_un.S_addr = 0;
#else
      ADDR.sin_addr.s_addr = 0;
#endif
  }

private:
  bool ok;
};


bool Connect(SOCKET sockfd, const SOCKADDR_IN& addr) {
#ifdef WIN32
   return bool(connect(sockfd, (sockaddr*)&addr, (int) addr.get_size()) != SOCKET_ERROR);
#else
   return bool(connect(sockfd, (sockaddr*)&addr, addr.get_size()) == 0);
#endif
}

bool Socket(SOCKET& s, int domain, int type, int protocol) {
   s = socket(AF_INET, type, protocol);
#ifdef WIN32
   return bool(s != INVALID_SOCKET);
#else
   return bool(s != -1);
#endif
}

bool Send(int &CharsSent, SOCKET s, const char *msg, size_t len, int flags) {
   CharsSent = send(s, msg, (int) len, flags);
#ifdef WIN32
	return bool((CharsSent != SOCKET_ERROR));
#else
	return bool((CharsSent != -1));
#endif
}

bool Recv(int &CharsRecv, SOCKET s, char *buf, size_t len, int flags) {
   CharsRecv = recv(s, buf, (int) len, flags);
#ifdef WIN32
	return bool((CharsRecv != SOCKET_ERROR));
#else
	return bool((CharsRecv != -1));
#endif
}

// just wrap the call to shutdown the connection on a socket
// this way I don't have to call it this way everywhere.
void Closesocket(const SOCKET& s) {
#ifdef WIN32
	closesocket(s);
#else
	close(s);
#endif
}

// This does nothing on unix.
// for windoze only, to initialise networking, snore
void initNetworking() {
#ifdef WIN32
	class socks
	{
	public:
		bool init() {

			WORD wVersionRequested;
			WSADATA wsaData;

			wVersionRequested = MAKEWORD( 2, 0 );
			int ret = WSAStartup( wVersionRequested, &wsaData);
			if(ret)
				return false;
			initialised = true;
			return true;
		}
		bool IsInitialised() const {return initialised;}
		socks():initialised(false){init();}
		~socks()
		{
			if(initialised)
				shutdown();
		}
	private:
		void shutdown(){WSACleanup();}
		bool initialised;
	};
	static socks s;
#endif
}




class mailer
{
public:
   // if MXLookup is true:
   //    'server' is a nameserver to lookup an MX record by.
   // if MXLookup is false.
   //    'server' is an SMTP server which will be attempted directly for mailing
   // if an IP address is not found, either MX record or direct to SMTP server,
   // an attempt will be made to send mail directly to the server in the mail address.
   // e.g. mail to fred@somewhere.com will have a connection attempt made directly to:
   //      somewhere.com  (which is probably wrong and therefore will still fail)
   mailer(const char* TOaddress, const char* FROMaddress,
         const char* Subject, const std::vector<char>& Message,
         const char* server = "127.0.0.1"/*default to localhost*/,
         unsigned short Port = SMTP_PORT, // default SMTP port
         bool MXLookup = true) : type(LOGIN),
                               subject(Subject),
                               server(getserveraddress(TOaddress)),
                               nameserver(server),
                               port(htons(Port)), // make the 'port' network byte order.
                               lookupMXRecord(MXLookup),
                               auth(false) {
   // Parse the email addresses into an Address structure.
   setsender(FROMaddress);
   addrecipient(TOaddress);
   setmessage(Message);

   initNetworking(); // in win32 init networking, else just does nothin'
};

   mailer(const char* TOaddress, const char* FROMaddress,
         const char* Subject, const char* Message,
         const char* server = "127.0.0.1"/*default to localhost*/,
         unsigned short Port = SMTP_PORT, // default SMTP port
         bool MXLookup = true) : type(LOGIN),
                               subject(Subject),
                               server(getserveraddress(TOaddress)),
                               nameserver(server),
                               port(htons(Port)), // make the 'port' network byte order.
                               lookupMXRecord(MXLookup),
                               auth(false) {
   // Parse the email addresses into an Address structure.
   setsender(FROMaddress);
   addrecipient(TOaddress);
   setmessage(Message);

   initNetworking(); // in win32 init networking, else just does nothin'
};

   // defaults to SMTP_PORT & no MX lookup.
   //  now we can do:
   //         mailer m;                          // mail an smtp server direct.
   //         mailer m2(true);                   // use MX lookup.
   //         mailer m2(false, weirdportnumber); // SMTP to a non standard port.
   mailer(bool MXLookup = false, unsigned short Port = SMTP_PORT):
      type(LOGIN),
      port(htons(Port)),
      lookupMXRecord(MXLookup),
      auth(false) {
   initNetworking(); // in win32 init networking, else just does nothin'
};

   ~mailer() {};

   // call this operator to have the mail mailed.
   // This is to facilitate using multiple threads
   // i.e. using boost::thread.     (see http://www.boost.org)
   //
   // e.g.
   //    mailer mail(args...);
   //    boost::thread thrd(mail); // operator()() implicitly called.
   //    thrd.join(); // if needed.
   //
   // or:
   //    mailer mail(args...);
   //    mail.operator()();
   void operator()() {
   returnstring = ""; // clear out any errors from previous use

   if(!recipients.size()) {
      returnstring = "451 Requested action aborted: local error who am I mailing";
      return;
   }
   if(!fromAddress.address.length()) {
      returnstring = "451 Requested action aborted: local error who am I";
      return;
   }
   if(!nameserver.length()) {
      returnstring = "451 Requested action aborted: local error no SMTP/name server/smtp server";
      return;
   }

   std::vector<SOCKADDR_IN> adds;
   if(lookupMXRecord) {
      if(!gethostaddresses(adds)) {
         // error!! we are dead.
         returnstring = "451 Requested action aborted: No MX records ascertained";
         return;
      }
   }
   else { // connect directly to an SMTP server.
      SOCKADDR_IN addr(nameserver, port, AF_INET);
      hostent* host = 0;
      if(addr) {
         host = gethostbyaddr(addr.get_sin_addr(), sizeof(addr.ADDR.sin_addr), AF_INET);
      }
      else
         host = gethostbyname(nameserver.c_str());
      if(!host) {
         returnstring = "451 Requested action aborted: local error in processing";
         return; // error!!!
      }
      //memcpy(addr.get_sin_addr(), host->h_addr, host->h_length);
      std::copy(host->h_addr_list[0], host->h_addr_list[0] + host->h_length, addr.get_sin_addr());
      adds.push_back(addr);
   }

   SOCKET s;
   if(!Socket(s, AF_INET, SOCK_STREAM, 0)) {
      returnstring =  "451 Requested action aborted: socket function error";
      return;
   }

   if(!adds.size()) { // oops
      returnstring = "451 Requested action aborted: No MX records ascertained";
   }

   const std::string OK("250");
   const std::vector<char> smtpheader(makesmtpmessage());
   const int buffsize(1024);
   char buff[buffsize] = "";

   for(std::vector<SOCKADDR_IN>::const_iterator address = adds.begin();
            address < adds.end(); ++address) {
      if(!Connect(s, *address)) {
         returnstring = "554 Transaction failed: server connect error.";
         continue;
      }

      // 220 the server line returned here
      int len1;
      if(!Recv(len1, s, buff, buffsize -1, 0)) {
         returnstring = "554 Transaction failed: server connect response error.";
         continue;
      }

      // get our hostname to pass to the smtp server
      char hn[buffsize] = "";
      if(gethostname(hn, buffsize)) {
         // no local hostname!!! make one up
         strcpy(hn, "flibbletoot");
      }
      std::string commandline(std::string("EHLO ") + hn + std::string("\r\n"));
      // say hello to the server

      if(!Send(len1, s, commandline.c_str(), commandline.length(), 0)) {
         returnstring = "554 Transaction failed: EHLO send";
         continue;
      }
      if(!Recv(len1, s, buff, buffsize -1, 0)) {
         returnstring = "554 Transaction failed: EHLO receipt";
         continue;
      }

      buff[len1] = '\0';
      std::string greeting = returnstring = buff;
      if(returnstring.substr(0,3) != OK) {
         if(auth) {
            // oops no ESMTP but using authentication no go bail out!
            returnstring = "554 possibly trying to use AUTH without ESMTP server, ERROR!";
            continue;
         }
         // maybe we only do non extended smtp
         // send HELO instead.
         commandline[0] = 'H';
         commandline[1] = 'E';
         if(!Send(len1, s, commandline.c_str(), commandline.length(), 0)) {
            returnstring = "554 Transaction failed: HELO send";
            continue;
         }
         if(!Recv(len1, s, buff, buffsize -1, 0)) {
            returnstring = "554 Transaction failed: HELO receipt";
            continue;
         }
         buff[len1] = '\0';

         returnstring = buff;
         if(returnstring.substr(0,3) != OK) {
            // we must issue a quit even on an error.
            // in keeping with the rfc's
            if(Send(len1, s, "QUIT\r\n", 6, 0)) {
               char dummy[buffsize];
               Recv(len1, s, dummy, buffsize -1, 0);
            }
            Closesocket(s);
            // don't know what went wrong here if we are connected!!
            // we continue because maybe we have more than 1 server to connect to.
            continue;
         }
      }

      if(auth)
         if(!authenticate(greeting, s))
            continue; // try the next server, you never know!!

      // MAIL
      // S: MAIL FROM:<Smith@Alpha.ARPA>
      // R: 250 OK
      // e.g. "MAIL FROM:<someone@somewhere.com>\r\n"
      // or   "MAIL FROM: John Wiggins <someone@somewhere.com>"
      commandline = "MAIL FROM:<" + fromAddress.address + ">\r\n";
      if(!Send(len1, s, commandline.c_str(), commandline.length(), 0)) {
         returnstring = "554 MAIL FROM sending error";
         continue;
      }

      if(!Recv(len1, s, buff, buffsize -1, 0)) {
         returnstring = "554 MAIL FROM receipt error";
         continue;
      }

      buff[len1] = '\0';
      returnstring = buff;
      if(returnstring.substr(0,3) != OK) {
         // we must issue a quit even on an error.
         // in keeping with the rfc's
         if(Send(len1, s, "QUIT\r\n", 6, 0)) {
            char dummy[buffsize];
            Recv(len1, s, dummy, buffsize -1, 0);
         }
         Closesocket(s);
         // don't know what went wrong here if we are connected!!
         // we continue because maybe we have more than 1 server to connect to.
         continue;
      }

      for(recipient_const_iter recip = recipients.begin(); recip < recipients.end(); ++recip) {
         // RCPT

         // S: RCPT TO:<Jones@Beta.ARPA>
         // R: 250 OK
         commandline = "RCPT TO: <" + (*recip).first.address + ">\r\n";
         // S: RCPT TO:<Green@Beta.ARPA>
         // R: 550 No such user here
         //
         // S: RCPT TO:<Brown@Beta.ARPA>
         // R: 250 OK
         if(!Send(len1, s, commandline.c_str(), commandline.length(), 0)) {
            returnstring = "554 Transaction failed";
            continue;
         }
         if(!Recv(len1, s, buff, buffsize -1, 0)) {
            returnstring = buff;
            continue;
         }
         buff[len1] = '\0';
         returnstring = buff;
         if(returnstring.substr(0,3) != OK) {
            // This particular recipient does not exist!
            // not strictly an error as we may have more than one recipient
            // we should have an error vector e.g.
            // vector<pair<string address, string error> > errs;
            // errs.push_back(make_pair(recip->first, returnstring));
            //
            // we then need a function to return this vector.
            // e.g. const vector<pair<string address, string error> >& getrecipienterrors();
            continue;
         }
      }

      // DATA

      // S: DATA
      // R: 354 Start mail input; end with <CRLF>.<CRLF>
      // S: Blah blah blah...
      // S: ...etc. etc. etc.

      // S: <CRLF>.<CRLF>
      // R: 250 OK
      if(!Send(len1, s, "DATA\r\n", 6, 0)) {
         returnstring = "554 DATA send error";
         continue;
      }
      if(!Recv(len1, s, buff, buffsize -1, 0)) {
         returnstring = "554 DATA, server response error";
         continue;
      }
      buff[len1] = '\0';
      returnstring = buff;
      if(returnstring.substr(0,3) != "354") {
         // we must issue a quit even on an error.
         // in keeping with the rfc's

         if(Send(len1, s, "QUIT\r\n", 6, 0)) {
            char dummy[buffsize];
            Recv(len1, s, dummy, buffsize -1, 0);
         }
         Closesocket(s);
         continue;
      }
      // Sending the email
      /*if(!Send(len1, s, smtpheader.c_str(), smtpheader.length(), 0)) {*/
      if(!Send(len1, s, &smtpheader[0], smtpheader.size(), 0)) {
         returnstring = "554 DATA, server response error (actual send)";
         continue;
      }
      if(!Recv(len1, s, buff, buffsize -1, 0)) {
         returnstring = "554 DATA, server response error (actual send)";
         continue;
      }

      // The server should give us a 250 reply if the mail was delivered okay
      buff[len1] = '\0';
      returnstring = buff;
      if(returnstring.substr(0,3) != OK) {
         // we must issue a quit even on an error.
         // in keeping with the rfc's
         if(Send(len1, s, "QUIT\r\n", 6, 0)) {
            char dummy[buffsize];
            Recv(len1, s, dummy, buffsize -1, 0);
         }
         Closesocket(s);
         continue;
      }
      // hang up the connection
      if(Send(len1, s, "QUIT\r\n", 6, 0)) {
         char dummy[buffsize];
         Recv(len1, s, dummy, buffsize -1, 0);
      }

      // Let the server give us our 250 reply.
      //buff[len1] = '\0';
      //returnstring = buff;

      // for future reference the server is meant to give a 221 response to a quit.
      if(returnstring.substr(0,3) != "221") {
         // maybe will use this later
      }
      Closesocket(s); // disconnect

      // Let the server give us our 250 reply.
      // don't continue as we have delivered the mail
      // at this point just leave. all done
      //returnstring = "250 Requested mail action okay, completed";
      break;
   }
};
   void send() {
   operator()();
};

   // attach a file to the mail. (MIME 1.0)
   // returns false if !filename.length() or
   // the file could not be opened for reading...etc.
   bool attach(const std::string& filename) {
   if(!filename.length()) // do silly checks.
      return false;

   std::ifstream file(filename.c_str(), std::ios::binary | std::ios::in);
   if(!file)
      return false;

   std::vector<char> filedata;
   char c = file.get();
   for(; file.good(); c = file.get()) {
      if(file.bad())
         break;
      filedata.push_back(c);
   }

   filedata = base64encode(filedata);

   std::string fn(filename);
   std::string::size_type p = fn.find_last_of('/');
   if(p == std::string::npos)
      p = fn.find_last_of('\\');
   if(p != std::string::npos) {
      p +=1; // get past folder delimeter
      fn = fn.substr(p, fn.length() - p);
   }

   attachments.push_back(std::make_pair(filedata, fn));

   return true;
};

   // remove an attachment from the list of attachments.
   // returns false if !filename.length() or
   // the file is not attached or there are no attachments.
   bool removeattachment(const std::string& filename) {
   if(!filename.length()) // do silly checks.
      return false;

   if(!attachments.size())
      return false;

   std::string fn(filename);
   std::string::size_type p = fn.find_last_of('/');
   if(p == std::string::npos)
      p = fn.find_last_of('\\');
   if(p != std::string::npos) {
      p +=1; // get past folder delimeter
      fn = fn.substr(p, fn.length() - p);
   }
   // fn is now what is stored in the attachments pair as the second parameter
   // i.e.  it->second == fn
   std::vector<std::pair<std::vector<char>, std::string> >::iterator it;
   for(it = attachments.begin(); it < attachments.end(); ++it) {
      if((*it).second == fn) {
         attachments.erase(it);
         return true;
      }
   }
   return false;
};

   // Set a new message (replacing the old)
   // will return false and not change the message if newmessage is empty.
   bool setmessage(const std::string& newmessage) {
   if(!newmessage.length())
      return false;

   message.clear(); // erase the old message
   for (std::string::size_type i = 0; i < newmessage.length(); ++i)
      message.push_back(newmessage[i]);

   checkRFCcompat();

   return true;
};
   bool setmessage(const std::vector<char>& newmessage) {
   if(!newmessage.size())
      return false;

   message = newmessage;

   checkRFCcompat();

   return true;
};

   // Set a new HTML message (replacing the old)
   // will return false and not change the message if newmessage is empty.
   bool setmessageHTML(const std::string& newmessage)  {
   if(!newmessage.length())
      return false;

   messageHTML.clear(); // erase the old message
   for (std::string::size_type i = 0; i < newmessage.length(); ++i)
      messageHTML.push_back(newmessage[i]);
   messageHTML = base64encode(messageHTML);

   return true;
};
   bool setmessageHTML(const std::vector<char>& newmessage)  {
   if(!newmessage.size())
      return false;

   messageHTML = base64encode(newmessage);

   return true;
};
   // use a file for the data
   bool setmessageHTMLfile(const std::string& filename) {
   if(!filename.length())
      return false;

   std::ifstream file(filename.c_str(), std::ios::binary | std::ios::in);
   if(!file)
      return false;
   std::vector<char> filedata;
   char c = file.get();
   for(; file.good(); c = file.get()) {
      if(file.bad())
         break;
      filedata.push_back(c);
   }

   messageHTML = base64encode(filedata);

   return true;
};

   // Set a new Subject for the mail (replacing the old)
   // will return false if newSubject is empty.
   bool setsubject(const std::string& newSubject) {
   if(!newSubject.length())
      return false;

   subject = newSubject;
   return true;
};

   // sets the nameserver or smtp server to connect to
   // dependant on the constructor call, i.e. whether
   // 'lookupMXRecord' was set to false or true.
   // (see constructor comment for details)
   bool setserver(const std::string& nameserver_or_smtpserver) {
   if(!nameserver_or_smtpserver.length())
      return false;

   nameserver = nameserver_or_smtpserver;
   return true;
};

   // sets the senders address (fromAddress variable)
   bool setsender(const std::string& newsender) {
   if(!newsender.length())
      return false;

   Address newaddress(parseaddress(newsender));

   fromAddress = newaddress;
   return true;
};

   // add a recipient to the recipient list. (maximum allowed recipients 100).
   // returns true if the address could be added to the
   // recipient list, otherwise false.
   // recipient_type must be in the range mailer::TO -> mailer::BCC if
   // not recipient_type defaults to BCC (blind copy), see const enum below.
   bool addrecipient(const std::string& newrecipient, short recipient_type = TO /*CC, BCC*/) {
   // SMTP only allows 100 recipients max at a time.
   // rfc821
   if(recipients.size() >= 100) // == would be fine, but let's be stupid safe
      return false;

   if(newrecipient.length()) {
      // If there are no recipients yet
      // set the server address for MX queries
      if(!recipients.size()) {
         server = getserveraddress(newrecipient);
      }

      Address newaddress = parseaddress(newrecipient);

      if(recipient_type > Bcc || recipient_type < TO)
         recipient_type = Bcc; // default to blind copy on error(hidden is better)

      recipients.push_back(std::make_pair(newaddress, recipient_type));
      return true;
   }
   return false;
};

   // remove a recipient from the recipient list.
   // returns true if the address could be removed from the
   // recipient list, otherwise false.
   bool removerecipient(const std::string& recipient) {
   if(recipient.length()) { // there is something to remove
      std::vector<std::pair<Address, short> >::iterator it(recipients.begin());
      for(; it < recipients.end(); ++it) {
         if((*it).first.address == recipient) {
            recipients.erase(it);
            return true;
         }
      }
      // fall through as we did not find this recipient
   }
   return false;
};

   // clear all recipients from the recipient list.
   void clearrecipients() {
   recipients.clear();
};

   // clear all attachments from the mail.
   void clearattachments() {
   attachments.clear();
};

   // clear all recipients, message, attachments, errors.
   // does not reset the name/smtp server (use setserver for this)
   // does not set the senders address (use setsender for this)
   void reset() {
   recipients.clear();
   attachments.clear();
   // fromAddress = ""; // assume the same sender.
   // if this is to be changed use the setserver function to change it.
   // nameserver = ""; // we don't do this as the same server is probably used!!
   // leave auth type alone.
   // leave username password pair alone.
   server = "";
   message.clear();
   messageHTML.clear();
   returnstring = ""; // clear out any errors from previous use
};

   // returns the return code sent by the smtp server or a local error.
   // this is the only way to find if there is an error in processing.
   // if the mail is sent correctly this string will begin with 250
   // see smtp RFC 821 section 4.2.2 for response codes.
   const std::string& response() const {
   return returnstring;
};

   // Constants
   // in unix we have to have a named object.
   const static enum {TO, Cc, Bcc, SMTP_PORT = 25, DNS_PORT = 53} consts;

   // what type of authentication are we using.
   // (if using authentication that is).
   enum authtype {LOGIN = 1, PLAIN} type;

   // set the authentication type
   // currently LOGIN or PLAIN only.
   // The default login type is LOGIN, set in the constructor
   void authtype(const enum authtype Type) {
   assert(Type == LOGIN || Type == PLAIN);
   type = Type;
};

   // set the username for authentication.
   // If this function is called with a non empty string
   // jwSMTP will try to use authentication.
   // To not use authentication after this, call again
   // with the empty string e.g.
   //    mailerobject.username("");
   void username(const std::string& User) {
   auth = (User.length() != 0);
   user = User;
};
   // set the password for authentication
   void password(const std::string& Pass) {
   pass = Pass;
};

private:
   // create a header with current message and attachments.
   std::vector<char> makesmtpmessage() const {
   std::string sender(fromAddress.address);
   if(sender.length()) {
      std::string::size_type pos(sender.find("@"));
      if(pos != std::string::npos) { //found the server beginning
         sender = sender.substr(0, pos);
      }
   }

   std::vector<char> ret;
   std::string headerline;
   if(fromAddress.name.length()) {
      headerline = "From: " + fromAddress.address + " (" + fromAddress.name + ") \r\n"
                   "Reply-To: " + fromAddress.address + "\r\n";
      ret.insert(ret.end(), headerline.begin(), headerline.end());
   }
   else {
      headerline = "From: " + fromAddress.address + "\r\n"
                   "Reply-To: " + fromAddress.address + "\r\n";
      ret.insert(ret.end(), headerline.begin(), headerline.end());
   }
   headerline.clear(); // clearout our temp variable

   // add the recipients to the header
   std::vector<std::string> to, cc, bcc;
   for(recipient_const_iter recip = recipients.begin(); recip < recipients.end(); ++recip) {
      if(recip->second == TO) {
         to.push_back(recip->first.address);
      }
      else if(recip->second == Cc) {
         cc.push_back(recip->first.address);
      }
      else if(recip->second == Bcc) {
         bcc.push_back(recip->first.address);
      }
   }
   vec_str_const_iter it; // instead of making three on the stack, just one (stops VC whining too)
   // next section adds To: Cc: Bcc: lines to the header
   int count = (int) to.size();
   if(count)
      headerline += "To: ";
   for(it = to.begin(); it < to.end(); ++it) {
      headerline += *it;
      if(count > 1 && ((it + 1) < to.end()) )
         headerline += ",\r\n "; // must add a space after the comma
      else
         headerline += "\r\n";
   }
   count = (int) cc.size();
   if(count)
      headerline += "Cc: ";
   for(it = cc.begin(); it < cc.end(); ++it) {
      headerline += *it;
      if(count > 1 && ((it + 1) < cc.end()) )
         headerline += ",\r\n "; // must add a space after the comma
      else
         headerline += "\r\n";
   }

   // Remove insertion of the Bcc line into the header, I should never have done this, oopsy
   //
   //count = bcc.size();
   //if(count)
   //   headerline += "Bcc: ";
   //for(it = bcc.begin(); it < bcc.end(); ++it) {
   //   headerline += *it;
   //   if(count > 1 && ((it + 1) < bcc.end()) )
   //      headerline += ",\r\n "; // must add a space after the comma
   //   else
   //      headerline += "\r\n";
   //}
   ret.insert(ret.end(), headerline.begin(), headerline.end());
   // end adding To: Cc: Bcc: lines to the header

   const std::string boundary("bounds=_NextP_0056wi_0_8_ty789432_tp");
   bool MIME(false);
   if(attachments.size() || messageHTML.size())
      MIME = true;

   if(MIME) { // we have attachments
      // use MIME 1.0
      headerline = "MIME-Version: 1.0\r\n"
                 "Content-Type: multipart/mixed;\r\n"
                 "\tboundary=\"" + boundary + "\"\r\n";
      ret.insert(ret.end(), headerline.begin(), headerline.end());
      headerline.clear();
   }

   ///////////////////////////////////////////////////////////////////////////
   // add the current time.
   // format is
   //     Date: 05 Jan 93 21:22:07
   //     Date: 05 Jan 93 21:22:07 -0500
   //     Date: 27 Oct 81 15:01:01 PST        (RFC 821 example)
   time_t t;
   time(&t);
   char timestring[128] = "";
   const char * timeformat = "Date: %d %b %y %H:%M:%S %Z";
   if(strftime(timestring, 127, timeformat, localtime(&t))) { // got the date
      headerline = timestring;
      headerline += "\r\n";
      ret.insert(ret.end(), headerline.begin(), headerline.end());
   }
   ///////////////////////////////////////////////////////////////////////////
   // add the subject
   headerline = "Subject: " + subject + "\r\n\r\n";
   ret.insert(ret.end(), headerline.begin(), headerline.end());

   ///////////////////////////////////////////////////////////////////////////
   //
   // everything else added is the body of the email message.
   //
   ///////////////////////////////////////////////////////////////////////////

   if(MIME) {
      headerline = "This is a MIME encapsulated message\r\n\r\n";
      headerline += "--" + boundary + "\r\n";
      if(!messageHTML.size()) {
         // plain text message first.
         headerline += "Content-type: text/plain; charset=iso-8859-1\r\n"
                       "Content-transfer-encoding: 7BIT\r\n\r\n";

         ret.insert(ret.end(), headerline.begin(), headerline.end());
         ret.insert(ret.end(), message.begin(), message.end());
         headerline = "\r\n\r\n--" + boundary + "\r\n";
      }
      else { // make it multipart/alternative as we have html
         const std::string innerboundary("inner_jfd_0078hj_0_8_part_tp");
         headerline += "Content-Type: multipart/alternative;\r\n"
                       "\tboundary=\"" + innerboundary + "\"\r\n";

         // need the inner boundary starter.
         headerline += "\r\n\r\n--" + innerboundary + "\r\n";

         // plain text message first.
         headerline += "Content-type: text/plain; charset=iso-8859-1\r\n"
                       "Content-transfer-encoding: 7BIT\r\n\r\n";
         ret.insert(ret.end(), headerline.begin(), headerline.end());
         ret.insert(ret.end(), message.begin(), message.end());
         headerline = "\r\n\r\n--" + innerboundary + "\r\n";
         ///////////////////////////////////
         // Add html message here!
         headerline += "Content-type: text/html; charset=iso-8859-1\r\n"
                       "Content-Transfer-Encoding: base64\r\n\r\n";

         ret.insert(ret.end(), headerline.begin(), headerline.end());
         ret.insert(ret.end(), messageHTML.begin(), messageHTML.end());
         headerline = "\r\n\r\n--" + innerboundary + "--\r\n";

         // end the boundaries if there are no attachments
         if(!attachments.size())
            headerline += "\r\n--" + boundary + "--\r\n";
         else
            headerline += "\r\n--" + boundary + "\r\n";
         ///////////////////////////////////
      }
      ret.insert(ret.end(), headerline.begin(), headerline.end());
      headerline.clear();

      // now add each attachment.
      for(vec_pair_char_str_const_iter it1 = attachments.begin();
                                       it1 != attachments.end(); ++ it1) {
         if(it1->second.length() > 3) { // long enough for an extension
            std::string typ(it1->second.substr(it1->second.length()-4, 4));
            if(typ == ".gif") { // gif format presumably
               headerline += "Content-Type: image/gif;\r\n";
            }
            else if(typ == ".jpg" || typ == "jpeg") { // j-peg format presumably
               headerline += "Content-Type: image/jpg;\r\n";
            }
            else if(typ == ".txt") { // text format presumably
               headerline += "Content-Type: plain/txt;\r\n";
            }
            else if(typ == ".bmp") { // windows bitmap format presumably
               headerline += "Content-Type: image/bmp;\r\n";
            }
            else if(typ == ".htm" || typ == "html") { // hypertext format presumably
               headerline += "Content-Type: plain/htm;\r\n";
            }
            else if(typ == ".png") { // portable network graphic format presumably
               headerline += "Content-Type: image/png;\r\n";
            }
            else if(typ == ".exe") { // application
               headerline += "Content-Type: application/X-exectype-1;\r\n";
            }
            else { // add other types
               // everything else
               headerline += "Content-Type: application/X-other-1;\r\n";
            }
         }
         else {
            // default to don't know
            headerline += "Content-Type: application/X-other-1;\r\n";
         }

         headerline += "\tname=\"" + it1->second + "\"\r\n";
         headerline += "Content-Transfer-Encoding: base64\r\n";
         headerline += "Content-Disposition: attachment; filename=\"" + it1->second + "\"\r\n\r\n";
         ret.insert(ret.end(), headerline.begin(), headerline.end());
         headerline.clear();

         ret.insert(ret.end(), it1->first.begin(), it1->first.end());

         // terminate the message with the boundary + "--"
         if((it1 + 1) == attachments.end())
            headerline += "\r\n\r\n--" + boundary + "--\r\n";
         else
            headerline += "\r\n\r\n--" + boundary + "\r\n";
         ret.insert(ret.end(), headerline.begin(), headerline.end());
			headerline.clear();
      }
   }
   else // just a plain text message only
      ret.insert(ret.end(), message.begin(), message.end());

   // end the data in the message.
   headerline = "\r\n.\r\n";
   ret.insert(ret.end(), headerline.begin(), headerline.end());

   return ret;
};

   // this breaks a message line up to be less than 1000 chars per line.
   // keeps words intact also --- rfc821
   // Check line returns are in the form "\r\n"
   // (qmail balks otherwise, i.e. LAME server)
   // also if a period is on a line by itself add a period
   //   stops prematurely ending the mail before whole message is sent.
   void checkRFCcompat(){
   // Check the line breaks.
   std::vector<char>::iterator it;
   for(it = message.begin(); it != message.end(); ++it) {
      // look for \n add \r before if not there. Pretty lame but still.
      // haven't thought of a better way yet.
      if(*it == '\n') {
         if(it == message.begin()) {
            it = message.insert(it, '\r');
            ++it; // step past newline
            continue;
         }
         if((*(it -1) != '\r') ) {
            // add a return before '\n'
            it = message.insert(it, '\r');
            ++it; // step past newline
         }
      }
   }

   // if we get a period on a line by itself
   // add another period to stop the server ending the mail prematurely.
   // ( suggested by david Irwin )
   if(message.size() == 1) {
      if(*(message.begin()) == '.')
         message.push_back('.');
   }
   else if(message.size() == 2) {
      if(*(message.begin()) == '.') {
         it = message.begin();
         it = message.insert(it, '.');
      }
   }
   else {
      if(*(message.begin()) == '.') {
         it = message.begin();
         it = message.insert(it, '.');
      }
      for(it = message.begin()+2; it != message.end(); ++it) {
         // follow the rfc. Add '.' if the first character on a line is '.'
         if(*it == '\n') {
            if( ((it + 1) != message.end()) && (*(it +1) == '.') ) {
               it = message.insert(it + 1, '.');
               ++it; // step past
            }
         }
      }
   }

   // don't do anything if we are not longer than a 1000 characters
   if(message.size() < 1000)
      return;

   // now we have checked line breaks
   // check line lengths.
   int count(1);
   for(it = message.begin(); it < message.end(); ++it, ++count) {
      if(*it == '\r') {
         count = 0; // reset for a new line.
         ++it; // get past newline
         continue;
      }
      else if(count >= 998) {
         ++it;
         if(*it != ' ') { // we are not in a word!!
            // it should never get to message.begin() because we
            // start at least 998 chars into the message!
            // Also, assume a word isn't bigger than 997 chars! (seems reasonable)
            std::vector<char>::iterator pos = it;
            for(int j = 0; j < 997; ++j, --pos) {
               if(*pos == ' ') {
                  it = ++pos; // get past the space.
                  break;
               }
            }
         }
         if(it < message.end())
            it = message.insert(it, '\r');
         ++it;
         if(it < message.end())
            it = message.insert(it, '\n');
         count = 0; // reset for a new line.
      }
   }
   count=1; // reset the count
   if(messageHTML.size()) {
      for(it = messageHTML.begin(); it < messageHTML.end(); ++it, ++count) {
         if(*it == '\r') {
            count = 0; // reset for a new line.
            ++it; // get past newline
            continue;
         }
         else if(count >= 998) {
            ++it;
            if(*it != ' ') { // we are in a word!!
               // it should never get to message.begin() because we
               // start at least 998 chars into the message!
               // Also, assume a word isn't bigger than 997 chars! (seems reasonable)
               std::vector<char>::iterator pos = it;
               for(int j = 0; j < 997; ++j, --pos) {
                  if(*pos == ' ') {
                     it = ++pos; // get past the space.
                     break;
                  }
               }
            }
            if(it < messageHTML.end())
               it = messageHTML.insert(it, '\r');
            ++it;
            if(it < messageHTML.end())
               it = messageHTML.insert(it, '\n');
            count = 0; // reset for a new line.
         }
      }
   }
};

   // helper function.
   // returns the part of the string toaddress after the @ symbol.
   // i.e. the 'toaddress' is an email address eg. someone@somewhere.com
   // this function returns 'somewhere.com'
   std::string getserveraddress(const std::string& toaddress) const {
   if(toaddress.length()) {
      std::string::size_type pos(toaddress.find("@"));
      if(pos != std::string::npos) { //found the server beginning
         if(++pos < toaddress.length())
            return toaddress.substr(pos, toaddress.length()- pos);
      }
   }
   return "";
};

   // Does the work of getting MX records for the server returned by 'getserveraddress'
   // will use the dns server passed to this's constructor in 'nameserver'
   // or if MXlookup is false in the constuctor, will return an address
   // for the server that 'getserveraddress' returns.
   // returns false on failure, true on success
   bool gethostaddresses(std::vector<SOCKADDR_IN>& adds) {
   adds.clear(); // be safe in case of my utter stupidity

   SOCKADDR_IN addr(nameserver, htons(DNS_PORT), AF_INET);

   hostent* host = 0;
   if(addr)
      host = gethostbyaddr(addr.get_sin_addr(), sizeof(addr.ADDR.sin_addr), AF_INET);
   else
      host = gethostbyname(nameserver.c_str());

   if(!host) { // couldn't get to dns, try to connect directly to 'server' instead.
      ////////////////////////////////////////////////////////////////////////////////
      // just try to deliver mail directly to "server"
      // as we didn't get an MX record.
      // addr.sin_family = AF_INET;
      addr = SOCKADDR_IN(server, port);
      addr.ADDR.sin_port = port; // smtp port!! 25
      if(addr) {
         host = gethostbyaddr(addr.get_sin_addr(), sizeof(addr.ADDR.sin_addr), AF_INET);
      }
      else
         host = gethostbyname(server.c_str());

      if(!host) {
         returnstring = "550 Requested action not taken: mailbox unavailable";
         return false; // error!!!
      }

      //memcpy((char*)&addr.sin_addr, host->h_addr, host->h_length);
      std::copy(host->h_addr_list[0], host->h_addr_list[0] + host->h_length, addr.get_sin_addr());
      adds.push_back(addr);

      return true;
   }
   else
      //memcpy((char*)&addr.sin_addr, host->h_addr, host->h_length);
      std::copy(host->h_addr_list[0], host->h_addr_list[0] + host->h_length, addr.get_sin_addr());

   SOCKET s;
   if(!Socket(s, AF_INET, SOCK_DGRAM, 0)) {
      returnstring = "451 Requested action aborted: socket function error";
      return false;
   }

   if(!Connect(s, addr)) {
      returnstring = "451 Requested action aborted: dns server unavailable";
      return false; // dns connection unavailable
   }

   // dnsheader info         id    flags   num queries
   unsigned char dns[512] = {1,1,   1,0,      0,1,      0,0, 0,0, 0,0};
   int dnspos = 12; // end of dns header
   std::string::size_type stringpos(0);
   std::string::size_type next(server.find("."));
   if(next != std::string::npos) { // multipart name e.g. "aserver.somewhere.net"
      while(stringpos < server.length()) {
         std::string part(server.substr(stringpos, next-stringpos));
         dns[dnspos] = (unsigned char) part.length();
         ++dnspos;
         for(std::string::size_type i = 0; i < part.length(); ++i, ++dnspos) {
            dns[dnspos] = part[i];
         }

         stringpos = ++next;
         next = server.find(".", stringpos);
         if(next == std::string::npos) {
            part = server.substr(stringpos, server.length() - stringpos);
            dns[dnspos] = (unsigned char) part.length();
            ++dnspos;
            for(std::string::size_type i = 0; i < part.length(); ++i, ++dnspos) {
               dns[dnspos] = part[i];
            }
            break;
         }
      }
   }
   else { // just a single part name. e.g. "aserver"
      dns[dnspos] = (unsigned char) server.length();
      ++dnspos;

      for(std::string::size_type i = 0; i < server.length(); ++i, ++dnspos) {
         dns[dnspos] = server[i];
      }
   }
   // in case the server string has a "." on the end
   if(server[server.length()-1] == '.')
      dns[dnspos] = 0;
   else
      dns[dnspos++] = 0;

   // add the class & type
   dns[dnspos++] = 0;
   dns[dnspos++] = 15;  // MX record.

   dns[dnspos++] = 0;
   dns[dnspos++] = 1;

   // used to have MSG_DONTROUTE this breaks obviously if you are not
   // running a local nameserver and using it (as I used to do so I didn't
   // notice until now, oops)
   int ret;
   if(!Send(ret, s, (char*)dns, dnspos, 0)) {
      returnstring = "451 Requested action aborted: server seems to have disconnected.";
      Closesocket(s); // clean up
      return false;
   }
   if(Recv(ret, s, (char*)dns, 512, 0)) {
      Closesocket(s);
      // now parse the data sent back from the dns for MX records
      if(dnspos > 12) { // we got more than a dns header back
         unsigned short numsitenames = ((unsigned short)dns[4]<<8) | dns[5];
         unsigned short numanswerRR = ((unsigned short)dns[6]<<8) | dns[7];
         unsigned short numauthorityRR = ((unsigned short)dns[8]<<8) | dns[9];
         unsigned short numadditionalRR = ((unsigned short)dns[10]<<8) | dns[11];

         if(!(dns[3] & 0x0F)) { // check for an error
            // int auth((dns[2] & 0x04)); // AA bit. the nameserver has given authoritive answer.
            int pos = 12; // start after the header.

            std::string questionname;
            if(numsitenames) {
               parsename(pos, dns, questionname);
               pos += 4; // move to the next RR
            }

            // This gives this warning in VC.
            // bloody annoying, there is a way round it according to microsoft.
            // The debugger basically cannot browse anything with a name
            // longer than 256 characters, "get with the template program MS".
            // #pragma warning( disable : 4786 )
            // #pragma warning( default : 4786 )
            std::vector<std::string> names;
            in_addr address;
            std::string name;
            // VC++ incompatability scoping
            // num should be able to be declared in every for loop here
            // not in VC
            int num = 0;
            for(; num < numanswerRR; ++num) {
               name = "";
               parseRR(pos, dns, name, address);
               if(name.length())
                  names.push_back(name);
            }
            for(num = 0; num < numauthorityRR; ++num) {
               name = "";
               parseRR(pos, dns, name, address);
               if(name.length())
                  names.push_back(name);
            }
            for(num = 0; num < numadditionalRR; ++num) {
               name = "";
               parseRR(pos, dns, name, address);
               if(name.length())
                  names.push_back(name);
            }

            // now get all the MX records IP addresess
            addr.ADDR.sin_family = AF_INET;
            addr.ADDR.sin_port = port; // smtp port!! 25
            hostent* host = 0;
            for(vec_str_const_iter it = names.begin(); it < names.end(); ++it) {
               host = gethostbyname(it->c_str());
               if(!host) {
                  addr.zeroaddress();
                  continue; // just skip it!!!
               }
               std::copy(host->h_addr_list[0], host->h_addr_list[0] + host->h_length, addr.get_sin_addr());
               adds.push_back(addr);
            }
            // got the addresses
            return true;
         }
      }
   }
   else
      Closesocket(s);
   // what are we doing here!!
   return false;
};

   // Parses a dns Resource Record (see TCP/IP illustrated, STEVENS, page 194)
   bool parseRR(int& pos, const unsigned char dns[], std::string& name, in_addr& address) {
   if(pos < 12) // didn,t get more than a header.
      return false;
   if(pos > 512) // oops.
      return false;

   int len = dns[pos];
   if(len >= 192) { // pointer
      int pos1 = dns[++pos];
      len = dns[pos1];
   }
   else { // not a pointer.
      parsename(pos, dns, name);
   }
   // If I do not seperate getting the short values to different
   // lines of code, the optimizer in VC++ only increments pos once!!!
   unsigned short a = ((unsigned short)dns[++pos]<<8);
   unsigned short b = dns[++pos];
   unsigned short Type = a | b;
   a = ((unsigned short)dns[++pos]<<8);
   b = dns[++pos];
   // unsigned short Class = a | b;
   pos += 4; // ttl
   a = ((unsigned short)dns[++pos]<<8);
   b = dns[++pos];
   unsigned short Datalen = a | b;
   if(Type == 15) { // MX record
      // first two bytes the precedence of the MX server
      a = ((unsigned short)dns[++pos]<<8);
      b = dns[++pos];
      // unsigned short order = a | b; // we don't use this here
      len = dns[++pos];
      if(len >= 192) {
         int pos1 = dns[++pos];
         parsename(pos1, dns, name);
      }
      else
         parsename(pos, dns, name);
   }
   else if(Type == 12) { // pointer record
      pos += Datalen+1;
   }
   else if(Type == 2) { // nameserver
      pos += Datalen+1;
   }
   else if(Type == 1) { // IP address, Datalen should be 4.
      pos += Datalen+1;
   }
   else {
      pos += Datalen+1;
   }
   return true;
};

   // Parses a dns name returned in a dns query (see TCP/IP illustrated, STEVENS, page 192)
   void parsename(int& pos, const unsigned char dns[], std::string& name) {
   int len = dns[pos];
   if(len >= 192) {
      int pos1 = ++pos;
      ++pos;
      parsename(pos1, dns, name);
   }
   else {
      for(int i = 0; i < len; ++i)
         name += dns[++pos];
      len = dns[++pos];
      if(len != 0)
         name += ".";
      if(len >= 192) {
         int pos1 = dns[++pos];
         ++pos;
         parsename(pos1, dns, name);
      }
      else if(len > 0) {
         parsename(pos, dns, name);
      }
      else if(len == 0)
         ++pos;
   }
};

   // email address wrapper struct
   struct Address {
      std::string name;    // e.g.   freddy foobar
      std::string address; // e.g.   someone@mail.com
   };

   // authenticate against a server.
   bool authenticate(const std::string& servergreeting, const SOCKET& s) {
   assert(auth && user.length()); // shouldn't be calling this function if this is not set!
   int len(0);
   if(!user.length()) { // obvioulsy a big whoops
      Send(len, s, "QUIT\r\n", 6, 0);
      return false;
   }

   // now parse the servergreeting looking for the auth type 'type'
   // if 'type' is not present exit with error (return false)
   std::string at;
   if(type == LOGIN)
      at = "LOGIN";
   else if(type == PLAIN)
      at = "PLAIN";
   else { // oopsy no other auth types yet!! MUST BE A BUG
      assert(false);
      returnstring = "554 jwSMTP only handles LOGIN or PLAIN authentication at present!";
      Send(len, s, "QUIT\r\n", 6, 0);
      return false;
   }

   // uppercase servergreeting first.
   std::string greeting(servergreeting);
   //char ch;
   for(std::string::size_type pos = 0; pos < greeting.length(); ++pos) {
      //ch = greeting[pos];
      greeting[pos] = toupper(greeting[pos] /*ch*/);
   }
   if(greeting.find(at) == std::string::npos) {
      returnstring = "554 jwSMTP only handles LOGIN or PLAIN authentication at present!";
      Send(len, s, "QUIT\r\n", 6, 0);
      return false; // didn't find that type of login!
   }

   // ok try and authenticate to the server.
   const int buffsize(1024);
   char buff[buffsize];
   if(type == LOGIN) {
      greeting = "auth " + at + "\r\n";
      if(!Send(len, s, greeting.c_str(), greeting.length(), 0)) {
         returnstring = "554 send failure: \"auth " + at + "\"";
         return false;
      }
      if(!Recv(len, s, buff, buffsize, 0)) {
         returnstring = "554 receive failure: waiting on username question!";
         return false;
      }
      buff[len] = '\0';
      returnstring = buff;

      // The server should give us a "334 VXNlcm5hbWU6" base64 username
      if(returnstring.substr(0,16) != "334 VXNlcm5hbWU6") {
         // returnstring = "554 Server did not return correct response to \'auth login\' command";
         Send(len, s, "QUIT\r\n", 6, 0);
         return false;
      }
      greeting = base64encode(user, false) + "\r\n";
      if(!Send(len, s, greeting.c_str(), greeting.length(), 0)) {
         returnstring = "554 send failure: sending username";
         return false;
      }
      // now get the password question
      if(!Recv(len, s, buff, buffsize, 0)) {
         returnstring = "554 receive failure: waiting on password question!";
         return false;
      }
      buff[len] = '\0';
      returnstring = buff;
      // The server should give us a "334 UGFzc3dvcmQ6" base64 password
      if(returnstring.substr(0,16) != "334 UGFzc3dvcmQ6") {
         // returnstring = "554 Server did not return correct password question";
         Send(len, s, "QUIT\r\n", 6, 0);
         return false;
      }
      greeting = base64encode(pass, false) + "\r\n";
      if(!Send(len, s, greeting.c_str(), greeting.length(), 0)) {
         returnstring = "554 send failure: sending password";
         return false;
      }
      // now see if we are authenticated.
      if(!Recv(len, s, buff, buffsize, 0)) {
         returnstring = "554 receive failure: waiting on auth login response!";
         return false;
      }
      buff[len] = '\0';
      returnstring = buff;
      if(returnstring.substr(0,3) == "235")
         return true;
   }
   // PLAIN authetication
   else if(type == PLAIN) { // else if not needed, being anal
      // now create the authentication response and send it.
      //       username\0username\0password\r\n
      // i.e.  \0fred\0secret\r\n                 (blank identity)
      std::vector<char> enc;
      std::string::size_type pos = 0;
      for(; pos < user.length(); ++pos)
         enc.push_back(user[pos]);
      enc.push_back('\0');
      for(pos = 0; pos < user.length(); ++pos)
         enc.push_back(user[pos]);
      enc.push_back('\0');
      for(pos = 0; pos < pass.length(); ++pos)
         enc.push_back(pass[pos]);

      enc = base64encode(enc, false);
      greeting = "auth plain ";
      for(std::vector<char>::const_iterator it1 = enc.begin(); it1 < enc.end(); ++it1)
         greeting += *it1;
      greeting += "\r\n";

      if(!Send(len, s, greeting.c_str(), greeting.length(), 0)) {
            returnstring = "554 send failure: sending login:plain authenication info";
            return false;
      }
      if(!Recv(len, s, buff, buffsize, 0)) {
         returnstring = "554 receive failure: waiting on auth plain autheticated response!";
         return false;
      }
      buff[len] = '\0';
      returnstring = buff;
      if(returnstring.substr(0,3) == "235")
         return true;
   }

   // fall through return an error.
   Send(len, s, "QUIT\r\n", 6, 0);
   return false;
};

   // less typing later, these are definately abominations!
   typedef std::vector<std::pair<std::vector<char>, std::string> >::const_iterator vec_pair_char_str_const_iter;
   typedef std::vector<std::pair<Address, short> >::const_iterator recipient_const_iter;
   typedef std::vector<std::pair<Address, short> >::iterator recipient_iter;
   typedef std::vector<std::string>::const_iterator vec_str_const_iter;

   // split an address into its relevant parts i.e.
   // name and actual address and return it in Address.
   // this may be usefull out of the class maybe
   // it should be a static function or a global? thinking about it.
   Address parseaddress(const std::string& addresstoparse) {
   Address newaddress; // return value

   // do some silly checks
   if(!addresstoparse.length())
      return newaddress; // its empty, oops (this should fail at the server.)

   if(!addresstoparse.find("@") == std::string::npos) {
      // no '@' symbol (could be a local address, e.g. root)
      // so just assume this. The SMTP server should just deny delivery if its messed up!
      newaddress.address = addresstoparse;
      return newaddress;
   }
   // we have one angle bracket but not the other
   // (this isn't strictly needed, just thought i'd throw it in)
   if(((addresstoparse.find('<') != std::string::npos) &&
      (addresstoparse.find('>') == std::string::npos)) ||
      ((addresstoparse.find('>') != std::string::npos) &&
      (addresstoparse.find('<') == std::string::npos))) {
      return newaddress; // its empty, oops (this should fail at the server.)
   }

   // we have angle bracketed delimitered address
   // like this maybe:
   //        "foo@bar.com"
   // or     "foo bar <foo@bar.com>"
   // or     "<foo@bar.com> foo bar"
   if((addresstoparse.find('<') != std::string::npos) &&
      (addresstoparse.find('>') != std::string::npos)) {
      std::string::size_type sta = addresstoparse.find('<');
      std::string::size_type end = addresstoparse.find('>');

      newaddress.address = addresstoparse.substr(sta + 1, end - sta - 1);

      if(sta > 0) { // name at the beginning
         // we are cutting off the last character if the bracket address
         // continues without a space into the bracketed address
         // e.g.  "hoopla girl<hoopla@wibble.com>"
         //       name becomes 'hoopla gir'
         // Fix by David Irwin
         // old code:
         // end = sta -1;
         // newaddress.name = addresstoparse.substr(0, end);
         newaddress.name = addresstoparse.substr(0, sta);
         return newaddress;
      }
      else { // name at the end
         // no name to get
         if(end >= addresstoparse.length()-1)
            return newaddress;

         end += 2;
         if(end >= addresstoparse.length())
            return newaddress;

         newaddress.name = addresstoparse.substr(end, addresstoparse.length()- end);
         // remove whitespace from end if need be
         if(newaddress.name[newaddress.name.length()-1] == ' ')
            newaddress.name = newaddress.name.substr(0, newaddress.name.length()-1);
         return newaddress;
      }
   }
   // if we get here assume an address of the form: foo@bar.com
   // and just save it.
   newaddress.address = addresstoparse;

   return newaddress;
};

   // The addresses to send the mail to
   std::vector<std::pair<Address, short> > recipients;
   // The address the mail is from.
   Address fromAddress;
   // Subject of the mail
   std::string subject;
   // The contents of the mail message
   std::vector<char> message;
   // The contents of the mail message in html format.
   std::vector<char> messageHTML;
   // attachments: the file as a stream of char's and the name of the file.
   std::vector<std::pair<std::vector<char>, std::string> > attachments;
   // This will be filled in from the toAddress by getserveraddress
   std::string server;
   // Name of a nameserver to query
   std::string nameserver;
   // The port to mail to on the smtp server.
   const unsigned short port;
   // use dns to query for MX records
   const bool lookupMXRecord;
   // using authentication
   bool auth;
   // username for authenticated smtp
   std::string user;
   // password for authenticated smtp
   std::string pass;
   // filled in with server return strings
   std::string returnstring;
};

} // end namespace jwsmtp

#endif // !ifndef __CM_MAILER_H__
