#
# Copyright (C) 2008 Search Solution Corporation. All rights reserved by Search Solution. 
#
#   This program is free software; you can redistribute it and/or modify 
#   it under the terms of the GNU General Public License as published by 
#   the Free Software Foundation; either version 2 of the License, or
#   (at your option) any later version. 
#
#  This program is distributed in the hope that it will be useful, 
#  but WITHOUT ANY WARRANTY; without even the implied warranty of 
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the 
#  GNU General Public License for more details. 
#
#  You should have received a copy of the GNU General Public License 
#  along with this program; if not, write to the Free Software 
#  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
#

AUTOMAKE_OPTIONS = foreign

EXTRA_DIST = openssl jsoncpp libevent

all:
	@echo "All OK"
install: all
	@echo "Make install for web manager"; \
		(cp -rf $(srcdir)/../share $(DESTDIR)${prefix}/); \
		(chmod -R +w $(DESTDIR)${prefix}/share/webmanager); \
		(find $(DESTDIR)${prefix}/share -name '.svn' | xargs rm -rf); \
		(echo "Install OK")
        
uninstall: clean-local-check
	@echo "Making uninstall for web manager";\
		(chmod -R +w $(DESTDIR)${prefix}/share/webmanager); \
		(rm -rf $(DESTDIR)${prefix}/share/webmanager); \
		(echo "Uninstall OK")

clean-local: clean-local-check
.PHONY: clean-local-check
clean-local-check:
	@echo "clean OK"
