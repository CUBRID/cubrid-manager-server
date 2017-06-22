# CUBRID Manager Server System

CUBRID Manager Server(CMS) is a part of CUBRID Tools.

CMS provides both HTTP or Socket interfaces for CUBRID Manager
to managing CUBRID system, and also provides monitoring information about CUBRID system.

## MAJOR REFERENCES

- CUBRID Official Site: http://www.cubrid.org and http://www.cubrid.com

## DOWNLOADS and FILE REPOSITORIES

CMS is distributed within CUBRID distribution which can be found here:

- http://www.cubrid.org/downloads
- http://ftp.cubrid.org

## HOW TO BUILD/INSTALL CMS

### you can refer to the wiki page

- http://www.cubrid.org/wiki_tools/entry/cms-build-and-install

### build and install on Linux

Unzip the package of CUBRID and you can find the source code of CMS here: cubrid-{version}/cubridmanager/server.

1. Move to the directory where the source is stored.

	```
	cd $HOME/cubridmanager/server
	```

2. Execute autogen.sh.

	```
	./autogen.sh
	```

3. Execute the configure script.

	```
	./configure --prefix=$CUBRID
	```

	- `--prefix=$CUBRID` : It specifies a directory to be installed.
    - `--enable-debug` : Used to enable debug mode.
	- `--enable-64bit` : Used to build in a 64-bit environment since supporting 64-bit from CUBRID 2008 R2.0 or higher.

4. Build by using make.

	```
	make
	```

5. Install by using make install.

	```
	make install
	```

### build and install on windows

If you want to build CMS on windows, VS2008 must be installed.

1. Open a commander "cmd.exe" and Move to the directory where the source is stored.

	```
	cd %CUBRID-SRC%/cubridmanager/server
	```

2. Execute the build batche file

	```
	cmd /c build.bat --prefix=%CUBRID% --with-cubrid-dir=%CUBRID%
	```

	- `--prefix=%CUBRID%` : It specifies a directory to be installed.
	- `--enable-64bit` : Used to build in a 64-bit environment since supporting 64-bit from CUBRID 2008 R2.0 or higher.
	- `--with-cubrid-dir=%CUBRID%` : Option specifies the directory CUBRID is installed.


## PROGRAMMING APIs

- [CMS APIs](docs/api/README.md)


## GETTING HELP

If You encounter any difficulties with getting started, or just have some
questions, or find bugs, or have some suggestions, we kindly ask you to 
post your thoughts on our subreddit at https://www.reddit.com/r/CUBRID/.

Sincerely,
Your CMS Development Team.
