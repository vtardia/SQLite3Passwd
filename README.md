# SQLite3Passwd

SQLite3Passwd is a "clone" of Apache's [htpasswd](https://httpd.apache.org/docs/2.4/programs/htpasswd.html) with a SQLite 3 backend.

It consists of:

 - a static C library to link to your own code,
 - and an executable utility to manage a SQLite users database.

## Install

SQLite3Passwd has currently been tested on GNU/Linux and macOS only.

Run `make && make install` to compile and install the components using the default directory prefix (`/usr/local`).

Alternatively, run `make && make install -e PREFIX=/custom/path` to install the components with a custom directory prefix. If the path is relative to your user's home directory, it's best to use `-e PREFIX=$HOME/some/path`.

The static library will be installed into `$PREFIX/lib/libsl3auth.a`, the header file into `$PREFIX/include/sl3auth.h` and the binary utility into `$PREFIX/bin/sl3passwd`.

When compiling your own programs, use the `-I $PREFIX/include` and `-L $PREFIX/lib` GCC compiler options and `-lsl3auth` options within your `Makefile`s or directly into the command line.

SQLite3Passwd also requires the OpenSSL 3 and SQLite3 packages to be linked at compile time.

## Usage

### Command line tool

The `sl3passwd` binary allows to list, view, create, edit and delete users within a given SQLite database. It also has the option to verify a user's password.

A typical command would be like

```console
$ sl3passwd </path/to/users.db> <command> [<username> [options]]
```

Run `sl3passwd -h` to display a list of commands and options and their syntax.


### Library functions

```c
#include <stdlib.h>
#include <sl3auth.h>

int main(int argc, char const *argv[]) {

	// Open your database
    sqlite3 *db = SL3Auth_open(/* /path/to/some.db */);
    if (db == NULL) goto fail;

    // Collect user name and password here...
    char *username = /* ... */
    char *password = /* ... */
	
	// Authenticate
	if (!SL3Auth_verifyUser(username, password, db)) {
		fprintf(stderr, "Authentication failed!\n");
		goto fail;
	}

	// Do authenticated stuff...

    // Clean exit
    sqlite3_close(db);
    return EXIT_SUCCESS;

fail:
  sqlite3_close(db);
  return EXIT_FAILURE;
}
```

### Username validation

The `sl3passwd` utility validates the username length and requires that it starts with a letter and does not contain spaces.

The `sl3auth` library only validates the username length through SQLite, so in your programs you are responsible for further validation.

## License

SQLite3Passwd is licensed under LGPL. Please refer to the [LICENSE](./LICENSE) file for detailed information.
