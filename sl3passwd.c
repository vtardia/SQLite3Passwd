/**
 * Like htpasswd but for SQLite
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libgen.h>
#include <ctype.h>

#include "sl3auth.h"

static const char * kProgramVersion = "1.0.0";

#define OP_LIST    "list"
#define OP_VIEW    "view"
#define OP_PREVIEW "preview"
#define OP_ADD     "add"
#define OP_EDIT    "edit"
#define OP_DELETE  "delete"
#define OP_VERIFY  "verify"

#define StringEquals(op, val) (strcmp(op, val) == 0)

#define CheckUsername() if (argc < 4) goto failWithUsage;

/// Converts raw column names to pretty labels
static char *labelFor(const char *col) {
  if (StringEquals(col, "id")) return "ID";
  if (StringEquals(col, "username")) return "Username";
  if (StringEquals(col, "password")) return "Password";
  if (StringEquals(col, "created_at")) return "Created";
  if (StringEquals(col, "updated_at")) return "Updated";
  return "(n/a)";
}

/// Callback used to display a user's details
static int showUser(int columnCount, char **columns, char **columnNames) {
  printf("\n");
  for(int i = 0; i < columnCount; i++) {
    printf("%10s: %s\n", labelFor(columnNames[i]), columns[i] ? columns[i] : "NULL");
  }
  printf("\n");
  return EXIT_SUCCESS;
}

/// Displays program version
int usage(const char *prog, const int ret) {
  fprintf(
    stderr,
    "Usage: %s <database> [list | [view|preview|add|edit|delete] <username>]\n",
    basename((char *)prog)
  );
  return ret;
}

int version(const char *prog) {
  fprintf(
    stdout,
    "%s %s\n",
    basename((char *)prog), kProgramVersion
  );
  return EXIT_SUCCESS;
}

/// Displays program help
int help(const char *prog) {
  fprintf(stderr,
    "\n%1$s - manage SQLite db for user authentication [version %2$s]\n"
    "\n"
    "Usage: %1$s [options] <database> <command> [<username> [options]]\n"
    "\n"
    "Available commands:\n"
    "\n"
    "   list                  Display the list of users in the given database.\n"
    "   preview <username>    Dry run, compute the password for the given user\n"
    "                         without saving it.\n"
    "   view <username>       Display the details of the given user.\n"
    "   add <username>        Add a new user or update an existing user.\n"
    "   edit <username>       Update an existing user or create a new one.\n"
    "   delete <username>     Delete an existing user.\n"
    "   verify <username>     Verify a given username/password combination.\n"
    "\n"
    "Current options include:\n"
    "   -v, --version   display the current program version;\n"
    "   -h, --help      display this help message;\n"
    "       --sha512    select the SHA512 algorhythm for add/edit/preview\n"
    "                   instead of the default SHA256 (must be specified\n"
    "                   after the username);\n"
    "\n"
    "The destination database file is automatically created if does not exist.\n"
    "\n", basename((char *)prog), kProgramVersion
  );
  return EXIT_SUCCESS;
}

int main(int argc, char const *argv[]) {
  // Validate minimal arguments list and global options
  if (argc < 3) {
    if (argc == 2) {
      if (StringEquals(argv[1], "-v") || StringEquals(argv[1], "--version")) {
        return version(argv[0]);
      }
      if (StringEquals(argv[1], "--help") || StringEquals(argv[1], "-h")) {
        return help(argv[0]);
      }
    }
    return usage(argv[0], EXIT_FAILURE);
  }

  const char *dbFilePath = argv[1];
  const char *operation = argv[2];

  // Try to open/create the database file
  sqlite3 *db = SL3Auth_open(dbFilePath);
  if (db == NULL) return EXIT_FAILURE;

  // Perform the selected operation
  if (StringEquals(operation, OP_LIST)) {
    if (!SL3Auth_listUsers(db, showUser)) goto fail;
  } else if (StringEquals(operation, OP_VIEW)) {
    CheckUsername();
    if (!SL3Auth_showUser(argv[3], db, showUser)) goto fail;
  } else if (
      StringEquals(operation, OP_ADD)
      || StringEquals(operation, OP_EDIT)
      || StringEquals(operation, OP_PREVIEW)
  ) {
    CheckUsername();
    const char *username = argv[3];

    // Minimal validation for username:
    // Max 50 chars
    if (strlen(username) > 50) {
      fprintf(stderr, "Username is too long, max 50 characters allowed\n");
      goto fail;
    }

    // No spaces or equivalents
    if (
      strchr(username, ' ') != NULL
      || strchr(username, '\r') != NULL
      || strchr(username, '\f') != NULL
      || strchr(username, '\v') != NULL
      || strchr(username, '\n') != NULL
      || strchr(username, '\t') != NULL
    ) {
      fprintf(stderr, "Username cannot contain spaces\n");
      goto fail;
    }

    // Must start with a letter
    if (!isalpha(username[0])) {
      fprintf(stderr, "Username must start with a letter\n");
      goto fail;
    }

    // Select algorhythm
    HashAlgo algo = SHA256Hash;
    if (argc >=5 && StringEquals(argv[4], "--sha512")) {
      algo = SHA512Hash;
    }

    // Ask for password
    char *password = SL3Auth_getPassword("Enter new password: ");

    // Dry run, hash password and display only
    if (StringEquals(operation, OP_PREVIEW)) {
      char *hash = SL3Auth_hashPassword(password, strlen(password), algo);
      free(password);
      if (hash == NULL) {
        fprintf(stderr, "Unable to hash password\n");
        goto fail;
      }
      printf("\nUsername: %s\nPassword: %s\n\n", username, hash);
      free(hash);
    } else {
      if (!SL3Auth_upsertUser(username, password, algo, db)) {
        free(password);
        goto fail;
      }
    }
  } else if (StringEquals(operation, OP_VERIFY)) {
    CheckUsername();
    // Ask for password
    char *password = SL3Auth_getPassword("Enter password: ");
    if (!SL3Auth_verifyUser(argv[3], password, db)) {
      fprintf(stderr, "Invalid username or password\n");
      goto fail;
    }
    printf("OK\n");
  } else if (StringEquals(operation, OP_DELETE)) {
    CheckUsername();
    if (!SL3Auth_deleteUser(argv[3], db)) goto fail;
  } else {
    goto failWithUsage;
  }
  
  // Cleanup
  sqlite3_close(db);
  return EXIT_SUCCESS;

failWithUsage:
  sqlite3_close(db);
  return usage(argv[0], EXIT_FAILURE);

fail:
  sqlite3_close(db);
  return EXIT_FAILURE;
}
