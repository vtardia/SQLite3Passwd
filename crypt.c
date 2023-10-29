#include "sl3auth.h"

#include <openssl/evp.h>
#include <openssl/sha.h>
#include <string.h>

/**
 * Converts a binary hash to readable hex text
 * @hash   The byte array hash
 * @length The length of the hash without NULL terminator
 *         (e.g. 32 for SHA256, 64 for SHA512)
 * 
 * Returns a char pointer that needs to be freed
 */
static char *Hash2Text(
  const unsigned char *hash,
  size_t length, HashAlgo algo
) {
  // Each byte is represented by 2 characters,
  // so the resulting text must have double size plus
  // the NULL terminator
  size_t resultLength = (length * 2);

  // Adding prefix as per crypt() definition
  // See https://en.wikipedia.org/wiki/Crypt_(C)
  char *prefix = (algo == SHA512Hash) ? "$6$" : "$5$";
  size_t prefixLength = strlen(prefix);

  char *text = calloc(1, prefixLength + resultLength + 1);
  if (text == NULL) return NULL;

  snprintf(text, prefixLength + 1, "%s", prefix);
  char *p = text + prefixLength;
  char *end = p + resultLength;
  for(size_t i = 0; i < length; i++) {
    if (p >= end) break; // prevents overflow
    sprintf(p, "%02x", hash[i]);
    p += 2;
  }
  return text;
}

/**
 * Encrypts the input data into a SHA256 hash and returns a text
 * representation prefixed by $5$
 */
char *SHA256Crypt(const void *data, size_t size) {
  unsigned char hash[SHA256_DIGEST_LENGTH] = {};
  if (!EVP_Q_digest(NULL, "SHA256", NULL, data, size, hash, NULL)) {
    return NULL;
  }
  return Hash2Text(hash, sizeof(hash), SHA256Hash);
}

/**
 * Encrypts the input data into a SHA512 hash and returns a text
 * representation prefixed by $6$
 */
char *SHA512Crypt(const void *data, size_t size) {
  unsigned char hash[SHA512_DIGEST_LENGTH] = {};
  if (!EVP_Q_digest(NULL, "SHA512", NULL, data, size, hash, NULL)) {
    return NULL;
  }
  return Hash2Text(hash, sizeof(hash), SHA512Hash);
}
