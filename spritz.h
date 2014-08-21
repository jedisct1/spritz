
#ifndef __SPRITZ_H__
#define __SPRITZ_H__

int spritz_hash(unsigned char *out, size_t outlen,
                const unsigned char *msg, size_t msglen);

int spritz_stream(unsigned char *out, size_t outlen,
                  const unsigned char *key, size_t keylen);

int spritz_encrypt(unsigned char *out, const unsigned char *msg, size_t msglen,
                   const unsigned char *nonce, size_t noncelen,
                   const unsigned char *key, size_t keylen);

int spritz_decrypt(unsigned char *out, const unsigned char *c, size_t clen,
                   const unsigned char *nonce, size_t noncelen,
                   const unsigned char *key, size_t keylen);

int spritz_auth(unsigned char *out, size_t outlen,
                const unsigned char *msg, size_t msglen,
                const unsigned char *key, size_t keylen);
#endif
