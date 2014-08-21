
A C implementation of [Spritz](http://people.csail.mit.edu/rivest/pubs/RS14.pdf),
a spongy RC4-like stream cipher and hash function.

```c
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
```

*WARNING* You probably shouldn't use the Spritz cipher for anything.

It has distinguishers, performance is not impressive (using Spritz to
build a hash function is even slower than Keccak), it depends on
conditional jumps and there is no cryptanalysis.
