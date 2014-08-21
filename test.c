
#include <stdio.h>

#include "spritz.h"

int
main(void)
{
    unsigned char       out[32];
    const unsigned char msg[] = { 'a', 'r', 'c', 'f', 'o', 'u', 'r' };
    size_t              i;

    spritz_hash(out, sizeof out, msg, 7);

    for (i = 0; i < sizeof out; i++) {
        printf("%02x ", out[i]);
    }
    putchar('\n');

    spritz_stream(out, sizeof out, msg, 7);
    for (i = 0; i < sizeof out; i++) {
        printf("%02x ", out[i]);
    }
    putchar('\n');

    return 0;
}
