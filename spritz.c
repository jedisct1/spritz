
#include <stdio.h>
#include <string.h>

#define N 256

typedef struct State_ {
    unsigned char s[N];
    unsigned char i;
    unsigned char j;
    unsigned char k;
    unsigned char z;
    unsigned char a;
    unsigned char w;
} State;

#define LOW(B)  ((B) & 0xf)
#define HIGH(B) ((B) >> 4)

static void
memzero(void *pnt, size_t len)
{
#ifdef _WIN32
    SecureZeroMemory(pnt, len);
#else
    volatile unsigned char *pnt_ = (volatile unsigned char *) pnt;
    size_t                     i = (size_t) 0U;

    while (i < len) {
        pnt_[i++] = 0U;
    }
#endif
}

static void
initialize_state(State *state)
{
    unsigned int v;

    state->i = 0;
    state->j = 0;
    state->k = 0;
    state->z = 0;
    state->a = 0;
    state->w = 1;

    for (v = 0; v < N; v++) {
        state->s[v] = (unsigned char) v;
    }
}

static void
update(State *state)
{
    unsigned char t;

    state->i += state->w;
    state->j = state->k + state->s[(state->j + state->s[state->i]) % N];
    state->k = state->i + state->k + state->s[state->j];
    t = state->s[state->i];
    state->s[state->i] = state->s[state->j];
    state->s[state->j] = t;
}

static unsigned char
output(State *state)
{
    state->z =
        state->s[(state->j +
                  state->s[(state->i +
                            state->s[(state->z + state->k) % N]) % N]) % N];
    return state->z;
}

static void
crush(State *state)
{
    unsigned int  v;
    unsigned char t;

    for (v = 0; v < N / 2; v++) {
        if (state->s[v] > state->s[N - 1 - v]) {
            t = state->s[v];
            state->s[v] = state->s[N - 1 - v];
            state->s[N - 1 - v] = t;
        }
    }
}

static void
whip(State *state)
{
    const unsigned int r = N * 2;
    unsigned int       v;

    for (v = 0; v < r; v++) {
        update(state);
    }
    state->w += 2;
}

static void
shuffle(State *state)
{
    whip(state);
    crush(state);
    whip(state);
    crush(state);
    whip(state);
    state->a = 0;
}

static void
absorb_stop(State *state)
{
    if (state->a == N / 2) {
        shuffle(state);
    }
    state->a++;
}

static void
absorb_nibble(State *state, const unsigned char x)
{
    unsigned char t;

    if (state->a == N / 2) {
        shuffle(state);
    }
    t = state->s[state->a];
    state->s[state->a] = state->s[(N / 2 + x) % N];
    state->s[(N / 2 + x) % N] = t;
    state->a++;
}

static void
absorb_byte(State *state, const unsigned char b)
{
    absorb_nibble(state, LOW(b));
    absorb_nibble(state, HIGH(b));
}

static void
absorb(State *state, const unsigned char *msg, size_t length)
{
    size_t v;

    for (v = 0; v < length; v++) {
        absorb_byte(state, msg[v]);
    }
}

static unsigned char
drip(State *state)
{
    if (state->a > 0) {
        shuffle(state);
    }
    update(state);

    return output(state);
}

static void
squeeze(State *state, unsigned char *out, size_t outlen)
{
    size_t v;

    if (state->a > 0) {
        shuffle(state);
    }
    for (v = 0; v < outlen; v++) {
        out[v] = drip(state);
    }
}

int
hash(unsigned char *out, size_t outlen,
     const unsigned char *msg, size_t msglen)
{
    State         state;
    unsigned char r;

    r = (unsigned char) outlen;
    initialize_state(&state);
    absorb(&state, msg, msglen);
    absorb_stop(&state);
    absorb(&state, &r, 1U);
    squeeze(&state, out, outlen);
    memzero(&state, sizeof state);

    return 0;
}

int
stream(unsigned char *out, size_t outlen, const unsigned char *key, size_t keylen)
{
    State  state;
    size_t v;

    initialize_state(&state);
    absorb(&state, key, keylen);
    if (state.a > 0) {
        shuffle(&state);
    }
    for (v = 0; v < outlen; v++) {
        out[v] = drip(&state);
    }
    memzero(&state, sizeof state);

    return 0;
}

int
encrypt(unsigned char *out, const unsigned char *msg, size_t msglen,
        const unsigned char *key, size_t keylen)
{
    State  state;
    size_t v;

    initialize_state(&state);
    absorb(&state, key, keylen);
    if (state.a > 0) {
        shuffle(&state);
    }
    for (v = 0; v < msglen; v++) {
        out[v] = msg[v] + drip(&state);
    }
    memzero(&state, sizeof state);

    return 0;
}

int
decrypt(unsigned char *out, const unsigned char *msg, size_t msglen,
        const unsigned char *key, size_t keylen)
{
    State  state;
    size_t v;

    initialize_state(&state);
    absorb(&state, key, keylen);
    if (state.a > 0) {
        shuffle(&state);
    }
    for (v = 0; v < msglen; v++) {
        out[v] = msg[v] - drip(&state);
    }
    memzero(&state, sizeof state);

    return 0;
}

int
main(void)
{
    unsigned char       out[32];
    const unsigned char msg[] = { 'a', 'r', 'c', 'f', 'o', 'u', 'r' };
    size_t              i;

    hash(out, sizeof out, msg, 7);

    for (i = 0; i < sizeof out; i++) {
        printf("%02x ", out[i]);
    }
    putchar('\n');

    stream(out, sizeof out, msg, 7);
    for (i = 0; i < sizeof out; i++) {
        printf("%02x ", out[i]);
    }
    putchar('\n');

    return 0;
}
