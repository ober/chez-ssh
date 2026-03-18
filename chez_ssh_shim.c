/*
 * chez_ssh_shim.c — SSH agent implementation for Chez Scheme
 *
 * Implements the SSH agent protocol (draft-miller-ssh-agent) with Ed25519
 * key support via OpenSSL. Private keys are stored in mlock'd memory and
 * never cross the FFI boundary — signing happens entirely in C.
 *
 * Provides:
 *   - OpenSSH private key parser (base64 + binary format)
 *   - Secure key storage (mlock, MADV_DONTDUMP, explicit_bzero)
 *   - SSH agent protocol handler (identities, signing)
 *   - Unix domain socket server (background pthread)
 *
 * Link with: -lcrypto -lpthread
 */

#define _GNU_SOURCE
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <pthread.h>
#include <signal.h>
#include <errno.h>
#include <poll.h>
#include <openssl/evp.h>

/* ========== Constants ========== */

#define MAX_KEYS        16
#define MAX_COMMENT     256
#define MAX_MSG         262144   /* 256 KB max agent message */
#define ED25519_SEED    32
#define ED25519_PUB     32
#define ED25519_SIG     64

/* SSH agent protocol message types */
#define SSH_AGENT_FAILURE                5
#define SSH_AGENT_SUCCESS                6
#define SSH_AGENTC_REQUEST_IDENTITIES    11
#define SSH_AGENT_IDENTITIES_ANSWER      12
#define SSH_AGENTC_SIGN_REQUEST          13
#define SSH_AGENT_SIGN_RESPONSE          14
#define SSH_AGENTC_ADD_IDENTITY          17
#define SSH_AGENTC_REMOVE_IDENTITY       18
#define SSH_AGENTC_REMOVE_ALL_IDENTITIES 19

/* ========== Key Storage ========== */

typedef struct {
    uint8_t seed[ED25519_SEED];     /* 32-byte Ed25519 private seed */
    uint8_t pubkey[ED25519_PUB];    /* 32-byte Ed25519 public key */
    char    comment[MAX_COMMENT];
    int     active;
} ssh_key_t;

/* Page-aligned for mlock granularity */
static ssh_key_t _keys[MAX_KEYS] __attribute__((aligned(4096)));
static int _key_count = 0;
static int _keys_hardened = 0;

/* Harden key storage: pin in RAM, exclude from core dumps */
static void harden_keys(void) {
    if (_keys_hardened) return;
    _keys_hardened = 1;
    mlock(_keys, sizeof(_keys));
    madvise(_keys, sizeof(_keys), MADV_DONTDUMP);
}

/* ========== Socket State ========== */

static int _agent_fd = -1;                      /* listening socket */
static char _agent_path[256] = {0};              /* socket file path */
static char _agent_dir[256] = {0};               /* socket directory */
static volatile int _agent_running = 0;
static pthread_t _agent_thread;
static int _agent_wakeup_pipe[2] = {-1, -1};     /* for clean shutdown */

/* ========== Base64 Decode ========== */

static const uint8_t b64_table[256] = {
    ['A']=0,  ['B']=1,  ['C']=2,  ['D']=3,  ['E']=4,  ['F']=5,
    ['G']=6,  ['H']=7,  ['I']=8,  ['J']=9,  ['K']=10, ['L']=11,
    ['M']=12, ['N']=13, ['O']=14, ['P']=15, ['Q']=16, ['R']=17,
    ['S']=18, ['T']=19, ['U']=20, ['V']=21, ['W']=22, ['X']=23,
    ['Y']=24, ['Z']=25,
    ['a']=26, ['b']=27, ['c']=28, ['d']=29, ['e']=30, ['f']=31,
    ['g']=32, ['h']=33, ['i']=34, ['j']=35, ['k']=36, ['l']=37,
    ['m']=38, ['n']=39, ['o']=40, ['p']=41, ['q']=42, ['r']=43,
    ['s']=44, ['t']=45, ['u']=46, ['v']=47, ['w']=48, ['x']=49,
    ['y']=50, ['z']=51,
    ['0']=52, ['1']=53, ['2']=54, ['3']=55, ['4']=56, ['5']=57,
    ['6']=58, ['7']=59, ['8']=60, ['9']=61, ['+']= 62, ['/']= 63,
};

static int is_b64_char(uint8_t c) {
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
           (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=';
}

/*
 * base64_decode — Decode base64 data, skipping whitespace.
 * Returns decoded length, or -1 on error.
 */
static int base64_decode(const uint8_t *in, size_t inlen,
                         uint8_t *out, size_t maxout) {
    size_t oi = 0;
    uint32_t acc = 0;
    int bits = 0;

    for (size_t i = 0; i < inlen; i++) {
        uint8_t c = in[i];
        if (c == '=' || c == '\n' || c == '\r' || c == ' ') continue;
        if (!is_b64_char(c)) return -1;
        acc = (acc << 6) | b64_table[c];
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            if (oi >= maxout) return -1;
            out[oi++] = (acc >> bits) & 0xFF;
        }
    }
    return (int)oi;
}

/* ========== SSH Wire Format Helpers ========== */

/* Read big-endian uint32 from buffer. Returns -1 if not enough data. */
static int read_uint32(const uint8_t *buf, size_t len, size_t *pos, uint32_t *val) {
    if (*pos + 4 > len) return -1;
    *val = ((uint32_t)buf[*pos] << 24) | ((uint32_t)buf[*pos+1] << 16) |
           ((uint32_t)buf[*pos+2] << 8) | buf[*pos+3];
    *pos += 4;
    return 0;
}

/* Read SSH string (uint32 length + bytes). Returns pointer and length. */
static int read_string(const uint8_t *buf, size_t len, size_t *pos,
                       const uint8_t **data, uint32_t *dlen) {
    uint32_t slen;
    if (read_uint32(buf, len, pos, &slen) < 0) return -1;
    if (*pos + slen > len) return -1;
    *data = buf + *pos;
    *dlen = slen;
    *pos += slen;
    return 0;
}

/* Write big-endian uint32 */
static void write_uint32(uint8_t *buf, size_t *pos, uint32_t val) {
    buf[*pos]   = (val >> 24) & 0xFF;
    buf[*pos+1] = (val >> 16) & 0xFF;
    buf[*pos+2] = (val >> 8)  & 0xFF;
    buf[*pos+3] =  val        & 0xFF;
    *pos += 4;
}

/* Write SSH string (uint32 length + bytes) */
static void write_string(uint8_t *buf, size_t *pos,
                         const uint8_t *data, uint32_t dlen) {
    write_uint32(buf, pos, dlen);
    memcpy(buf + *pos, data, dlen);
    *pos += dlen;
}

/* ========== OpenSSH Key Parser ========== */

static const char OPENSSH_MAGIC[] = "openssh-key-v1\0";
#define OPENSSH_MAGIC_LEN 15

/*
 * parse_openssh_key — Parse an OpenSSH private key file.
 *
 * Extracts Ed25519 seed (32 bytes), public key (32 bytes), and comment
 * from the -----BEGIN OPENSSH PRIVATE KEY----- format.
 *
 * Only supports unencrypted Ed25519 keys (cipher "none").
 * Returns 0 on success, -1 on error.
 */
static int parse_openssh_key(const uint8_t *data, size_t len,
                             uint8_t *seed_out, uint8_t *pubkey_out,
                             char *comment_out, size_t comment_max) {
    /* Find base64 payload between BEGIN/END markers */
    const char *begin_marker = "-----BEGIN OPENSSH PRIVATE KEY-----";
    const char *end_marker = "-----END OPENSSH PRIVATE KEY-----";
    /* Ensure data is null-terminated within len for strstr */
    (void)len;
    const char *begin = strstr((const char *)data, begin_marker);
    if (!begin) return -1;
    begin += strlen(begin_marker);
    const char *end = strstr(begin, end_marker);
    if (!end) return -1;

    /* Base64 decode */
    size_t b64len = end - begin;
    size_t maxdec = (b64len * 3) / 4 + 4;
    uint8_t *dec = calloc(1, maxdec);
    if (!dec) return -1;
    int declen = base64_decode((const uint8_t *)begin, b64len, dec, maxdec);
    if (declen < 0) { free(dec); return -1; }

    size_t pos = 0;

    /* Verify magic */
    if ((size_t)declen < OPENSSH_MAGIC_LEN ||
        memcmp(dec, OPENSSH_MAGIC, OPENSSH_MAGIC_LEN) != 0) {
        free(dec); return -1;
    }
    pos = OPENSSH_MAGIC_LEN;

    /* Read cipher, kdf, kdfoptions */
    const uint8_t *sdata;
    uint32_t slen;
    if (read_string(dec, declen, &pos, &sdata, &slen) < 0) { free(dec); return -1; }
    /* cipher must be "none" */
    if (slen != 4 || memcmp(sdata, "none", 4) != 0) {
        /* Encrypted key — not supported (embed layer handles encryption) */
        free(dec); return -1;
    }
    if (read_string(dec, declen, &pos, &sdata, &slen) < 0) { free(dec); return -1; } /* kdf */
    if (read_string(dec, declen, &pos, &sdata, &slen) < 0) { free(dec); return -1; } /* kdfoptions */

    /* Number of keys */
    uint32_t nkeys;
    if (read_uint32(dec, declen, &pos, &nkeys) < 0 || nkeys < 1) { free(dec); return -1; }

    /* Skip public key blob */
    if (read_string(dec, declen, &pos, &sdata, &slen) < 0) { free(dec); return -1; }

    /* Read private section */
    const uint8_t *priv_section;
    uint32_t priv_len;
    if (read_string(dec, declen, &pos, &priv_section, &priv_len) < 0) { free(dec); return -1; }

    /* Parse private section */
    size_t ppos = 0;

    /* Check integers (must match) */
    uint32_t check1, check2;
    if (read_uint32(priv_section, priv_len, &ppos, &check1) < 0) { free(dec); return -1; }
    if (read_uint32(priv_section, priv_len, &ppos, &check2) < 0) { free(dec); return -1; }
    if (check1 != check2) { free(dec); return -1; }

    /* Key type — must be "ssh-ed25519" */
    const uint8_t *keytype;
    uint32_t keytype_len;
    if (read_string(priv_section, priv_len, &ppos, &keytype, &keytype_len) < 0) { free(dec); return -1; }
    if (keytype_len != 11 || memcmp(keytype, "ssh-ed25519", 11) != 0) {
        free(dec); return -1;
    }

    /* Public key (32 bytes) */
    const uint8_t *pk;
    uint32_t pk_len;
    if (read_string(priv_section, priv_len, &ppos, &pk, &pk_len) < 0) { free(dec); return -1; }
    if (pk_len != 32) { free(dec); return -1; }
    memcpy(pubkey_out, pk, 32);

    /* Private key (64 bytes: seed[32] || pubkey[32]) */
    const uint8_t *sk;
    uint32_t sk_len;
    if (read_string(priv_section, priv_len, &ppos, &sk, &sk_len) < 0) { free(dec); return -1; }
    if (sk_len != 64) { free(dec); return -1; }
    memcpy(seed_out, sk, 32);  /* first 32 bytes are the seed */

    /* Comment */
    const uint8_t *comment;
    uint32_t comment_len;
    if (read_string(priv_section, priv_len, &ppos, &comment, &comment_len) < 0) {
        comment_out[0] = '\0';
    } else {
        size_t clen = comment_len < comment_max - 1 ? comment_len : comment_max - 1;
        memcpy(comment_out, comment, clen);
        comment_out[clen] = '\0';
    }

    /* Zero the decoded buffer (contained the raw private key) */
    explicit_bzero(dec, maxdec);
    free(dec);
    return 0;
}

/* ========== Ed25519 Signing (via OpenSSL) ========== */

/*
 * ed25519_sign — Sign data with an Ed25519 seed. Key stays in C.
 * Returns 0 on success, -1 on error.
 */
static int ed25519_sign(const uint8_t *seed,
                        const uint8_t *data, size_t datalen,
                        uint8_t *sig_out) {
    EVP_PKEY *pkey = EVP_PKEY_new_raw_private_key(
        EVP_PKEY_ED25519, NULL, seed, ED25519_SEED);
    if (!pkey) return -1;

    EVP_MD_CTX *mctx = EVP_MD_CTX_new();
    if (!mctx) { EVP_PKEY_free(pkey); return -1; }

    size_t siglen = ED25519_SIG;
    int rc = -1;
    if (EVP_DigestSignInit(mctx, NULL, NULL, NULL, pkey) == 1 &&
        EVP_DigestSign(mctx, sig_out, &siglen, data, datalen) == 1) {
        rc = 0;
    }

    EVP_MD_CTX_free(mctx);
    EVP_PKEY_free(pkey);
    return rc;
}

/*
 * ed25519_derive_pubkey — Derive public key from seed via OpenSSL.
 * Returns 0 on success, -1 on error.
 */
static int ed25519_derive_pubkey(const uint8_t *seed, uint8_t *pubkey_out) {
    EVP_PKEY *pkey = EVP_PKEY_new_raw_private_key(
        EVP_PKEY_ED25519, NULL, seed, ED25519_SEED);
    if (!pkey) return -1;

    size_t publen = ED25519_PUB;
    int rc = EVP_PKEY_get_raw_public_key(pkey, pubkey_out, &publen) == 1 ? 0 : -1;
    EVP_PKEY_free(pkey);
    return rc;
}

/* ========== Key Management ========== */

/*
 * Build the SSH public key blob for an Ed25519 key:
 *   string "ssh-ed25519" || string pubkey(32)
 * Total: 4+11+4+32 = 51 bytes
 */
#define ED25519_BLOB_SIZE 51

static void build_pubkey_blob(const uint8_t *pubkey, uint8_t *blob) {
    size_t pos = 0;
    write_string(blob, &pos, (const uint8_t *)"ssh-ed25519", 11);
    write_string(blob, &pos, pubkey, ED25519_PUB);
}

int chez_ssh_agent_load_openssh_key(const uint8_t *data, int len) {
    if (_key_count >= MAX_KEYS) return -1;

    harden_keys();

    int idx = _key_count;
    ssh_key_t *k = &_keys[idx];
    memset(k, 0, sizeof(*k));

    if (parse_openssh_key(data, len, k->seed, k->pubkey,
                          k->comment, MAX_COMMENT) < 0) {
        explicit_bzero(k, sizeof(*k));
        return -1;
    }

    k->active = 1;
    _key_count++;
    return idx;
}

int chez_ssh_agent_load_ed25519(const uint8_t *seed, const char *comment) {
    if (_key_count >= MAX_KEYS) return -1;

    harden_keys();

    int idx = _key_count;
    ssh_key_t *k = &_keys[idx];
    memset(k, 0, sizeof(*k));

    memcpy(k->seed, seed, ED25519_SEED);
    if (ed25519_derive_pubkey(seed, k->pubkey) < 0) {
        explicit_bzero(k, sizeof(*k));
        return -1;
    }

    if (comment) {
        strncpy(k->comment, comment, MAX_COMMENT - 1);
        k->comment[MAX_COMMENT - 1] = '\0';
    }

    k->active = 1;
    _key_count++;
    return idx;
}

int chez_ssh_agent_key_count(void) {
    return _key_count;
}

int chez_ssh_agent_get_pubkey_blob(int index, uint8_t *out, int max_out) {
    if (index < 0 || index >= _key_count || !_keys[index].active) return -1;
    if (max_out < ED25519_BLOB_SIZE) return -1;
    build_pubkey_blob(_keys[index].pubkey, out);
    return ED25519_BLOB_SIZE;
}

/* Copy comment into caller's buffer. Returns length or -1. */
int chez_ssh_agent_get_comment(int index, char *out, int max_out) {
    if (index < 0 || index >= _key_count || !_keys[index].active) return -1;
    int len = strlen(_keys[index].comment);
    if (len >= max_out) len = max_out - 1;
    memcpy(out, _keys[index].comment, len);
    out[len] = '\0';
    return len;
}

void chez_ssh_agent_remove_key(int index) {
    if (index < 0 || index >= _key_count) return;
    explicit_bzero(&_keys[index], sizeof(ssh_key_t));
    /* Compact the array */
    for (int i = index; i < _key_count - 1; i++) {
        _keys[i] = _keys[i + 1];
    }
    explicit_bzero(&_keys[_key_count - 1], sizeof(ssh_key_t));
    _key_count--;
}

void chez_ssh_agent_remove_all(void) {
    explicit_bzero(_keys, sizeof(_keys));
    _key_count = 0;
}

/* ========== Agent Protocol ========== */

/* Find key by matching public key blob */
static int find_key_by_blob(const uint8_t *blob, uint32_t bloblen) {
    if (bloblen != ED25519_BLOB_SIZE) return -1;

    uint8_t candidate[ED25519_BLOB_SIZE];
    for (int i = 0; i < _key_count; i++) {
        if (!_keys[i].active) continue;
        build_pubkey_blob(_keys[i].pubkey, candidate);
        if (memcmp(candidate, blob, ED25519_BLOB_SIZE) == 0)
            return i;
    }
    return -1;
}

/*
 * handle_identities — Build SSH_AGENT_IDENTITIES_ANSWER.
 * Format: byte(12) || uint32(nkeys) || for each: string(blob) || string(comment)
 */
static int handle_identities(uint8_t *resp, size_t maxresp) {
    size_t pos = 0;

    /* Leave room for outer length (4 bytes), filled in at end */
    pos = 4;

    /* Message type */
    if (pos >= maxresp) return -1;
    resp[pos++] = SSH_AGENT_IDENTITIES_ANSWER;

    /* Count active keys */
    int nactive = 0;
    for (int i = 0; i < _key_count; i++)
        if (_keys[i].active) nactive++;

    write_uint32(resp, &pos, nactive);

    for (int i = 0; i < _key_count; i++) {
        if (!_keys[i].active) continue;
        /* Public key blob */
        uint8_t blob[ED25519_BLOB_SIZE];
        build_pubkey_blob(_keys[i].pubkey, blob);
        if (pos + 4 + ED25519_BLOB_SIZE + 4 + MAX_COMMENT > maxresp) return -1;
        write_string(resp, &pos, blob, ED25519_BLOB_SIZE);
        /* Comment */
        uint32_t clen = strlen(_keys[i].comment);
        write_string(resp, &pos, (const uint8_t *)_keys[i].comment, clen);
    }

    /* Fill in outer length (message length, not including the 4-byte length itself) */
    size_t msg_len = pos - 4;
    size_t lpos = 0;
    write_uint32(resp, &lpos, msg_len);

    return (int)pos;
}

/*
 * handle_sign — Process SSH_AGENTC_SIGN_REQUEST, build SSH_AGENT_SIGN_RESPONSE.
 */
static int handle_sign(const uint8_t *payload, size_t paylen,
                       uint8_t *resp, size_t maxresp) {
    (void)maxresp;
    size_t ppos = 0;

    /* Read key blob */
    const uint8_t *key_blob;
    uint32_t key_blob_len;
    if (read_string(payload, paylen, &ppos, &key_blob, &key_blob_len) < 0)
        return -1;

    /* Read data to sign */
    const uint8_t *data;
    uint32_t datalen;
    if (read_string(payload, paylen, &ppos, &data, &datalen) < 0)
        return -1;

    /* Read flags (ignored for Ed25519) */
    uint32_t flags = 0;
    read_uint32(payload, paylen, &ppos, &flags);

    /* Find matching key */
    int kidx = find_key_by_blob(key_blob, key_blob_len);
    if (kidx < 0) return -1;

    /* Sign */
    uint8_t signature[ED25519_SIG];
    if (ed25519_sign(_keys[kidx].seed, data, datalen, signature) < 0)
        return -1;

    /* Build response:
     * uint32(outer_len) || byte(14) || string(sig_blob)
     * sig_blob = string("ssh-ed25519") || string(signature_64)
     * sig_blob size = 4+11+4+64 = 83 bytes
     */
    #define SIG_BLOB_SIZE 83

    size_t pos = 4; /* skip outer length */

    resp[pos++] = SSH_AGENT_SIGN_RESPONSE;

    /* Build signature blob in-place */
    /* First, write outer string length for sig_blob */
    write_uint32(resp, &pos, SIG_BLOB_SIZE);
    /* sig_blob contents */
    write_string(resp, &pos, (const uint8_t *)"ssh-ed25519", 11);
    write_string(resp, &pos, signature, ED25519_SIG);

    /* Fill in outer length */
    size_t msg_len = pos - 4;
    size_t lpos = 0;
    write_uint32(resp, &lpos, msg_len);

    return (int)pos;
}

/* Send a simple failure response */
static int build_failure(uint8_t *resp) {
    size_t pos = 0;
    write_uint32(resp, &pos, 1);  /* length = 1 byte */
    resp[pos++] = SSH_AGENT_FAILURE;
    return (int)pos;
}

/* ========== Socket I/O ========== */

/* Read exactly n bytes from fd. Returns 0 on success, -1 on error/EOF. */
static int read_exact(int fd, uint8_t *buf, size_t n) {
    size_t done = 0;
    while (done < n) {
        ssize_t r = read(fd, buf + done, n - done);
        if (r <= 0) {
            if (r < 0 && errno == EINTR) continue;
            return -1;
        }
        done += r;
    }
    return 0;
}

/* Write exactly n bytes to fd. Returns 0 on success, -1 on error. */
static int write_exact(int fd, const uint8_t *buf, size_t n) {
    size_t done = 0;
    while (done < n) {
        ssize_t w = write(fd, buf + done, n - done);
        if (w <= 0) {
            if (w < 0 && errno == EINTR) continue;
            return -1;
        }
        done += w;
    }
    return 0;
}

/* Handle a single client connection (may have multiple messages) */
static void handle_client(int client_fd) {
    uint8_t lenbuf[4];
    uint8_t *msg = NULL;
    uint8_t *resp = NULL;

    /* Allocate response buffer (generous size) */
    resp = malloc(MAX_MSG);
    if (!resp) goto done;

    while (1) {
        /* Read 4-byte message length */
        if (read_exact(client_fd, lenbuf, 4) < 0) break;

        uint32_t msglen = ((uint32_t)lenbuf[0] << 24) | ((uint32_t)lenbuf[1] << 16) |
                          ((uint32_t)lenbuf[2] << 8) | lenbuf[3];

        if (msglen == 0 || msglen > MAX_MSG) break;

        /* Read message body */
        msg = malloc(msglen);
        if (!msg) break;
        if (read_exact(client_fd, msg, msglen) < 0) { free(msg); msg = NULL; break; }

        uint8_t msg_type = msg[0];
        int resp_len;

        switch (msg_type) {
        case SSH_AGENTC_REQUEST_IDENTITIES:
            resp_len = handle_identities(resp, MAX_MSG);
            break;

        case SSH_AGENTC_SIGN_REQUEST:
            resp_len = handle_sign(msg + 1, msglen - 1, resp, MAX_MSG);
            break;

        case SSH_AGENTC_REMOVE_ALL_IDENTITIES:
            chez_ssh_agent_remove_all();
            resp_len = 5; /* length(4) + SUCCESS(1) */
            { size_t p = 0; write_uint32(resp, &p, 1); resp[4] = SSH_AGENT_SUCCESS; }
            break;

        default:
            resp_len = -1;
            break;
        }

        if (resp_len < 0) {
            resp_len = build_failure(resp);
        }

        write_exact(client_fd, resp, resp_len);

        free(msg);
        msg = NULL;
    }

done:
    if (msg) free(msg);
    if (resp) free(resp);
    close(client_fd);
}

/* ========== Socket Server ========== */

static void *agent_thread_fn(void *arg) {
    (void)arg;

    /* Block signals in this thread — let main thread handle them */
    sigset_t all;
    sigfillset(&all);
    pthread_sigmask(SIG_BLOCK, &all, NULL);

    while (_agent_running) {
        struct pollfd pfds[2];
        pfds[0].fd = _agent_fd;
        pfds[0].events = POLLIN;
        pfds[1].fd = _agent_wakeup_pipe[0];
        pfds[1].events = POLLIN;

        int nready = poll(pfds, 2, -1);
        if (nready < 0) {
            if (errno == EINTR) continue;
            break;
        }

        /* Wakeup pipe signalled — time to stop */
        if (pfds[1].revents & POLLIN) break;

        /* New client connection */
        if (pfds[0].revents & POLLIN) {
            int client = accept(_agent_fd, NULL, NULL);
            if (client < 0) {
                if (errno == EINTR || errno == EAGAIN) continue;
                break;
            }
            handle_client(client);
        }
    }

    return NULL;
}

int chez_ssh_agent_start(const char *socket_dir) {
    if (_agent_running) return 0;  /* already running */

    /* Determine socket directory */
    const char *dir = socket_dir;
    if (!dir || dir[0] == '\0') {
        dir = getenv("XDG_RUNTIME_DIR");
        if (!dir) dir = "/tmp";
    }

    /* Create agent-specific subdirectory: <dir>/jsh-agent-<pid>/ */
    pid_t pid = getpid();
    snprintf(_agent_dir, sizeof(_agent_dir), "%s/jsh-agent-%d", dir, pid);
    if (mkdir(_agent_dir, 0700) < 0 && errno != EEXIST) return -1;

    /* Socket path: <dir>/jsh-agent-<pid>/agent.<pid> */
    snprintf(_agent_path, sizeof(_agent_path), "%s/agent.%d", _agent_dir, pid);

    /* Remove stale socket */
    unlink(_agent_path);

    /* Create Unix domain socket */
    _agent_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (_agent_fd < 0) return -1;

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, _agent_path, sizeof(addr.sun_path) - 1);

    if (bind(_agent_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(_agent_fd); _agent_fd = -1; return -1;
    }

    /* Owner-only access */
    chmod(_agent_path, 0600);

    if (listen(_agent_fd, 8) < 0) {
        close(_agent_fd); _agent_fd = -1;
        unlink(_agent_path);
        return -1;
    }

    /* Create wakeup pipe for clean shutdown */
    if (pipe(_agent_wakeup_pipe) < 0) {
        close(_agent_fd); _agent_fd = -1;
        unlink(_agent_path);
        return -1;
    }

    /* Start accept thread */
    _agent_running = 1;
    if (pthread_create(&_agent_thread, NULL, agent_thread_fn, NULL) != 0) {
        _agent_running = 0;
        close(_agent_fd); _agent_fd = -1;
        close(_agent_wakeup_pipe[0]); close(_agent_wakeup_pipe[1]);
        _agent_wakeup_pipe[0] = _agent_wakeup_pipe[1] = -1;
        unlink(_agent_path);
        return -1;
    }

    return 0;
}

const char *chez_ssh_agent_get_socket_path(void) {
    if (!_agent_running) return NULL;
    return _agent_path;
}

int chez_ssh_agent_is_running(void) {
    return _agent_running;
}

void chez_ssh_agent_stop(void) {
    if (!_agent_running) return;

    _agent_running = 0;

    /* Signal the accept thread to wake up */
    if (_agent_wakeup_pipe[1] >= 0) {
        uint8_t byte = 1;
        ssize_t r;
        do { r = write(_agent_wakeup_pipe[1], &byte, 1); } while (r < 0 && errno == EINTR);
    }

    pthread_join(_agent_thread, NULL);

    if (_agent_fd >= 0) { close(_agent_fd); _agent_fd = -1; }
    if (_agent_wakeup_pipe[0] >= 0) { close(_agent_wakeup_pipe[0]); _agent_wakeup_pipe[0] = -1; }
    if (_agent_wakeup_pipe[1] >= 0) { close(_agent_wakeup_pipe[1]); _agent_wakeup_pipe[1] = -1; }

    /* Clean up socket file and directory */
    if (_agent_path[0]) { unlink(_agent_path); _agent_path[0] = '\0'; }
    if (_agent_dir[0])  { rmdir(_agent_dir);   _agent_dir[0] = '\0'; }

    /* Zero all keys */
    chez_ssh_agent_remove_all();
}
