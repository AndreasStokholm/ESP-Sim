/*
 * Host tests for the Omnipod 5 side: P-256 and the pod's certificate, AID
 * answers, 244-byte packets, and, against OmnipodKit's own computations
 * (golden_o5.h, from tools/o5golden), pairing and a whole session.
 */
#include <pthread.h>
#include <stdlib.h>
#include <unistd.h>

#include "dash_internal.h"
#include "host_io.h"
#include "test.h"

#if __has_include("golden_o5.h")
#include "golden_o5.h"
#define HAVE_GOLDEN_O5 1
#include "golden_dash.h" /* an EAP-AKA challenge to reuse */
#endif

static uint8_t buf[4096];

/* ---- random bytes the tests choose ---------------------------------------------- */

static uint8_t planned[64];
static size_t planned_len, planned_at;
static pthread_mutex_t planned_mu = PTHREAD_MUTEX_INITIALIZER;

static void planned_random(uint8_t *p, size_t n)
{
    pthread_mutex_lock(&planned_mu);
    size_t take = planned_len - planned_at < n ? planned_len - planned_at : n;
    memcpy(p, planned + planned_at, take);
    planned_at += take;
    pthread_mutex_unlock(&planned_mu);
    if (take < n) {
        arc4random_buf(p + take, n - take);
    }
}

__attribute__((unused)) static void plan_random(const uint8_t *a, size_t an, const uint8_t *b, size_t bn)
{
    pthread_mutex_lock(&planned_mu);
    memcpy(planned, a, an);
    memcpy(planned + an, b, bn);
    planned_len = an + bn;
    planned_at = 0;
    pthread_mutex_unlock(&planned_mu);
    dash_random_hook = planned_random;
}

/* ---- the certificate ------------------------------------------------------------- */

static const uint8_t SPKI[] = {0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06,
                               0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04};

/* Reads a DER tag and length at p: returns the header size, or 0. */
static size_t der(const uint8_t *p, uint8_t tag, size_t *len)
{
    if (p[0] != tag) {
        return 0;
    }
    if (p[1] < 0x80) {
        *len = p[1];
        return 2;
    }
    if (p[1] == 0x81) {
        *len = p[2];
        return 3;
    }
    if (p[1] == 0x82) {
        *len = (size_t)p[2] << 8 | p[3];
        return 4;
    }
    return 0;
}

static void der_int32(const uint8_t *p, size_t n, uint8_t out[32])
{
    while (n > 32 && *p == 0) {
        p++;
        n--;
    }
    memset(out, 0, 32);
    memcpy(out + 32 - n, p, n);
}

/* What OmnipodKit takes from a pod certificate (O5CertificateStore), and
 * that it is properly self-signed. Returns the public key's offset, or -1. */
static int check_certificate(const uint8_t *cert, size_t n, const uint8_t pub[64])
{
    size_t len, h, at = -1;
    for (size_t i = 0; i + sizeof SPKI + 64 <= n; i++) {
        if (memcmp(cert + i, SPKI, sizeof SPKI) == 0) {
            at = i + sizeof SPKI;
            break;
        }
    }
    CHECK(at != (size_t)-1 && memcmp(cert + at, pub, 64) == 0);
    static const uint8_t v3[] = {0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x08};
    CHECK(memmem(cert, n, v3, sizeof v3) != NULL); /* a v3 certificate with an 8-byte serial */

    h = der(cert, 0x30, &len);
    CHECK(h && h + len == n);
    const uint8_t *tbs = cert + h;
    size_t th = der(tbs, 0x30, &len);
    size_t tbs_len = th + len;
    const uint8_t *alg = tbs + tbs_len;
    CHECK(alg[0] == 0x30 && alg[1] == 0x0a);
    const uint8_t *bits = alg + 12;
    size_t bh = der(bits, 0x03, &len);
    CHECK(bh && bits[bh] == 0);
    const uint8_t *seq = bits + bh + 1;
    size_t sh = der(seq, 0x30, &len);
    uint8_t sig[64];
    size_t rl, sl;
    size_t rh = der(seq + sh, 0x02, &rl);
    der_int32(seq + sh + rh, rl, sig);
    size_t sh2 = der(seq + sh + rh + rl, 0x02, &sl);
    der_int32(seq + sh + rh + rl + sh2, sl, sig + 32);
    CHECK(dash_p256_verify(pub, tbs, tbs_len, sig) == 0);
    return (int)at;
}

static void test_p256_and_certificate(void)
{
    uint8_t a[32], b[32], pa[64], pb[64], s1[32], s2[32], sig[64];
    CHECK(dash_p256_keygen(a) == 0 && dash_p256_keygen(b) == 0);
    CHECK(dash_p256_public(a, pa) == 0 && dash_p256_public(b, pb) == 0);
    CHECK(dash_p256_ecdh(a, pb, s1) == 0 && dash_p256_ecdh(b, pa, s2) == 0);
    CHECK(memcmp(s1, s2, 32) == 0);
    CHECK(dash_p256_sign(a, (const uint8_t *)"transcript", 10, sig) == 0);
    CHECK(dash_p256_verify(pa, (const uint8_t *)"transcript", 10, sig) == 0);
    CHECK(dash_p256_verify(pa, (const uint8_t *)"transcripT", 10, sig) != 0);
    CHECK(dash_p256_verify(pb, (const uint8_t *)"transcript", 10, sig) != 0);
    uint8_t bad[64];
    memset(bad, 0x42, 64);
    CHECK(dash_p256_ecdh(a, bad, s1) != 0); /* not a point on the curve */

    int n = dash_o5_certificate(a, buf, sizeof buf);
    CHECK(n > 200 && n < 600);
    if (n > 0) {
        check_certificate(buf, (size_t)n, pa);
    }
}

/* ---- AID ------------------------------------------------------------------------- */

static void aid(const void *cmd, size_t n, const char *want, size_t want_len)
{
    uint8_t out[512];
    int r = dash_o5_aid(cmd, n, out, sizeof out);
    CHECK_BYTES(out, r, (const uint8_t *)want, want_len);
}

#define AID(cmd, want) aid(cmd, sizeof cmd - 1, want, sizeof want - 1)

static void test_aid(void)
{
    AID("SE255.2=1789000000", "ES255.2=0");
    AID("S3.9=8,G3.9", "3.9=8");
    AID("S3.7=3670015,G3.7", "3.7=3670015");
    AID("S3.2=\x00\x03\x00\x0e\x00,G3.2", "3.2=\x00\x03\x00\x0e\x00");
    AID("S3.2=a,b,G3.2", "3.2=a,b"); /* binary data with a comma in it */
    AID("G3.11", "3.11=0");
    AID("G3.12", "3.12=0");
    uint8_t out[64];
    CHECK(dash_o5_aid((const uint8_t *)"S3.9=8,G3.8", 11, out, sizeof out) < 0);
    CHECK(dash_o5_aid((const uint8_t *)"Shello", 6, out, sizeof out) < 0);
    CHECK(dash_o5_aid((const uint8_t *)"G", 1, out, sizeof out) < 0);
}

/* ---- packets ----------------------------------------------------------------------- */

typedef struct {
    uint8_t b[8192];
    size_t len;
} flat_t;

static void emit2(void *ctx, const uint8_t *p, size_t n)
{
    flat_t *f = ctx;
    f->b[f->len++] = (uint8_t)(n >> 8);
    f->b[f->len++] = (uint8_t)n;
    memcpy(f->b + f->len, p, n);
    f->len += n;
}

static host_end_t frag_end, frag_sink;
static dash_pod_t frag_pod;

/* The pod reads a message from these packets (2-byte length, packet). */
static int read_back_o5(const uint8_t *pkts, size_t pkts_len, uint8_t *out)
{
    host_end_init(&frag_end);
    host_end_init(&frag_sink);
    host_link(&frag_end, &frag_sink);
    memset(&frag_pod, 0, sizeof frag_pod);
    frag_pod.io = &frag_end.io;
    frag_pod.st.pod_type = DASH_POD_O5;
    for (size_t at = 0; at < pkts_len;) {
        size_t l = (size_t)pkts[at] << 8 | pkts[at + 1];
        host_push(&frag_end, DASH_EV_DATA, pkts + at + 2, l);
        at += 2 + l;
    }
    /* The link layer hands over a TW message: give it a header. */
    static dash_msg_t m;
    if (dash_link_read_msg(&frag_pod, &m, 500) != DASH_LINK_OK) {
        return -1;
    }
    CHECK(frag_sink.count == 1 && frag_sink.q[0].data[0] == 4); /* Success */
    return dash_msg_marshal(&m, out, 4096);
}

static void test_packets(void)
{
    static const size_t sizes[] = {16, 30, 237, 238, 242, 243, 244, 300, 480, 481, 485, 486, 700, 1105, 1500};
    static uint8_t msg[2048], back[4096];
    for (size_t i = 0; i < sizeof sizes / sizeof sizes[0]; i++) {
        size_t n = sizes[i];
        dash_msg_t m;
        const uint8_t a[4] = {1, 2, 3, 4}, b[4] = {5, 6, 7, 8};
        dash_msg_new(&m, DASH_MSG_PAIRING, a, b);
        m.payload_len = n - 16;
        for (size_t k = 0; k < m.payload_len; k++) {
            m.payload[k] = (uint8_t)(k * 7);
        }
        int rn = dash_msg_marshal(&m, msg, sizeof msg);
        flat_t f = {.len = 0};
        dash_link_fragment_o5(msg, (size_t)rn, emit2, &f);
        int bn = read_back_o5(f.b, f.len, back);
        CHECK_BYTES(back, bn, msg, rn);
    }
#ifdef HAVE_GOLDEN_O5
    for (size_t i = 0; i < O5_FRAG_COUNT; i++) {
        flat_t f = {.len = 0};
        dash_link_fragment_o5(O5_FRAGS[i].msg, O5_FRAGS[i].msg_len, emit2, &f);
        CHECK_BYTES(f.b, f.len, O5_FRAGS[i].pkts, O5_FRAGS[i].pkts_len);
    }
#endif
}

#ifdef HAVE_GOLDEN_O5

/* ---- against OmnipodKit ------------------------------------------------------------- */

static void test_golden_crypto(void)
{
    uint8_t pub[64], shared[32];
    CHECK(dash_p256_public(O5_POD_PRIV, pub) == 0);
    CHECK_BYTES(pub, 64, O5_POD_PUB, 64);
    CHECK(dash_p256_public(O5_PDM_PRIV, pub) == 0);
    CHECK_BYTES(pub, 64, O5_PDM_PUB, 64);
    CHECK(dash_p256_ecdh(O5_POD_PRIV, O5_PDM_PUB, shared) == 0);
    CHECK_BYTES(shared, 32, O5_SHARED, 32);
    CHECK_BYTES(DASH_O5_FIRMWARE_ID, 6, O5_FIRMWARE_ID, 6);

    dash_o5_pair_t c;
    memset(&c, 0, sizeof c);
    memcpy(c.pdm_pub, O5_PDM_PUB, 64);
    memcpy(c.pod_pub, O5_POD_PUB, 64);
    memcpy(c.pdm_nonce, O5_PDM_NONCE, 16);
    memcpy(c.pod_nonce, O5_POD_NONCE, 16);
    dash_o5_derive(&c, O5_SHARED);
    CHECK_BYTES(c.conf, 16, O5_CONF, 16);
    CHECK_BYTES(c.ltk, 16, O5_LTK, 16);

    /* The certificate exchange's nonces, step by step as the phone takes them. */
    uint8_t nonce[13];
    dash_o5_sps_nonce(&c, true, nonce);
    CHECK_BYTES(nonce, 13, O5_SPS_NONCE_W0, 13);
    CHECK(dash_ccm_decrypt(O5_CONF, nonce, NULL, 0, O5_CT_PHONE21, sizeof O5_CT_PHONE21, buf) == 0);
    CHECK_BYTES(buf, sizeof O5_CT_PHONE21 - 8, O5_PHONE_CERT21, sizeof O5_PHONE_CERT21);
    dash_o5_nonce_increment(c.pdm_nonce);
    dash_o5_sps_nonce(&c, false, nonce);
    CHECK_BYTES(nonce, 13, O5_SPS_NONCE_R0, 13);
    dash_ccm_encrypt(O5_CONF, nonce, NULL, 0, O5_POD_CERT21, sizeof O5_POD_CERT21, buf);
    CHECK_BYTES(buf, sizeof O5_POD_CERT21 + 8, O5_CT_POD21, sizeof O5_CT_POD21);
    dash_o5_nonce_increment(c.pod_nonce);
    dash_o5_sps_nonce(&c, true, nonce);
    CHECK_BYTES(nonce, 13, O5_SPS_NONCE_W1, 13);
    CHECK(dash_ccm_decrypt(O5_CONF, nonce, NULL, 0, O5_CT_PHONE2, sizeof O5_CT_PHONE2, buf) == 0);
    CHECK_BYTES(buf, sizeof O5_CT_PHONE2 - 8, O5_PHONE_CERT2, sizeof O5_PHONE_CERT2);
    dash_o5_nonce_increment(c.pdm_nonce);
    /* The pod signs here: after SPS2's decryption, before its own encryption. */
    uint8_t transcript[171];
    dash_o5_pod_transcript(&c, transcript);
    CHECK_BYTES(transcript, 171, O5_POD_TRANSCRIPT, sizeof O5_POD_TRANSCRIPT);
    dash_o5_sps_nonce(&c, false, nonce);
    CHECK_BYTES(nonce, 13, O5_SPS_NONCE_R1, 13);
    dash_ccm_encrypt(O5_CONF, nonce, NULL, 0, O5_POD_CERT2, sizeof O5_POD_CERT2, buf);
    CHECK_BYTES(buf, sizeof O5_POD_CERT2 + 8, O5_CT_POD2, sizeof O5_CT_POD2);

    /* The Omnipod CRC-16 and a signed (Type 4) command. */
    CHECK(dash_crc16((const uint8_t *)"\x1d\x18\x00\xa0\x28\x00\x00\x04\x63\xff", 10) == O5_CRC16_0);
    dash_msg_t m;
    CHECK(dash_msg_unmarshal(O5_SIGNED_CMD, sizeof O5_SIGNED_CMD, &m) == 0);
    CHECK(m.type == DASH_MSG_ENCRYPTED_SIGNED && m.signed_ && m.eqos == 1 && m.seq == 9);
    CHECK(dash_decrypt_msg(O5_CK, O5_NONCE_PREFIX, 5, &m) == 0);
    CHECK_BYTES(m.payload, m.payload_len, O5_SIGNED_CMD_PLAIN, sizeof O5_SIGNED_CMD_PLAIN);
    dash_cmd_t cmd;
    CHECK(dash_cmd_parse(m.payload, m.payload_len, &cmd) == 0 && cmd.type == DASH_CMD_STOP_DELIVERY);

    /* Every AID setup command gets an answer with the prefix the phone expects. */
    static const struct {
        const uint8_t *cmd;
        size_t n;
        const char *prefix;
    } aids[] = {
        {O5_AID_UTC, sizeof O5_AID_UTC, O5_AID_UTC_PREFIX},
        {O5_AID_TDI, sizeof O5_AID_TDI, O5_AID_TDI_PREFIX},
        {O5_AID_TARGET, sizeof O5_AID_TARGET, O5_AID_TARGET_PREFIX},
        {O5_AID_DIA, sizeof O5_AID_DIA, O5_AID_DIA_PREFIX},
        {O5_AID_EGV, sizeof O5_AID_EGV, O5_AID_EGV_PREFIX},
        {O5_AID_HISTORY, sizeof O5_AID_HISTORY, O5_AID_HISTORY_PREFIX},
        {O5_AID_STATUS, sizeof O5_AID_STATUS, O5_AID_STATUS_PREFIX},
        {O5_AID_UNIFIED, sizeof O5_AID_UNIFIED, O5_AID_UNIFIED_PREFIX},
    };
    for (size_t i = 0; i < sizeof aids / sizeof aids[0]; i++) {
        int n = dash_o5_aid(aids[i].cmd, aids[i].n, buf, sizeof buf);
        CHECK(n >= (int)strlen(aids[i].prefix) && memcmp(buf, aids[i].prefix, strlen(aids[i].prefix)) == 0);
    }
}

/* ---- a whole Omnipod 5 pairing and session against a simulated phone ---------------- */

static host_end_t pod_end, phone_end;
static dash_pod_t pod, phone;
static const uint8_t PDM_ID[4] = {0x17, 0x00, 0x2c, 0x00};
static const uint8_t POD_ID[4] = {0x00, 0x00, 0x10, 0x25};
static uint8_t ck[16], prefix[8];
static uint64_t nonce_seq;
static uint8_t msg_seq = 20, cmd_seq;

static void *pod_thread(void *arg)
{
    dash_pod_run(&pod);
    return NULL;
}

static bool recv_msg(dash_msg_t *m)
{
    dash_link_t r = dash_link_read_msg(&phone, m, 3000);
    CHECK(r == DASH_LINK_OK);
    return r == DASH_LINK_OK;
}

/* The value of a "KEY=" + length + value field. */
static const uint8_t *field(const dash_msg_t *m, const char *key, size_t *len)
{
    size_t kl = strlen(key);
    if (m->payload_len < kl + 2 || memcmp(m->payload, key, kl) != 0) {
        return NULL;
    }
    *len = (size_t)m->payload[kl] << 8 | m->payload[kl + 1];
    return m->payload + kl + 2;
}

/* Sends a command payload encrypted (and, for signed, with a signature
 * after), and returns the pod's decrypted answer. Then ACKs it. */
static size_t exchange(const uint8_t *pl, size_t n, bool signed_, uint8_t *answer)
{
    static dash_msg_t m;
    uint8_t nonce[13];
    dash_msg_new(&m, signed_ ? DASH_MSG_ENCRYPTED_SIGNED : DASH_MSG_ENCRYPTED, PDM_ID, POD_ID);
    memcpy(m.payload, pl, n);
    m.payload_len = n;
    m.seq = ++msg_seq;
    m.eqos = 1;
    int rn = dash_msg_marshal(&m, buf, sizeof buf);
    /* As OmnipodKit writes it: without the Go pod's flag carry-over (which
     * would turn type 4 with eqos 1 into type 5). */
    buf[3] = m.type;
    dash_nonce(prefix, nonce_seq++, true, buf + 2048);
    memcpy(nonce, buf + 2048, 13);
    dash_ccm_encrypt(ck, nonce, buf, 16, buf + 16, (size_t)rn - 16, buf + 16);
    rn += 8;
    if (signed_) {
        memset(buf + rn, 0xee, 64);
        rn += 64;
    }
    CHECK(dash_link_write_raw(&phone, buf, (size_t)rn) == DASH_LINK_OK);

    if (!recv_msg(&m)) {
        return 0;
    }
    CHECK(m.type == DASH_MSG_ENCRYPTED && m.ack && m.ack_num == (uint8_t)(msg_seq + 1));
    dash_nonce(prefix, nonce_seq++, false, nonce);
    CHECK(dash_ccm_decrypt(ck, nonce, m.header, 16, m.payload, m.payload_len, m.payload) == 0);
    size_t an = m.payload_len - 8;
    memcpy(answer, m.payload, an);

    dash_msg_new(&m, DASH_MSG_ENCRYPTED, PDM_ID, POD_ID);
    m.seq = ++msg_seq;
    m.ack = true;
    rn = dash_msg_marshal(&m, buf, sizeof buf);
    dash_nonce(prefix, nonce_seq++, true, nonce);
    dash_ccm_encrypt(ck, nonce, buf, 16, buf + 16, 0, buf + 16);
    CHECK(dash_link_write_raw(&phone, buf, (size_t)rn + 8) == DASH_LINK_OK);
    usleep(20000);
    return an;
}

/* A pod command ("S0.0=" ... ",G0.0"), answered "0.0=" + message with CRC. */
static size_t command(const uint8_t *cmd, size_t cmd_len, bool signed_, uint8_t *body)
{
    uint8_t pl[300], answer[600];
    size_t il = 4 + 2 + cmd_len + 2;
    memcpy(pl, "S0.0=", 5);
    pl[5] = (uint8_t)(il >> 8);
    pl[6] = (uint8_t)il;
    memcpy(pl + 7, POD_ID, 4);
    uint16_t lsf = (uint16_t)((cmd_seq & 0x0f) << 10 | cmd_len);
    pl[11] = (uint8_t)(lsf >> 8);
    pl[12] = (uint8_t)lsf;
    memcpy(pl + 13, cmd, cmd_len);
    uint16_t crc = dash_crc16(pl + 7, 6 + cmd_len);
    pl[13 + cmd_len] = (uint8_t)(crc >> 8);
    pl[14 + cmd_len] = (uint8_t)crc;
    memcpy(pl + 15 + cmd_len, ",G0.0", 5);
    size_t an = exchange(pl, 20 + cmd_len, signed_, answer);
    cmd_seq = (uint8_t)((cmd_seq + 2) & 0x0f);
    if (an < 16 || memcmp(answer, "0.0=", 4) != 0) {
        CHECK(!"answer is not 0.0=");
        return 0;
    }
    size_t inner = (size_t)answer[4] << 8 | answer[5];
    const uint8_t *msg = answer + 6;
    CHECK(inner == an - 6);
    /* OmnipodKit checks the CRC on Omnipod 5 (Message(encodedData:checkCRC:)). */
    uint16_t got = (uint16_t)(msg[inner - 2] << 8 | msg[inner - 1]);
    CHECK(dash_crc16(msg, inner - 2) == got);
    CHECK(((msg[4] >> 2) & 0x0f) == ((cmd_seq - 1) & 0x0f));
    memcpy(body, msg + 6, inner - 8);
    return inner - 8;
}

static void send_raw(const uint8_t *raw, size_t n)
{
    CHECK(dash_link_write_raw(&phone, raw, n) == DASH_LINK_OK);
}

static bool pod_paired(void)
{
    pthread_mutex_lock(&pod_end.state_mu);
    bool b = pod_end.saved.paired && pod_end.saved.has_session;
    pthread_mutex_unlock(&pod_end.state_mu);
    return b;
}

static void test_o5_end_to_end(void)
{
    static dash_msg_t m;
    uint8_t body[300], nonce[13], identity[64];
    size_t n;
    const uint8_t *v;

    host_end_init(&pod_end);
    host_end_init(&phone_end);
    host_link(&pod_end, &phone_end);
    dash_pod_init(&pod, &pod_end.io, NULL);
    dash_pod_set_type(&pod, DASH_POD_O5);
    CHECK(pod.st.pod_type == DASH_POD_O5 && pod_end.adv_type == DASH_POD_O5 && !pod_end.adv_has_pdm_id);
    CHECK(dash_p256_public(pod.st.o5_key, identity) == 0);
    memset(&phone, 0, sizeof phone);
    phone.io = &phone_end.io;
    phone.st.pod_type = DASH_POD_O5;
    plan_random(O5_POD_PRIV, 32, O5_POD_NONCE, 16); /* the pod's pairing key and nonce */

    pthread_t t;
    pthread_create(&t, NULL, pod_thread, NULL);
    host_push(&pod_end, DASH_EV_CONNECTED, NULL, 0);
    const uint8_t hello[] = {0x06, 0x01, 0x04, 0x17, 0x00, 0x2c, 0x00};
    host_push(&pod_end, DASH_EV_CMD, hello, sizeof hello);

    /* Pairing, with the messages OmnipodKit builds. */
    send_raw(O5_MSG_SP1SP2, sizeof O5_MSG_SP1SP2);
    send_raw(O5_MSG_SPS0, sizeof O5_MSG_SPS0);
    CHECK(recv_msg(&m) && m.type == DASH_MSG_PAIRING);
    v = field(&m, "SPS0=", &n);
    CHECK(v && n == 5);
    if (v) CHECK_BYTES(v, n, O5_POD_SPS0_VALUE, 5);

    send_raw(O5_MSG_SPS1, sizeof O5_MSG_SPS1);
    CHECK(recv_msg(&m));
    v = field(&m, "SPS1=", &n);
    CHECK(v && n == 80);
    if (v) {
        CHECK_BYTES(v, 64, O5_POD_PUB, 64);
        CHECK_BYTES(v + 64, 16, O5_POD_NONCE, 16);
    }

    send_raw(O5_MSG_SPS21, sizeof O5_MSG_SPS21);
    CHECK(recv_msg(&m));
    v = field(&m, "SPS2.1=", &n);
    CHECK(v && n > 8 && dash_ccm_decrypt(O5_CONF, O5_SPS_NONCE_R0, NULL, 0, v, n, buf) == 0);
    if (v) check_certificate(buf, n - 8, identity);

    send_raw(O5_MSG_SPS2, sizeof O5_MSG_SPS2);
    CHECK(recv_msg(&m));
    v = field(&m, "SPS2=", &n);
    CHECK(v && n > 72 && dash_ccm_decrypt(O5_CONF, O5_SPS_NONCE_R1, NULL, 0, v, n, buf) == 0);
    if (v) {
        size_t cert = n - 8 - 64;
        check_certificate(buf, cert, identity);
        /* The signature OmnipodKit checks: over its pod transcript, with the
         * key in the pod's certificate. */
        CHECK(dash_p256_verify(identity, O5_POD_TRANSCRIPT, sizeof O5_POD_TRANSCRIPT, buf + cert) == 0);
    }

    send_raw(O5_MSG_SP0GP0, sizeof O5_MSG_SP0GP0);
    CHECK(recv_msg(&m));
    v = field(&m, "P0=", &n);
    CHECK(v && n == 1 && v[0] == 0xa5);

    /* EAP-AKA, as for DASH. */
    dash_msg_t eap;
    CHECK(dash_msg_unmarshal(G_EAP_REQ_RAW, sizeof G_EAP_REQ_RAW, &eap) == 0);
    dash_msg_new(&m, DASH_MSG_SESSION, PDM_ID, POD_ID);
    memcpy(m.payload, eap.payload, eap.payload_len);
    m.payload_len = eap.payload_len;
    m.seq = ++msg_seq;
    n = (size_t)dash_msg_marshal(&m, buf, sizeof buf);
    send_raw(buf, n);
    CHECK(recv_msg(&m) && m.type == DASH_MSG_SESSION);
    static const uint8_t OP[16] = {0xcd, 0xc2, 0x02, 0xd5, 0x12, 0x3e, 0x20, 0xf6,
                                   0x2b, 0x6d, 0x67, 0x6a, 0xc7, 0x2c, 0xb3, 0x18};
    uint8_t res[8];
    dash_milenage(O5_LTK, OP, eap.payload + 12, res, ck, NULL, NULL);
    CHECK_BYTES(m.payload + 12, 8, res, 8);
    memcpy(prefix, eap.payload + eap.payload_len - 4, 4);
    memcpy(prefix + 4, m.payload + 24, 4);
    dash_msg_new(&m, DASH_MSG_SESSION, PDM_ID, POD_ID);
    m.payload[0] = 3;
    m.payload[1] = eap.payload[1];
    m.payload[3] = 4;
    m.payload_len = 4;
    m.seq = ++msg_seq;
    n = (size_t)dash_msg_marshal(&m, buf, sizeof buf);
    send_raw(buf, n);
    nonce_seq = 1;
    for (int i = 0; i < 100 && !pod_paired(); i++) {
        usleep(10000);
    }
    CHECK(pod_paired());
    CHECK_BYTES(pod_end.saved.ltk, 16, O5_LTK, 16);
    CHECK(pod_end.adv_has_pdm_id && memcmp(pod_end.adv_pdm_id, PDM_ID, 4) == 0);
    uint8_t le[16];
    dash_o5_advertised_uuid(PDM_ID, le);
    CHECK(le[15] == 0xce && le[4] == 0x17 && le[1] == 0x00 && le[0] == 0x00); /* CE1F923D-...-0A17002C0000 */

    /* The phone's first command: the version, now an Omnipod 5's, with a CRC. */
    n = command((const uint8_t[]){0x07, 0x04, 0x00, 0x00, 0x10, 0x25}, 6, false, body);
    CHECK(n == 0x17 && body[0] == 0x01 && body[8] == 0x05);

    /* The AID setup commands. */
    size_t an = exchange(O5_AID_UTC, sizeof O5_AID_UTC, false, body);
    CHECK(an == strlen(O5_AID_UTC_PREFIX) + 1 && memcmp(body, O5_AID_UTC_PREFIX, an - 1) == 0);
    an = exchange(O5_AID_TARGET, sizeof O5_AID_TARGET, false, body);
    CHECK(an == strlen(O5_AID_TARGET_PREFIX) + 194 && memcmp(body, O5_AID_TARGET_PREFIX, 4) == 0);
    an = exchange(O5_AID_STATUS, sizeof O5_AID_STATUS, false, body);
    CHECK(an == 6 && memcmp(body, "3.11=0", 6) == 0);

    /* Setup, then a signed (Type 4) command. */
    n = command((const uint8_t[]){0x03, 0x13, 0x00, 0x00, 0x10, 0x25, 0, 0, 0, 0}, 10, false, body);
    CHECK(n == 0x1d && body[15] == 0x05);
    n = command((const uint8_t[]){0x1f, 0x05, 0x49, 0x4e, 0x53, 0x2e, 0x07}, 7, true, body);
    CHECK(n == 10 && body[0] == 0x1d);
    CHECK(!pod.st.basal_active);

    /* Back to DASH from the control panel: a new pod, advertised as DASH. */
    CHECK(dash_pod_panel_command(&pod, "{\"command\":\"setPodType\",\"value\":0}", 34) == NULL);
    CHECK(pod.st.pod_type == DASH_POD_DASH && !pod.st.paired && pod_end.adv_type == DASH_POD_DASH);

    host_push(&pod_end, DASH_EV_STOP, NULL, 0);
    pthread_join(t, NULL);
    dash_random_hook = NULL;
    (void)nonce;
}

#endif /* HAVE_GOLDEN_O5 */

void test_o5_all(void)
{
    test_p256_and_certificate();
    test_aid();
    test_packets();
#ifdef HAVE_GOLDEN_O5
    test_golden_crypto();
    test_o5_end_to_end();
#else
    fprintf(stderr, "golden_o5.h missing (run tools/o5golden): OmnipodKit comparisons skipped\n");
#endif
}
