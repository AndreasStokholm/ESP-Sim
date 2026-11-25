/*
 * Host tests for the DASH pod core: published crypto vectors, byte-for-byte
 * agreement with the Go simulator it was ported from (golden_dash.h), and a
 * whole pairing + session + commands run against a simulated phone.
 */
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "dash_internal.h"
#include "golden_dash.h"
#include "host_io.h"
#include "test.h"

int failures, checks;

/* ---- published vectors -------------------------------------------------- */

static void test_crypto_vectors(void)
{
    uint8_t key[16], msg[64], want[64], out[64];

    /* CRC-32 (IEEE) of "123456789" */
    CHECK(dash_crc32((const uint8_t *)"123456789", 9) == 0xcbf43926u);

    /* RFC 4493 AES-CMAC examples 1, 2 and 4 */
    hex("2b7e151628aed2a6abf7158809cf4f3c", key);
    hex("bb1d6929e95937287fa37d129b756746", want);
    dash_cmac(key, NULL, 0, out);
    CHECK_BYTES(out, 16, want, 16);
    hex("6bc1bee22e409f96e93d7e117393172a", msg);
    hex("070a16b46b4d4144f79bdd9dd04a287c", want);
    dash_cmac(key, msg, 16, out);
    CHECK_BYTES(out, 16, want, 16);
    size_t n = hex("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51"
                   "30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
                   msg);
    hex("51f0bebf7e3b9d92fc49741779363cfe", want);
    dash_cmac(key, msg, n, out);
    CHECK_BYTES(out, 16, want, 16);

    /* RFC 3610 packet vector #1: 13-byte nonce, 8-byte tag */
    uint8_t nonce[13], aad[8], pt[23];
    hex("c0c1c2c3c4c5c6c7c8c9cacbcccdcecf", key);
    hex("00000003020100a0a1a2a3a4a5", nonce);
    hex("0001020304050607", aad);
    hex("08090a0b0c0d0e0f101112131415161718191a1b1c1d1e", pt);
    n = hex("588c979a61c663d2f066d0c2c0f989806d5f6b61dac38417e8d12cfdf926e0", want);
    dash_ccm_encrypt(key, nonce, aad, 8, pt, 23, out);
    CHECK_BYTES(out, 31, want, n);
    uint8_t back[64];
    CHECK(dash_ccm_decrypt(key, nonce, aad, 8, out, 31, back) == 0);
    CHECK_BYTES(back, 23, pt, 23);
    out[30] ^= 1;
    CHECK(dash_ccm_decrypt(key, nonce, aad, 8, out, 31, back) == -1);

    /* RFC 7748 section 5.2, first X25519 vector, and 6.1's key agreement */
    uint8_t s[32], u[32], r[32], w[32];
    hex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4", s);
    hex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c", u);
    hex("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552", w);
    dash_x25519(r, s, u);
    CHECK_BYTES(r, 32, w, 32);
    hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a", s);
    hex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a", w);
    dash_x25519_base(r, s);
    CHECK_BYTES(r, 32, w, 32);

    /* 3GPP TS 35.208 Milenage test set 1 */
    uint8_t k[16], op[16], rnd[16], res[8], ck[16], ik[16], ak[6];
    hex("465b5ce8b199b49faa5f0a2ee238a6bc", k);
    hex("cdc202d5123e20f62b6d676ac72cb318", op);
    hex("23553cbe9637a89d218ae64dae47bf35", rnd);
    dash_milenage(k, op, rnd, res, ck, ik, ak);
    hex("a54211d5e3ba50bf", want);
    CHECK_BYTES(res, 8, want, 8);
    hex("b40ba9a3c58b2a05bbf0d987b21bf8cb", want);
    CHECK_BYTES(ck, 16, want, 16);
    hex("f769bcd751044604127672711c6d3441", want);
    CHECK_BYTES(ik, 16, want, 16);
    hex("aa689c648370", want);
    CHECK_BYTES(ak, 6, want, 6);
}

/* ---- against the Go simulator ----------------------------------------------- */

static void put_field(dash_msg_t *m, const char *name, const uint8_t *v, size_t l)
{
    size_t nl = strlen(name);
    memcpy(m->payload + m->payload_len, name, nl);
    m->payload[m->payload_len + nl] = (uint8_t)(l >> 8);
    m->payload[m->payload_len + nl + 1] = (uint8_t)l;
    memcpy(m->payload + m->payload_len + nl + 2, v, l);
    m->payload_len += nl + 2 + l;
}

static uint8_t raw[4096];

static void test_golden_pairing(void)
{
    dash_pair_t c;
    dash_msg_t m;
    int n;

    dash_msg_new(&m, DASH_MSG_PAIRING, G_PAIR_PDM_ID, G_PAIR_POD_ID);
    put_field(&m, "SP1=", (const uint8_t[]){0, 0, 0x10, 0x24}, 4);
    put_field(&m, ",SP2=", (const uint8_t[]){0, 0, 0, 0x0a}, 4);
    CHECK(dash_pair_parse_sp1sp2(&c, &m) == 0);

    uint8_t v[48];
    memcpy(v, G_PAIR_PDM_PUB, 32);
    memcpy(v + 32, G_PAIR_PDM_NONCE, 16);
    dash_msg_new(&m, DASH_MSG_PAIRING, G_PAIR_PDM_ID, G_PAIR_POD_ID);
    put_field(&m, "SPS1=", v, 48);
    CHECK(dash_pair_parse_sps1(&c, &m) == 0);
    dash_pair_sps1(&c, &m);
    n = dash_msg_marshal(&m, raw, sizeof raw);
    CHECK_BYTES(raw, n, G_PAIR_SPS1_RAW, sizeof G_PAIR_SPS1_RAW);

    dash_msg_new(&m, DASH_MSG_PAIRING, G_PAIR_PDM_ID, G_PAIR_POD_ID);
    put_field(&m, "SPS2=", G_PAIR_PDM_CONF, 16);
    CHECK(dash_pair_parse_sps2(&c, &m) == 0);
    dash_pair_sps2(&c, &m);
    n = dash_msg_marshal(&m, raw, sizeof raw);
    CHECK_BYTES(raw, n, G_PAIR_SPS2_RAW, sizeof G_PAIR_SPS2_RAW);

    dash_msg_new(&m, DASH_MSG_PAIRING, G_PAIR_PDM_ID, G_PAIR_POD_ID);
    memcpy(m.payload, "SP0,GP0", 7);
    m.payload_len = 7;
    CHECK(dash_pair_parse_sp0gp0(&c, &m) == 0);
    dash_pair_p0(&c, &m);
    n = dash_msg_marshal(&m, raw, sizeof raw);
    CHECK_BYTES(raw, n, G_PAIR_P0_RAW, sizeof G_PAIR_P0_RAW);
    CHECK_BYTES(c.ltk, 16, G_PAIR_LTK, 16);

    /* A wrong confirmation value fails. */
    dash_msg_new(&m, DASH_MSG_PAIRING, G_PAIR_PDM_ID, G_PAIR_POD_ID);
    uint8_t bad[16];
    memcpy(bad, G_PAIR_PDM_CONF, 16);
    bad[0] ^= 1;
    put_field(&m, "SPS2=", bad, 16);
    CHECK(dash_pair_parse_sps2(&c, &m) != 0);
}

static void test_golden_eap(void)
{
    dash_msg_t m;
    dash_eap_t e;
    CHECK(dash_msg_unmarshal(G_EAP_REQ_RAW, sizeof G_EAP_REQ_RAW, &m) == 0);
    dash_eap_new(&e, G_PAIR_LTK, G_EAP_SQN_IN);
    CHECK(dash_eap_parse_challenge(&e, &m) == 0);
    CHECK(dash_eap_response(&e, &m) == 0);
    CHECK(m.payload_len == G_EAP_RSP_LEN);
    CHECK(m.payload[1] == G_EAP_RSP_IDENTIFIER);
    CHECK_BYTES(m.payload + 12, 8, G_EAP_RES, 8);
    CHECK_BYTES(m.payload + 24, 4, G_EAP_POD_IV, 4);
    CHECK(e.sqn == G_EAP_SQN_OUT);
    uint8_t ck[16], prefix[8];
    dash_eap_session(&e, ck, prefix);
    CHECK_BYTES(ck, 16, G_EAP_CK, 16);
    CHECK_BYTES(prefix, 8, G_EAP_NONCE_PREFIX, 8);

    dash_msg_t s;
    dash_msg_new(&s, DASH_MSG_SESSION, G_PAIR_PDM_ID, G_PAIR_POD_ID);
    s.payload[0] = 3;
    s.payload[1] = 0x2a;
    s.payload[2] = 0;
    s.payload[3] = 4;
    s.payload_len = 4;
    CHECK(dash_eap_parse_success(&s) == 0);
    s.payload[0] = 4;
    CHECK(dash_eap_parse_success(&s) != 0);
}

static void test_golden_session_crypto(void)
{
    dash_msg_t m;
    CHECK(dash_msg_unmarshal(G_CMD_GETVERSION_ENC, sizeof G_CMD_GETVERSION_ENC, &m) == 0);
    CHECK(dash_decrypt_msg(G_EAP_CK, G_EAP_NONCE_PREFIX, 1, &m) == 0);
    CHECK_BYTES(m.payload, m.payload_len, G_CMD_GETVERSION_PLAIN, sizeof G_CMD_GETVERSION_PLAIN);
    /* The wrong nonce sequence fails. */
    dash_msg_t m2;
    dash_msg_unmarshal(G_CMD_GETVERSION_ENC, sizeof G_CMD_GETVERSION_ENC, &m2);
    CHECK(dash_decrypt_msg(G_EAP_CK, G_EAP_NONCE_PREFIX, 2, &m2) != 0);

    dash_cmd_t c;
    CHECK(dash_cmd_parse(m.payload, m.payload_len, &c) == 0);
    CHECK(c.type == DASH_CMD_GET_VERSION);
    uint8_t body[256];
    size_t bl = dash_rsp_version(body, DASH_POD_DASH);
    dash_msg_t r;
    CHECK(dash_rsp_message(body, bl, 1, 2, 3, c.id, m.dst, m.src, false, &r) == 0);
    int n = dash_msg_marshal(&r, raw, sizeof raw);
    CHECK_BYTES(raw, n, G_RSP_VERSION_PLAIN, sizeof G_RSP_VERSION_PLAIN);
    n = dash_encrypt_raw(G_EAP_CK, G_EAP_NONCE_PREFIX, 2, raw, (size_t)n, sizeof raw);
    CHECK_BYTES(raw, n, G_RSP_VERSION_ENC, sizeof G_RSP_VERSION_ENC);
}

static void test_golden_responses(void)
{
    uint8_t out[256];
    size_t n;
    dash_status_t s;

    memset(&s, 0, sizeof s);
    n = dash_rsp_general(&s, out);
    CHECK_BYTES(out, n, G_RSP_GENERAL_DEFAULT, sizeof G_RSP_GENERAL_DEFAULT);

    s = (dash_status_t){.alerts = 0x82, .bolus_active = true, .basal_active = true, .progress = 8, .delivered = 0x1ab,
                        .bolus_remaining = 0x123, .minutes_active = 0x0abc, .reservoir = 3000, .last_prog_seq = 9};
    n = dash_rsp_general(&s, out);
    CHECK_BYTES(out, n, G_RSP_GENERAL_RUNNING, sizeof G_RSP_GENERAL_RUNNING);

    s = (dash_status_t){.temp_basal_active = true, .extended_bolus_active = true, .progress = 9, .delivered = 0x7ff,
                        .minutes_active = 4799, .reservoir = 0x2a5, .last_prog_seq = 15};
    n = dash_rsp_general(&s, out);
    CHECK_BYTES(out, n, G_RSP_GENERAL_LOW, sizeof G_RSP_GENERAL_LOW);

    s = (dash_status_t){.progress = 8, .basal_active = true, .bolus_active = true, .bolus_remaining = 0x0102,
                        .last_prog_seq = 5, .delivered = 0x0345, .reservoir = 900, .minutes_active = 0x0607,
                        .alerts = 0x10};
    n = dash_rsp_detailed(&s, out);
    CHECK_BYTES(out, n, G_RSP_DETAILED_OK, sizeof G_RSP_DETAILED_OK);

    s = (dash_status_t){.progress = 8, .bolus_active = true, .fault = 0x14, .fault_time = 0x0222,
                        .delivered = 0x0345, .reservoir = 5000, .minutes_active = 0x0607};
    n = dash_rsp_detailed(&s, out);
    CHECK_BYTES(out, n, G_RSP_DETAILED_FAULT, sizeof G_RSP_DETAILED_FAULT);

    const uint16_t trig[8] = {1, 0x203, 0, 0, 0, 0, 0, 0xfffe};
    n = dash_rsp_type1(trig, out);
    CHECK_BYTES(out, n, G_RSP_TYPE1, sizeof G_RSP_TYPE1);
    n = dash_rsp_type3(0x1c, 0x1234, 0x5678, out);
    CHECK_BYTES(out, n, G_RSP_TYPE3, sizeof G_RSP_TYPE3);
    n = dash_rsp_type5(0x1c, 0x12c0, 26, 11, 14, 10, 55, out);
    CHECK_BYTES(out, n, G_RSP_TYPE5, sizeof G_RSP_TYPE5);
    n = dash_rsp_type46(out);
    CHECK_BYTES(out, n, G_RSP_TYPE46, sizeof G_RSP_TYPE46);
    n = dash_rsp_type50(out);
    CHECK_BYTES(out, n, G_RSP_TYPE50, sizeof G_RSP_TYPE50);
    n = dash_rsp_type51(out);
    CHECK_BYTES(out, n, G_RSP_TYPE51, sizeof G_RSP_TYPE51);
    n = dash_rsp_nack(out);
    CHECK_BYTES(out, n, G_RSP_NACK, sizeof G_RSP_NACK);
    n = dash_rsp_set_unique_id(out, DASH_POD_DASH);
    CHECK_BYTES(out, n, G_RSP_SETUNIQUEID, sizeof G_RSP_SETUNIQUEID);
}

static void test_golden_messages(void)
{
    const uint8_t a[4] = {1, 2, 3, 4}, b[4] = {5, 6, 7, 8};
    dash_msg_t m;
    dash_msg_new(&m, DASH_MSG_ENCRYPTED, a, b);
    m.payload[0] = 0xaa;
    m.payload[1] = 0xbb;
    m.payload_len = 2;
    m.seq = 7;
    m.ack_num = 9;
    m.ack = true;
    m.eqos = 1;
    int n = dash_msg_marshal(&m, raw, sizeof raw);
    CHECK_BYTES(raw, n, G_MSG_ACK_EQOS1, sizeof G_MSG_ACK_EQOS1);

    dash_msg_new(&m, DASH_MSG_SESSION, a, b);
    m.sas = m.tfs = m.priority = m.last_message = m.gateway = true;
    m.eqos = 5;
    for (int i = 0; i < 300; i++) {
        m.payload[i] = (uint8_t)i;
    }
    m.payload_len = 300;
    n = dash_msg_marshal(&m, raw, sizeof raw);
    CHECK_BYTES(raw, n, G_MSG_FLAGS_LONG, sizeof G_MSG_FLAGS_LONG);
    /* SAS and TFS leak into the type bits (the Go quirk), so, as in Go, it
     * does not read back. */
    dash_msg_t back;
    CHECK(dash_msg_unmarshal(raw, (size_t)n, &back) != 0);

    /* Without flags that leak, the 11-bit length reads back. */
    m.sas = m.tfs = false;
    m.eqos = 2;
    n = dash_msg_marshal(&m, raw, sizeof raw);
    CHECK(dash_msg_unmarshal(raw, (size_t)n, &back) == 0);
    CHECK(back.payload_len == 300 && back.type == DASH_MSG_SESSION && back.eqos == 2 && back.gateway);
    CHECK(memcmp(back.payload, m.payload, 300) == 0);

    /* An encrypted-type message must carry its 8-byte tag. */
    CHECK(dash_msg_unmarshal(G_MSG_ACK_EQOS1, sizeof G_MSG_ACK_EQOS1, &back) != 0);
}

typedef struct {
    uint8_t buf[2048];
    size_t len;
} flat_t;

static void emit_flat(void *ctx, const uint8_t *p, size_t n)
{
    flat_t *f = ctx;
    f->buf[f->len++] = (uint8_t)n;
    memcpy(f->buf + f->len, p, n);
    f->len += n;
}

static host_end_t frag_end;
static dash_pod_t frag_pod;

/* Feeds packets to a pod end as the phone's writes and reads the message. */
static void read_back(const uint8_t *pkts, size_t pkts_len, const uint8_t *want, size_t want_len)
{
    host_end_init(&frag_end);
    memset(&frag_pod, 0, sizeof frag_pod);
    frag_pod.io = &frag_end.io;
    host_push(&frag_end, DASH_EV_CMD, (const uint8_t[]){0}, 1); /* RTS */
    for (size_t at = 0; at < pkts_len;) {
        size_t l = pkts[at];
        host_push(&frag_end, DASH_EV_DATA, pkts + at + 1, l);
        at += 1 + l;
    }
    dash_msg_t m;
    CHECK(dash_link_read_msg(&frag_pod, &m, 1000) == DASH_LINK_OK);
    int n = dash_msg_marshal(&m, raw, sizeof raw);
    CHECK_BYTES(raw, n, want, want_len);
}

static void test_golden_fragments(void)
{
    for (size_t i = 0; i < G_FRAG_COUNT; i++) {
        flat_t f = {.len = 0};
        dash_link_fragment(G_FRAGS[i].msg, G_FRAGS[i].msg_len, emit_flat, &f);
        CHECK_BYTES(f.buf, f.len, G_FRAGS[i].pkts, G_FRAGS[i].pkts_len);
        /* The pod's own packets read back, except for 14 to 18-byte
         * messages, where the Go writer puts 14 bytes in the first packet
         * and its reader (like the phone's writer) 13. */
        if (G_FRAGS[i].msg_len < 14 || G_FRAGS[i].msg_len > 18) {
            read_back(G_FRAGS[i].pkts, G_FRAGS[i].pkts_len, G_FRAGS[i].msg, G_FRAGS[i].msg_len);
        }
    }

    /* A 16-byte message as a phone sends it: 13 bytes, then 3. */
    const uint8_t *msg = G_FRAG_0_MSG;
    uint32_t sum = dash_crc32(msg, 16);
    uint8_t pk[64];
    size_t l = 0;
    pk[l++] = 20;
    const uint8_t first[7] = {0, 0, (uint8_t)(sum >> 24), (uint8_t)(sum >> 16), (uint8_t)(sum >> 8), (uint8_t)sum, 16};
    memcpy(pk + l, first, 7);
    memcpy(pk + l + 7, msg, 13);
    l += 20;
    pk[l++] = 5;
    pk[l++] = 1;
    pk[l++] = 3;
    memcpy(pk + l, msg + 13, 3);
    l += 3;
    read_back(pk, l, msg, 16);

    /* A corrupted packet is answered with Fail, and the message is lost. */
    flat_t f = {.len = 0};
    dash_link_fragment(G_FRAG_40_MSG, sizeof G_FRAG_40_MSG, emit_flat, &f);
    f.buf[5] ^= 0xff;
    host_end_init(&frag_end);
    memset(&frag_pod, 0, sizeof frag_pod);
    frag_pod.io = &frag_end.io;
    host_end_t sink;
    host_end_init(&sink);
    host_link(&frag_end, &sink);
    host_push(&frag_end, DASH_EV_CMD, (const uint8_t[]){0}, 1);
    for (size_t at = 0; at < f.len; at += 1 + f.buf[at]) {
        host_push(&frag_end, DASH_EV_DATA, f.buf + at + 1, f.buf[at]);
    }
    dash_msg_t m;
    CHECK(dash_link_read_msg(&frag_pod, &m, 300) == DASH_LINK_TIMEOUT);
    CHECK(sink.count == 2 && sink.q[0].data[0] == 1 && sink.q[1].data[0] == 5); /* CTS, Fail */
}

static const char *panel(const char *j);

/* ---- a whole session against a simulated phone --------------------------------- */

static host_end_t pod_end, phone_end;
static dash_pod_t pod, phone;
static uint8_t pdm_id[4] = {0x00, 0x00, 0x10, 0x24};
static uint8_t pod_addr[4] = {0xff, 0xff, 0xff, 0xfe};
static uint8_t ck[16], prefix[8];
static uint64_t nonce_seq;
static uint8_t msg_seq;
static uint8_t cmd_seq;

static void *pod_thread(void *arg)
{
    (void)arg;
    dash_pod_run(&pod);
    return NULL;
}

static void phone_send(dash_msg_t *m)
{
    CHECK(dash_link_write_msg(&phone, m) == DASH_LINK_OK);
}

static bool phone_recv(dash_msg_t *m)
{
    dash_link_t r = dash_link_read_msg(&phone, m, 3000);
    CHECK(r == DASH_LINK_OK);
    return r == DASH_LINK_OK;
}

static void phone_connect(void)
{
    host_push(&pod_end, DASH_EV_CONNECTED, NULL, 0);
    host_push(&pod_end, DASH_EV_CMD, (const uint8_t[]){0x06, 0x01, 0x04}, 3); /* hello */
}

static void phone_pair(void)
{
    dash_msg_t m;
    uint8_t v[48];

    dash_msg_new(&m, DASH_MSG_PAIRING, pdm_id, pod_addr);
    put_field(&m, "SP1=", (const uint8_t[]){0, 0, 0x10, 0x24}, 4);
    put_field(&m, ",SP2=", (const uint8_t[]){0, 0, 0, 0x0a}, 4);
    phone_send(&m);

    memcpy(v, G_PAIR_PDM_PUB, 32);
    memcpy(v + 32, G_PAIR_PDM_NONCE, 16);
    dash_msg_new(&m, DASH_MSG_PAIRING, pdm_id, pod_addr);
    put_field(&m, "SPS1=", v, 48);
    phone_send(&m);

    CHECK(phone_recv(&m));
    int n = dash_msg_marshal(&m, raw, sizeof raw);
    CHECK_BYTES(raw, n, G_PAIR_SPS1_RAW, sizeof G_PAIR_SPS1_RAW);

    dash_msg_new(&m, DASH_MSG_PAIRING, pdm_id, pod_addr);
    put_field(&m, "SPS2=", G_PAIR_PDM_CONF, 16);
    phone_send(&m);
    CHECK(phone_recv(&m));
    n = dash_msg_marshal(&m, raw, sizeof raw);
    CHECK_BYTES(raw, n, G_PAIR_SPS2_RAW, sizeof G_PAIR_SPS2_RAW);

    dash_msg_new(&m, DASH_MSG_PAIRING, pdm_id, pod_addr);
    memcpy(m.payload, "SP0,GP0", 7);
    m.payload_len = 7;
    phone_send(&m);
    CHECK(phone_recv(&m));
    n = dash_msg_marshal(&m, raw, sizeof raw);
    CHECK_BYTES(raw, n, G_PAIR_P0_RAW, sizeof G_PAIR_P0_RAW);
}

static void phone_session(void)
{
    dash_msg_t m;
    CHECK(dash_msg_unmarshal(G_EAP_REQ_RAW, sizeof G_EAP_REQ_RAW, &m) == 0);
    memcpy(m.dst, pod_addr, 4);
    phone_send(&m);
    CHECK(phone_recv(&m));
    CHECK(m.type == DASH_MSG_SESSION);
    CHECK_BYTES(m.payload + 12, 8, G_EAP_RES, 8);

    dash_msg_new(&m, DASH_MSG_SESSION, pdm_id, pod_addr);
    m.payload[0] = 3;
    m.payload[1] = 0x2a;
    m.payload[3] = 4;
    m.payload_len = 4;
    phone_send(&m);
    memcpy(ck, G_EAP_CK, 16);
    memcpy(prefix, G_EAP_NONCE_PREFIX, 8);
    nonce_seq = 1;
}

/* Sends one encrypted command and returns the pod's decrypted response body. */
static size_t phone_command(const uint8_t *cmd, size_t cmd_len, uint8_t *body)
{
    dash_msg_t m;
    uint8_t nonce[13];

    uint8_t inner[300];
    size_t il = 0;
    memcpy(inner, pod_addr, 4);
    il = 4;
    uint16_t lsf = (uint16_t)((cmd_seq & 0x0f) << 10 | cmd_len);
    inner[il++] = (uint8_t)(lsf >> 8);
    inner[il++] = (uint8_t)lsf;
    memcpy(inner + il, cmd, cmd_len);
    il += cmd_len;
    inner[il++] = 0;
    inner[il++] = 0;

    dash_msg_new(&m, DASH_MSG_ENCRYPTED, pdm_id, pod_addr);
    memcpy(m.payload, "S0.0=", 5);
    m.payload[5] = (uint8_t)(il >> 8);
    m.payload[6] = (uint8_t)il;
    memcpy(m.payload + 7, inner, il);
    memcpy(m.payload + 7 + il, ",G0.0", 5);
    m.payload_len = 12 + il;
    m.seq = ++msg_seq;
    int n = dash_msg_marshal(&m, raw, sizeof raw);
    dash_nonce(prefix, nonce_seq++, true, nonce);
    dash_ccm_encrypt(ck, nonce, raw, 16, raw + 16, (size_t)n - 16, raw + 16);
    CHECK(dash_link_write_raw(&phone, raw, (size_t)n + 8) == DASH_LINK_OK);

    if (!phone_recv(&m)) {
        return 0;
    }
    CHECK(m.type == DASH_MSG_ENCRYPTED && m.ack && m.ack_num == (uint8_t)(msg_seq + 1));
    dash_nonce(prefix, nonce_seq++, false, nonce);
    CHECK(dash_ccm_decrypt(ck, nonce, m.header, 16, m.payload, m.payload_len, m.payload) == 0);
    size_t pl = m.payload_len - 8;
    CHECK(pl >= 14 && memcmp(m.payload, "0.0=", 4) == 0);
    CHECK(((m.payload[10] << 8 | m.payload[11]) >> 10) == ((cmd_seq + 1) & 0x0f));
    size_t bl = pl - 14;
    memcpy(body, m.payload + 12, bl);

    /* The ACK: an encrypted message with nothing in it. */
    dash_msg_new(&m, DASH_MSG_ENCRYPTED, pdm_id, pod_addr);
    m.seq = ++msg_seq;
    n = dash_msg_marshal(&m, raw, sizeof raw);
    dash_nonce(prefix, nonce_seq++, true, nonce);
    dash_ccm_encrypt(ck, nonce, raw, 16, raw + 16, 0, raw + 16);
    CHECK(dash_link_write_raw(&phone, raw, (size_t)n + 8) == DASH_LINK_OK);
    cmd_seq = (uint8_t)((cmd_seq + 2) & 0x0f);
    usleep(20000); /* let the pod take the ACK */
    return bl;
}

static bool wait_for(bool (*cond)(void))
{
    for (int i = 0; i < 200; i++) {
        if (cond()) {
            return true;
        }
        usleep(10000);
    }
    return false;
}

static bool pod_is_paired(void)
{
    pthread_mutex_lock(&pod_end.state_mu);
    bool b = pod_end.saved.paired && pod_end.saved.has_session;
    pthread_mutex_unlock(&pod_end.state_mu);
    return b;
}

static bool pod_is_fresh(void)
{
    pthread_mutex_lock(&pod_end.state_mu);
    bool b = !pod_end.saved.paired && pod_end.saves > 0;
    pthread_mutex_unlock(&pod_end.state_mu);
    return b;
}

static const char *panel(const char *j)
{
    return dash_pod_panel_command(&pod, j, strlen(j));
}

static void test_end_to_end(void)
{
    uint8_t body[256], want[256];
    size_t n, wn;

    host_end_init(&pod_end);
    host_end_init(&phone_end);
    host_link(&pod_end, &phone_end);
    dash_pod_init(&pod, &pod_end.io, NULL);
    memset(&phone, 0, sizeof phone);
    phone.io = &phone_end.io;

    pthread_t t;
    pthread_create(&t, NULL, pod_thread, NULL);
    usleep(20000);
    CHECK(pod_end.adverts >= 1 && !pod_end.adv_has_id);

    phone_connect();
    phone_pair();
    phone_session();
    CHECK(wait_for(pod_is_paired));
    CHECK_BYTES(pod_end.saved.ltk, 16, G_PAIR_LTK, 16);

    /* GET_VERSION: the hardcoded version response */
    n = phone_command((const uint8_t[]){0x07, 0x04, 0x00, 0x00, 0x10, 0x24}, 6, body);
    wn = dash_rsp_version(want, DASH_POD_DASH);
    CHECK_BYTES(body, n, want, wn);
    CHECK(pod.st.progress == DASH_PROGRESS_REMINDER_INITIALIZED);

    /* SET_UNIQUE_ID: the pod takes the new id and advertises it */
    n = phone_command((const uint8_t[]){0x03, 0x13, 0x17, 0x01, 0x02, 0x03, 0, 0, 0, 0}, 10, body);
    wn = dash_rsp_set_unique_id(want, DASH_POD_DASH);
    CHECK_BYTES(body, n, want, wn);
    CHECK(pod_end.adv_has_id && memcmp(pod_end.adv_id, (const uint8_t[]){0x17, 0x01, 0x02, 0x03}, 4) == 0);
    CHECK(pod.st.progress == DASH_PROGRESS_PAIRING_COMPLETED);

    /* PROGRAM_INSULIN, table 2: the 52-pulse prime */
    n = phone_command((const uint8_t[]){0x1a, 0x0e, 0, 0, 0, 0, 0x02, 0, 0, 0x01, 0, 0, 0, 0x34, 0x00}, 15, body);
    CHECK(n == 10 && body[0] == 0x1d);
    CHECK((body[1] & 0x0f) == DASH_PROGRESS_PRIMING);
    CHECK(body[1] & 0x40); /* bolus active */
    CHECK(pod.st.reservoir == 3000 - 52 && pod.st.delivered == 52);
    uint16_t remaining = (uint16_t)((body[4] & 7) << 8 | body[5]);
    CHECK(remaining >= 51 && remaining <= 53);

    /* GET_STATUS 0x46: hardcoded */
    n = phone_command((const uint8_t[]){0x0e, 0x01, 0x46}, 3, body);
    wn = dash_rsp_type46(want);
    CHECK_BYTES(body, n, want, wn);

    /* The prime finishes; a fault from the control panel shows in a detailed status. */
    host_clock_advance(60000);
    CHECK(panel("{\"command\":\"setFault\",\"value\":20}") == NULL);
    CHECK(pod_end.adv_fault == 20);
    n = phone_command((const uint8_t[]){0x0e, 0x01, 0x00}, 3, body);
    CHECK(n == 24 && body[0] == 0x02 && body[2] == 0x02 && body[10] == 20);
    CHECK((body[19] & 0x0f) == DASH_PROGRESS_PRIMING_COMPLETED);
    CHECK(panel("{\"command\":\"setFault\",\"value\":0}") == NULL);

    char json[1024];
    CHECK(dash_pod_status_json(&pod, json, sizeof json) > 0);
    CHECK(strstr(json, "\"id\":\"17010203\"") && strstr(json, "\"paired\":true"));
    CHECK(strstr(json, "\"progressName\":\"Priming completed\""));
    CHECK(panel("{\"command\":\"bogus\"}") != NULL);
    CHECK(panel("{\"command\":\"changeReservoir\",\"value\":500}") != NULL);

    /* A new connection starts a new session: hello, then EAP-AKA again. */
    phone_connect();
    usleep(50000);
    phone_session();
    usleep(50000);
    n = phone_command((const uint8_t[]){0x0e, 0x01, 0x00}, 3, body);
    CHECK(n == 10 && body[0] == 0x1d);

    /* An unknown command gets the NACK response. */
    n = phone_command((const uint8_t[]){0x42, 0x01, 0x00}, 3, body);
    wn = dash_rsp_nack(want);
    CHECK_BYTES(body, n, want, wn);

    /* A bad tag ends the connection, not the pod. */
    int before = pod_end.disconnects;
    {
        dash_msg_t m;
        dash_msg_new(&m, DASH_MSG_ENCRYPTED, pdm_id, pod_addr);
        m.seq = ++msg_seq;
        memset(m.payload, 0x55, 20);
        m.payload_len = 20;
        int rn = dash_msg_marshal(&m, raw, sizeof raw);
        CHECK(dash_link_write_raw(&phone, raw, (size_t)rn + 8) == DASH_LINK_OK);
    }
    usleep(100000);
    CHECK(pod_end.disconnects == before + 1);

    /* After a reconnect, DEACTIVATE makes it a new, unpaired pod. */
    phone_connect();
    usleep(50000);
    phone_session();
    usleep(50000);
    n = phone_command((const uint8_t[]){0x1c, 0x04, 0, 0, 0, 0}, 6, body);
    CHECK(n == 10 && body[0] == 0x1d);
    CHECK(wait_for(pod_is_fresh));
    CHECK(!pod_end.adv_has_id);

    host_push(&pod_end, DASH_EV_STOP, NULL, 0);
    pthread_join(t, NULL);
}

void test_o5_all(void);
void test_cgm_all(void);
void test_ypso_all(void);

int main(void)
{
    test_crypto_vectors();
    test_golden_pairing();
    test_golden_eap();
    test_golden_session_crypto();
    test_golden_responses();
    test_golden_messages();
    test_golden_fragments();
    test_end_to_end();
    test_o5_all();
    test_cgm_all();
    test_ypso_all();
    printf("%d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}
