/*
 * Bluetooth on NimBLE. One board, two devices: the pod, from the chip's
 * public address, and (when one is switched on) a Dexcom CGM, from a random
 * static address of its own. Each is a separate advertising set, so the phone
 * sees two peripherals and can be connected to both at once.
 *
 * They share one GATT database (NimBLE has one per host), so each device's
 * services are visible on the other's connection too: the apps pick their
 * device by advertisement and name, and writes to the other device's
 * characteristics are ignored. The GAP device name is answered per
 * connection, because the apps read it after connecting.
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
#include <string.h>

#include "app.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "host/ble_hs.h"
#include "host/util/util.h"
#include "nimble/nimble_port.h"
#include "nimble/nimble_port_freertos.h"
#include "services/gatt/ble_svc_gatt.h"

#include "dash_internal.h"

static const char *TAG = "ble";

#define POD_INSTANCE 0
#define CGM_INSTANCE 1

/* 1a7e4024-e3ed-4464-8b7e-751e03d0dc5f and its two characteristics, as
 * NimBLE wants 128-bit UUIDs: least significant byte first. */
#define DASH_UUID(b12, b13) \
    BLE_UUID128_INIT(0x5f, 0xdc, 0xd0, 0x03, 0x1e, 0x75, 0x7e, 0x8b, 0x64, 0x44, 0xed, 0xe3, b12, b13, 0x7e, 0x1a)

static const ble_uuid128_t svc_uuid = DASH_UUID(0x24, 0x40);
static const ble_uuid128_t cmd_uuid = DASH_UUID(0x41, 0x24);
static const ble_uuid128_t data_uuid = DASH_UUID(0x42, 0x24);    /* DASH */
static const ble_uuid128_t o5_data_uuid = DASH_UUID(0x43, 0x24); /* Omnipod 5 */

/* Dexcom: F808xxxx-849E-531C-C594-30F1F86A4EA5. */
#define DEX_UUID(b12, b13) \
    BLE_UUID128_INIT(0xa5, 0x4e, 0x6a, 0xf8, 0xf1, 0x30, 0x94, 0xc5, 0x1c, 0x53, 0x9e, 0x84, b12, b13, 0x08, 0xf8)

static const ble_uuid128_t dex_svc_uuid = DEX_UUID(0x32, 0x35);
static const ble_uuid128_t dex_chr_uuid[CGM_CHR_COUNT] = {
    [CGM_CHR_COMM] = DEX_UUID(0x33, 0x35),
    [CGM_CHR_CONTROL] = DEX_UUID(0x34, 0x35),
    [CGM_CHR_AUTH] = DEX_UUID(0x35, 0x35),
    [CGM_CHR_BACKFILL] = DEX_UUID(0x36, 0x35),
};
static const ble_uuid16_t dex_adv_uuid = BLE_UUID16_INIT(0xfebc);

static const ble_uuid16_t gap_svc_uuid = BLE_UUID16_INIT(0x1800);
static const ble_uuid16_t gap_name_uuid = BLE_UUID16_INIT(0x2a00);
static const ble_uuid16_t gap_appearance_uuid = BLE_UUID16_INIT(0x2a01);

static QueueHandle_t events;
static uint16_t cmd_handle, data_handle, o5_data_handle;
static uint16_t dex_handle[CGM_CHR_COUNT];
static volatile uint16_t pod_conn = BLE_HS_CONN_HANDLE_NONE;
static volatile uint16_t cgm_conn = BLE_HS_CONN_HANDLE_NONE;
static uint8_t own_addr_type;
static volatile bool synced;

static SemaphoreHandle_t adv_mu; /* the advertisements' contents below */
static dash_pod_type_t adv_type;
static bool adv_has_id, adv_has_pdm_id;
static uint8_t adv_id[4], adv_pdm_id[4], adv_fault, adv_alerts;
static bool cgm_adv_on;
static char cgm_adv_name[16];
static uint8_t cgm_adv_addr[6];

static void push(uint8_t type, const uint8_t *data, size_t n)
{
    dash_ev_t ev = {.type = type, .len = (uint8_t)n};
    if (n) {
        memcpy(ev.data, data, n);
    }
    if (xQueueSend(events, &ev, 0) != pdTRUE) {
        ESP_LOGW(TAG, "event queue full: a packet from the phone was dropped");
    }
}

static int flat(struct os_mbuf *om, uint8_t *buf, size_t cap, uint16_t *len)
{
    if (OS_MBUF_PKTLEN(om) > cap) {
        return BLE_ATT_ERR_INVALID_ATTR_VALUE_LEN;
    }
    return ble_hs_mbuf_to_flat(om, buf, (uint16_t)cap, len) == 0 ? 0 : BLE_ATT_ERR_UNLIKELY;
}

/* ---- the pod's characteristics ------------------------------------------- */

static int pod_access(uint16_t conn_handle, uint16_t attr_handle, struct ble_gatt_access_ctxt *ctxt, void *arg)
{
    if (ctxt->op != BLE_GATT_ACCESS_OP_WRITE_CHR) {
        return BLE_ATT_ERR_REQ_NOT_SUPPORTED;
    }
    uint8_t buf[DASH_PKT_MAX];
    uint16_t len = 0;
    int rc = flat(ctxt->om, buf, sizeof buf, &len);
    if (rc != 0 || conn_handle != pod_conn) {
        return rc; /* another device's connection: ignored */
    }
    push(attr_handle == cmd_handle ? DASH_EV_CMD : DASH_EV_DATA, buf, len);
    return 0;
}

/* ---- the CGM's characteristics ------------------------------------------- */

static int dex_access(uint16_t conn_handle, uint16_t attr_handle, struct ble_gatt_access_ctxt *ctxt, void *arg)
{
    cgm_chr_t chr = (cgm_chr_t)(intptr_t)arg;
    bool ours = conn_handle == cgm_conn;
    if (ctxt->op == BLE_GATT_ACCESS_OP_READ_CHR) {
        uint8_t buf[32];
        size_t n = ours ? cgm_app_on_read(chr, buf, sizeof buf) : 0;
        return os_mbuf_append(ctxt->om, buf, n) == 0 ? 0 : BLE_ATT_ERR_INSUFFICIENT_RES;
    }
    if (ctxt->op != BLE_GATT_ACCESS_OP_WRITE_CHR) {
        return BLE_ATT_ERR_REQ_NOT_SUPPORTED;
    }
    uint8_t buf[32];
    uint16_t len = 0;
    int rc = flat(ctxt->om, buf, sizeof buf, &len);
    if (rc == 0 && ours) {
        cgm_app_on_write(chr, buf, len);
    }
    return rc;
}

/* ---- GAP: the name depends on which device the phone connected to ---------- */

static int gap_access(uint16_t conn_handle, uint16_t attr_handle, struct ble_gatt_access_ctxt *ctxt, void *arg)
{
    if (ctxt->op != BLE_GATT_ACCESS_OP_READ_CHR) {
        return BLE_ATT_ERR_REQ_NOT_SUPPORTED;
    }
    if (ble_uuid_cmp(ctxt->chr->uuid, &gap_appearance_uuid.u) == 0) {
        uint16_t appearance = 0;
        return os_mbuf_append(ctxt->om, &appearance, 2) == 0 ? 0 : BLE_ATT_ERR_INSUFFICIENT_RES;
    }
    char name[16];
    xSemaphoreTake(adv_mu, portMAX_DELAY);
    strcpy(name, conn_handle == cgm_conn ? cgm_adv_name : DASH_ADVERTISED_NAME);
    xSemaphoreGive(adv_mu);
    return os_mbuf_append(ctxt->om, name, strlen(name)) == 0 ? 0 : BLE_ATT_ERR_INSUFFICIENT_RES;
}

#define DEX_CHR(c, fl) \
    {.uuid = &dex_chr_uuid[c].u, .access_cb = dex_access, .arg = (void *)(intptr_t)(c), .flags = (fl), \
     .val_handle = &dex_handle[c]}

static const struct ble_gatt_svc_def services[] = {
    {
        .type = BLE_GATT_SVC_TYPE_PRIMARY,
        .uuid = &gap_svc_uuid.u,
        .characteristics =
            (struct ble_gatt_chr_def[]){
                {.uuid = &gap_name_uuid.u, .access_cb = gap_access, .flags = BLE_GATT_CHR_F_READ},
                {.uuid = &gap_appearance_uuid.u, .access_cb = gap_access, .flags = BLE_GATT_CHR_F_READ},
                {0},
            },
    },
    {
        .type = BLE_GATT_SVC_TYPE_PRIMARY,
        .uuid = &svc_uuid.u,
        .characteristics =
            (struct ble_gatt_chr_def[]){
                {
                    .uuid = &cmd_uuid.u,
                    .access_cb = pod_access,
                    .flags = BLE_GATT_CHR_F_WRITE | BLE_GATT_CHR_F_WRITE_NO_RSP | BLE_GATT_CHR_F_NOTIFY,
                    .val_handle = &cmd_handle,
                },
                {
                    .uuid = &data_uuid.u,
                    .access_cb = pod_access,
                    .flags = BLE_GATT_CHR_F_WRITE | BLE_GATT_CHR_F_WRITE_NO_RSP | BLE_GATT_CHR_F_NOTIFY,
                    .val_handle = &data_handle,
                },
                {
                    .uuid = &o5_data_uuid.u,
                    .access_cb = pod_access,
                    .flags = BLE_GATT_CHR_F_WRITE | BLE_GATT_CHR_F_WRITE_NO_RSP | BLE_GATT_CHR_F_NOTIFY,
                    .val_handle = &o5_data_handle,
                },
                {0},
            },
    },
    {
        /* The apps subscribe with setNotifyValue: they take notifications
         * or indications alike, and notifications need no queueing here. */
        .type = BLE_GATT_SVC_TYPE_PRIMARY,
        .uuid = &dex_svc_uuid.u,
        .characteristics =
            (struct ble_gatt_chr_def[]){
                DEX_CHR(CGM_CHR_COMM, BLE_GATT_CHR_F_READ | BLE_GATT_CHR_F_NOTIFY),
                DEX_CHR(CGM_CHR_CONTROL, BLE_GATT_CHR_F_WRITE | BLE_GATT_CHR_F_NOTIFY | BLE_GATT_CHR_F_INDICATE),
                DEX_CHR(CGM_CHR_AUTH, BLE_GATT_CHR_F_READ | BLE_GATT_CHR_F_WRITE | BLE_GATT_CHR_F_NOTIFY |
                                          BLE_GATT_CHR_F_INDICATE),
                DEX_CHR(CGM_CHR_BACKFILL, BLE_GATT_CHR_F_READ | BLE_GATT_CHR_F_WRITE | BLE_GATT_CHR_F_NOTIFY),
                {0},
            },
    },
    {0},
};

/* ---- advertising ------------------------------------------------------------ */

static int pod_gap_event(struct ble_gap_event *event, void *arg);
static int cgm_gap_event(struct ble_gap_event *event, void *arg);

/* (Re)starts an advertising set with these fields, from addr (NULL: public). */
static void adv_start(uint8_t instance, const struct ble_hs_adv_fields *fields, const struct ble_hs_adv_fields *rsp,
                      const uint8_t *addr, ble_gap_event_fn *cb)
{
    if (ble_gap_ext_adv_active(instance)) {
        ble_gap_ext_adv_stop(instance);
    }
    struct ble_gap_ext_adv_params params = {
        .connectable = 1,
        .scannable = 1,
        .legacy_pdu = 1,
        .itvl_min = 0x00f4, /* 152.5 ms, as the Go simulator */
        .itvl_max = 0x00f4,
        .channel_map = 0x07,
        .own_addr_type = addr ? BLE_OWN_ADDR_RANDOM : own_addr_type,
        .primary_phy = BLE_HCI_LE_PHY_1M,
        .secondary_phy = BLE_HCI_LE_PHY_1M,
        .tx_power = 127,
        .sid = instance,
    };
    int rc = ble_gap_ext_adv_configure(instance, &params, NULL, cb, NULL);
    if (rc == 0 && addr) {
        ble_addr_t a = {.type = BLE_ADDR_RANDOM};
        memcpy(a.val, addr, 6);
        rc = ble_gap_ext_adv_set_addr(instance, &a);
    }
    struct os_mbuf *d = NULL;
    if (rc == 0) {
        d = os_msys_get_pkthdr(BLE_HS_ADV_MAX_SZ, 0);
        rc = d ? ble_hs_adv_set_fields_mbuf(fields, d) : BLE_HS_ENOMEM;
        rc = rc == 0 ? ble_gap_ext_adv_set_data(instance, d) : (os_mbuf_free_chain(d), rc);
    }
    if (rc == 0) {
        d = os_msys_get_pkthdr(BLE_HS_ADV_MAX_SZ, 0);
        rc = d ? ble_hs_adv_set_fields_mbuf(rsp, d) : BLE_HS_ENOMEM;
        rc = rc == 0 ? ble_gap_ext_adv_rsp_set_data(instance, d) : (os_mbuf_free_chain(d), rc);
    }
    if (rc == 0) {
        rc = ble_gap_ext_adv_start(instance, 0, 0);
    }
    if (rc != 0) {
        ESP_LOGE(TAG, "could not advertise (set %u): %d", instance, rc);
    }
}

static void pod_advertise_now(void)
{
    if (!synced || pod_conn != BLE_HS_CONN_HANDLE_NONE) {
        return;
    }
    static ble_uuid16_t uuids[9];
    static ble_uuid128_t o5_uuid;
    struct ble_hs_adv_fields fields = {0};
    fields.flags = BLE_HS_ADV_F_DISC_GEN | BLE_HS_ADV_F_BREDR_UNSUP;

    xSemaphoreTake(adv_mu, portMAX_DELAY);
    if (adv_type == DASH_POD_O5) {
        /* One 128-bit UUID with the paired controller's id in it. */
        o5_uuid = (ble_uuid128_t)BLE_UUID128_INIT(0);
        dash_o5_advertised_uuid(adv_has_pdm_id ? adv_pdm_id : NULL, o5_uuid.value);
        fields.uuids128 = &o5_uuid;
        fields.num_uuids128 = 1;
        fields.uuids128_is_complete = 1;
    } else {
        uint16_t svc[9];
        dash_advertised_services(adv_has_id ? adv_id : NULL, adv_fault, adv_alerts, svc);
        for (int i = 0; i < 9; i++) {
            uuids[i] = (ble_uuid16_t)BLE_UUID16_INIT(0);
            uuids[i].value = svc[i];
        }
        fields.uuids16 = uuids;
        fields.num_uuids16 = 9;
        fields.uuids16_is_complete = 1;
    }
    xSemaphoreGive(adv_mu);

    struct ble_hs_adv_fields rsp = {0};
    rsp.name = (const uint8_t *)DASH_ADVERTISED_NAME;
    rsp.name_len = strlen(DASH_ADVERTISED_NAME);
    rsp.name_is_complete = 1;
    adv_start(POD_INSTANCE, &fields, &rsp, NULL, pod_gap_event);
}

static void cgm_advertise_now(void)
{
    if (!synced || cgm_conn != BLE_HS_CONN_HANDLE_NONE) {
        return;
    }
    xSemaphoreTake(adv_mu, portMAX_DELAY);
    bool on = cgm_adv_on;
    char name[16];
    uint8_t addr[6];
    strcpy(name, cgm_adv_name);
    memcpy(addr, cgm_adv_addr, 6);
    xSemaphoreGive(adv_mu);
    if (!on) {
        if (ble_gap_ext_adv_active(CGM_INSTANCE)) {
            ble_gap_ext_adv_stop(CGM_INSTANCE);
        }
        return;
    }
    /* Like a Dexcom: the FEBC service and the name, in the advertisement. */
    struct ble_hs_adv_fields fields = {0};
    fields.flags = BLE_HS_ADV_F_DISC_GEN | BLE_HS_ADV_F_BREDR_UNSUP;
    fields.uuids16 = &dex_adv_uuid;
    fields.num_uuids16 = 1;
    fields.uuids16_is_complete = 1;
    fields.name = (const uint8_t *)name;
    fields.name_len = strlen(name);
    fields.name_is_complete = 1;
    struct ble_hs_adv_fields rsp = {0};
    rsp.name = (const uint8_t *)name;
    rsp.name_len = strlen(name);
    rsp.name_is_complete = 1;
    adv_start(CGM_INSTANCE, &fields, &rsp, addr, cgm_gap_event);
}

/* ---- connections -------------------------------------------------------------- */

static int pod_gap_event(struct ble_gap_event *event, void *arg)
{
    switch (event->type) {
    case BLE_GAP_EVENT_CONNECT:
        if (event->connect.status == 0) {
            pod_conn = event->connect.conn_handle;
            ESP_LOGI(TAG, "phone connected to the pod");
            push(DASH_EV_CONNECTED, NULL, 0);
        } else {
            pod_advertise_now();
        }
        break;
    case BLE_GAP_EVENT_DISCONNECT:
        ESP_LOGI(TAG, "phone disconnected from the pod (reason 0x%x)", event->disconnect.reason);
        pod_conn = BLE_HS_CONN_HANDLE_NONE;
        push(DASH_EV_DISCONNECTED, NULL, 0);
        pod_advertise_now();
        break;
    case BLE_GAP_EVENT_ADV_COMPLETE:
        if (pod_conn == BLE_HS_CONN_HANDLE_NONE) {
            pod_advertise_now();
        }
        break;
    case BLE_GAP_EVENT_MTU:
        ESP_LOGI(TAG, "pod MTU %u", event->mtu.value);
        break;
    case BLE_GAP_EVENT_SUBSCRIBE:
        if (event->subscribe.attr_handle == cmd_handle || event->subscribe.attr_handle == data_handle ||
            event->subscribe.attr_handle == o5_data_handle) {
            ESP_LOGI(TAG, "%s notifications %s", event->subscribe.attr_handle == cmd_handle ? "CMD" : "DATA",
                     event->subscribe.cur_notify ? "on" : "off");
        }
        break;
    default:
        break;
    }
    return 0;
}

static int cgm_gap_event(struct ble_gap_event *event, void *arg)
{
    switch (event->type) {
    case BLE_GAP_EVENT_CONNECT:
        if (event->connect.status == 0) {
            cgm_conn = event->connect.conn_handle;
            cgm_app_on_connect();
        } else {
            cgm_advertise_now();
        }
        break;
    case BLE_GAP_EVENT_DISCONNECT:
        ESP_LOGI(TAG, "CGM link closed (reason 0x%x)", event->disconnect.reason);
        cgm_conn = BLE_HS_CONN_HANDLE_NONE;
        cgm_app_on_disconnect(); /* may advertise again */
        break;
    case BLE_GAP_EVENT_SUBSCRIBE:
        for (int c = 0; c < CGM_CHR_COUNT; c++) {
            if (event->subscribe.attr_handle == dex_handle[c]) {
                cgm_app_on_subscribe((cgm_chr_t)c, event->subscribe.cur_notify || event->subscribe.cur_indicate);
            }
        }
        break;
    default:
        break;
    }
    return 0;
}

static void on_sync(void)
{
    ble_hs_util_ensure_addr(0);
    ble_hs_id_infer_auto(0, &own_addr_type);
    uint8_t addr[6] = {0};
    ble_hs_id_copy_addr(own_addr_type, addr, NULL);
    ESP_LOGI(TAG, "pod's Bluetooth address %02X:%02X:%02X:%02X:%02X:%02X", addr[5], addr[4], addr[3], addr[2],
             addr[1], addr[0]);
    synced = true;
    pod_advertise_now();
    cgm_advertise_now();
}

static void on_reset(int reason)
{
    ESP_LOGW(TAG, "Bluetooth host reset: %d", reason);
    synced = false;
}

static void host_task(void *arg)
{
    nimble_port_run();
    nimble_port_freertos_deinit();
}

void ble_start(void)
{
    events = xQueueCreate(64, sizeof(dash_ev_t));
    adv_mu = xSemaphoreCreateMutex();
    ESP_ERROR_CHECK(nimble_port_init());
    ble_hs_cfg.sync_cb = on_sync;
    ble_hs_cfg.reset_cb = on_reset;
    /* Not NimBLE's GAP service: ours answers the name per connection. */
    ble_svc_gatt_init();
    ESP_ERROR_CHECK(ble_gatts_count_cfg(services));
    ESP_ERROR_CHECK(ble_gatts_add_svcs(services));
    nimble_port_freertos_init(host_task);
}

bool ble_connected(void)
{
    return pod_conn != BLE_HS_CONN_HANDLE_NONE;
}

static void notify(uint16_t c, uint16_t handle, const uint8_t *p, size_t n)
{
    if (c == BLE_HS_CONN_HANDLE_NONE) {
        return;
    }
    /* With a dozen fragments queued, NimBLE can run short of buffers for a
     * moment: wait for them rather than lose a fragment. */
    for (int tries = 0; tries < 100; tries++) {
        struct os_mbuf *om = ble_hs_mbuf_from_flat(p, (uint16_t)n);
        if (om) {
            int rc = ble_gatts_notify_custom(c, handle, om);
            if (rc == 0) {
                return;
            }
            if (rc != BLE_HS_ENOMEM) {
                ESP_LOGW(TAG, "notification failed: %d", rc);
                return;
            }
        }
        vTaskDelay(pdMS_TO_TICKS(5));
    }
    ESP_LOGW(TAG, "notification dropped: no buffers");
}

/* ---- the pod: the radio half of dash_io_t ------------------------------------- */

bool ble_next_event(void *ctx, dash_ev_t *ev, uint32_t timeout_ms)
{
    TickType_t t = timeout_ms == DASH_WAIT_FOREVER ? portMAX_DELAY : pdMS_TO_TICKS(timeout_ms);
    if (t == 0 && timeout_ms > 0) {
        t = 1;
    }
    return xQueueReceive(events, ev, t) == pdTRUE;
}

void ble_notify_cmd(void *ctx, const uint8_t *p, size_t n)
{
    notify(pod_conn, cmd_handle, p, n);
}

void ble_notify_data(void *ctx, const uint8_t *p, size_t n)
{
    notify(pod_conn, adv_type == DASH_POD_O5 ? o5_data_handle : data_handle, p, n);
}

void ble_disconnect(void *ctx)
{
    uint16_t c = pod_conn;
    if (c != BLE_HS_CONN_HANDLE_NONE) {
        ble_gap_terminate(c, BLE_ERR_REM_USER_CONN_TERM);
    }
}

void ble_advertise(void *ctx, const dash_adv_t *adv)
{
    xSemaphoreTake(adv_mu, portMAX_DELAY);
    adv_type = (dash_pod_type_t)adv->pod_type;
    adv_has_id = adv->id != NULL;
    if (adv->id) {
        memcpy(adv_id, adv->id, 4);
    }
    adv_has_pdm_id = adv->pdm_id != NULL;
    if (adv->pdm_id) {
        memcpy(adv_pdm_id, adv->pdm_id, 4);
    }
    adv_fault = adv->fault;
    adv_alerts = adv->alerts;
    bool paired = adv_type == DASH_POD_O5 ? adv_has_pdm_id : adv_has_id;
    xSemaphoreGive(adv_mu);
    ESP_LOGI(TAG, "advertising as %s %s pod (fault 0x%02x, alerts 0x%02x)", paired ? "a paired" : "an unpaired",
             adv_type == DASH_POD_O5 ? "Omnipod 5" : "DASH", adv->fault, adv->alerts);
    pod_advertise_now(); /* while a phone is connected, it takes effect when it leaves */
}

/* ---- the CGM: the radio half of cgm_io_t ---------------------------------------- */

void ble_cgm_send(void *ctx, cgm_chr_t chr, const uint8_t *p, size_t n)
{
    notify(cgm_conn, dex_handle[chr], p, n);
}

void ble_cgm_disconnect(void *ctx)
{
    uint16_t c = cgm_conn;
    if (c != BLE_HS_CONN_HANDLE_NONE) {
        ble_gap_terminate(c, BLE_ERR_REM_USER_CONN_TERM);
    }
}

void ble_cgm_advertise(void *ctx, bool on, const char *name, const uint8_t addr[6])
{
    xSemaphoreTake(adv_mu, portMAX_DELAY);
    cgm_adv_on = on;
    strncpy(cgm_adv_name, name, sizeof cgm_adv_name - 1);
    memcpy(cgm_adv_addr, addr, 6);
    xSemaphoreGive(adv_mu);
    cgm_advertise_now();
}
