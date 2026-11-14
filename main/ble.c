/*
 * The pod's Bluetooth side on NimBLE: the DASH GATT service with its command
 * and data characteristics, and the pod's advertisement.
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
#include "services/gap/ble_svc_gap.h"
#include "services/gatt/ble_svc_gatt.h"

#include "dash_internal.h"

static const char *TAG = "ble";

/* 1a7e4024-e3ed-4464-8b7e-751e03d0dc5f and its two characteristics, as
 * NimBLE wants 128-bit UUIDs: least significant byte first. */
#define DASH_UUID(b12, b13) \
    BLE_UUID128_INIT(0x5f, 0xdc, 0xd0, 0x03, 0x1e, 0x75, 0x7e, 0x8b, 0x64, 0x44, 0xed, 0xe3, b12, b13, 0x7e, 0x1a)

static const ble_uuid128_t svc_uuid = DASH_UUID(0x24, 0x40);
static const ble_uuid128_t cmd_uuid = DASH_UUID(0x41, 0x24);
static const ble_uuid128_t data_uuid = DASH_UUID(0x42, 0x24);    /* DASH */
static const ble_uuid128_t o5_data_uuid = DASH_UUID(0x43, 0x24); /* Omnipod 5 */

static QueueHandle_t events;
static uint16_t cmd_handle, data_handle, o5_data_handle;
static volatile uint16_t conn = BLE_HS_CONN_HANDLE_NONE;
static uint8_t own_addr_type;
static volatile bool synced;

static SemaphoreHandle_t adv_mu;
static dash_pod_type_t adv_type;
static bool adv_has_id, adv_has_pdm_id;
static uint8_t adv_id[4], adv_pdm_id[4], adv_fault, adv_alerts;

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

static int chr_access(uint16_t conn_handle, uint16_t attr_handle, struct ble_gatt_access_ctxt *ctxt, void *arg)
{
    if (ctxt->op != BLE_GATT_ACCESS_OP_WRITE_CHR) {
        return BLE_ATT_ERR_REQ_NOT_SUPPORTED;
    }
    uint8_t buf[DASH_PKT_MAX];
    uint16_t len = 0;
    if (OS_MBUF_PKTLEN(ctxt->om) > sizeof buf) {
        return BLE_ATT_ERR_INVALID_ATTR_VALUE_LEN;
    }
    if (ble_hs_mbuf_to_flat(ctxt->om, buf, sizeof buf, &len) != 0) {
        return BLE_ATT_ERR_UNLIKELY;
    }
    push(attr_handle == cmd_handle ? DASH_EV_CMD : DASH_EV_DATA, buf, len);
    return 0;
}

static const struct ble_gatt_svc_def services[] = {
    {
        .type = BLE_GATT_SVC_TYPE_PRIMARY,
        .uuid = &svc_uuid.u,
        .characteristics =
            (struct ble_gatt_chr_def[]){
                {
                    .uuid = &cmd_uuid.u,
                    .access_cb = chr_access,
                    .flags = BLE_GATT_CHR_F_WRITE | BLE_GATT_CHR_F_WRITE_NO_RSP | BLE_GATT_CHR_F_NOTIFY,
                    .val_handle = &cmd_handle,
                },
                {
                    .uuid = &data_uuid.u,
                    .access_cb = chr_access,
                    .flags = BLE_GATT_CHR_F_WRITE | BLE_GATT_CHR_F_WRITE_NO_RSP | BLE_GATT_CHR_F_NOTIFY,
                    .val_handle = &data_handle,
                },
                {
                    .uuid = &o5_data_uuid.u,
                    .access_cb = chr_access,
                    .flags = BLE_GATT_CHR_F_WRITE | BLE_GATT_CHR_F_WRITE_NO_RSP | BLE_GATT_CHR_F_NOTIFY,
                    .val_handle = &o5_data_handle,
                },
                {0},
            },
    },
    {0},
};

static int gap_event(struct ble_gap_event *event, void *arg);

static void start_advertising(void)
{
    if (!synced || conn != BLE_HS_CONN_HANDLE_NONE) {
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

    if (ble_gap_adv_active()) {
        ble_gap_adv_stop();
    }
    int rc = ble_gap_adv_set_fields(&fields);
    if (rc == 0) {
        rc = ble_gap_adv_rsp_set_fields(&rsp);
    }
    if (rc != 0) {
        ESP_LOGE(TAG, "could not set the advertisement: %d", rc);
        return;
    }
    struct ble_gap_adv_params params = {
        .conn_mode = BLE_GAP_CONN_MODE_UND,
        .disc_mode = BLE_GAP_DISC_MODE_GEN,
        .itvl_min = 0x00f4, /* 152.5 ms, as the Go simulator */
        .itvl_max = 0x00f4,
        .channel_map = 0x07,
    };
    rc = ble_gap_adv_start(own_addr_type, NULL, BLE_HS_FOREVER, &params, gap_event, NULL);
    if (rc != 0) {
        ESP_LOGE(TAG, "could not advertise: %d", rc);
    }
}

static int gap_event(struct ble_gap_event *event, void *arg)
{
    switch (event->type) {
    case BLE_GAP_EVENT_CONNECT:
        if (event->connect.status == 0) {
            conn = event->connect.conn_handle;
            ESP_LOGI(TAG, "phone connected");
            push(DASH_EV_CONNECTED, NULL, 0);
        } else {
            start_advertising();
        }
        break;
    case BLE_GAP_EVENT_DISCONNECT:
        ESP_LOGI(TAG, "phone disconnected (reason 0x%x)", event->disconnect.reason);
        conn = BLE_HS_CONN_HANDLE_NONE;
        push(DASH_EV_DISCONNECTED, NULL, 0);
        start_advertising();
        break;
    case BLE_GAP_EVENT_ADV_COMPLETE:
        start_advertising();
        break;
    case BLE_GAP_EVENT_MTU:
        ESP_LOGI(TAG, "MTU %u", event->mtu.value);
        break;
    case BLE_GAP_EVENT_SUBSCRIBE:
        ESP_LOGI(TAG, "%s notifications %s", event->subscribe.attr_handle == cmd_handle ? "CMD" : "DATA",
                 event->subscribe.cur_notify ? "on" : "off");
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
    ESP_LOGI(TAG, "Bluetooth address %02X:%02X:%02X:%02X:%02X:%02X", addr[5], addr[4], addr[3], addr[2], addr[1],
             addr[0]);
    synced = true;
    start_advertising();
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
    ble_svc_gap_init();
    ble_svc_gatt_init();
    ble_svc_gap_device_name_set(DASH_ADVERTISED_NAME);
    ESP_ERROR_CHECK(ble_gatts_count_cfg(services));
    ESP_ERROR_CHECK(ble_gatts_add_svcs(services));
    nimble_port_freertos_init(host_task);
}

bool ble_connected(void)
{
    return conn != BLE_HS_CONN_HANDLE_NONE;
}

/* ---- the radio half of dash_io_t ---------------------------------------- */

bool ble_next_event(void *ctx, dash_ev_t *ev, uint32_t timeout_ms)
{
    TickType_t t = timeout_ms == DASH_WAIT_FOREVER ? portMAX_DELAY : pdMS_TO_TICKS(timeout_ms);
    if (t == 0 && timeout_ms > 0) {
        t = 1;
    }
    return xQueueReceive(events, ev, t) == pdTRUE;
}

static void notify(uint16_t handle, const uint8_t *p, size_t n)
{
    uint16_t c = conn;
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

void ble_notify_cmd(void *ctx, const uint8_t *p, size_t n)
{
    notify(cmd_handle, p, n);
}

void ble_notify_data(void *ctx, const uint8_t *p, size_t n)
{
    notify(adv_type == DASH_POD_O5 ? o5_data_handle : data_handle, p, n);
}

void ble_disconnect(void *ctx)
{
    uint16_t c = conn;
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
    start_advertising(); /* while a phone is connected, it takes effect when it leaves */
}
