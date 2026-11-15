/* The ESP32 side of ESP-Sim: radio, storage and control panel.
 * SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include "cgm.h"
#include "dash.h"

/* ble.c: the pod's GATT service and advertising (NimBLE). */
void ble_start(void);
/* The dash_io_t radio half: events from the phone, notifications to it. */
bool ble_next_event(void *ctx, dash_ev_t *ev, uint32_t timeout_ms);
void ble_notify_cmd(void *ctx, const uint8_t *p, size_t n);
void ble_notify_data(void *ctx, const uint8_t *p, size_t n);
void ble_disconnect(void *ctx);
void ble_advertise(void *ctx, const dash_adv_t *adv);
bool ble_connected(void);
/* The cgm_io_t radio half, for the CGM's own advertising set and connection. */
void ble_cgm_send(void *ctx, cgm_chr_t chr, const uint8_t *p, size_t n);
void ble_cgm_disconnect(void *ctx);
void ble_cgm_advertise(void *ctx, bool on, const char *name, const uint8_t addr[6]);

/* cgm_app.c: the simulated Dexcom G6 or G7. */
void cgm_app_start(void);
void cgm_app_on_connect(void);
void cgm_app_on_disconnect(void);
void cgm_app_on_subscribe(cgm_chr_t chr, bool on);
void cgm_app_on_write(cgm_chr_t chr, const uint8_t *p, size_t n);
size_t cgm_app_on_read(cgm_chr_t chr, uint8_t *out, size_t cap);
size_t cgm_app_status_json(char *out, size_t cap);
const char *cgm_app_command(const char *body); /* NULL, or what was wrong */

/* store.c: NVS. */
void store_init(void);
bool store_load_state(dash_state_t *st);
void store_save_state(void *ctx, const dash_state_t *st);
bool store_load_wifi(char ssid[33], char password[65]);
void store_save_wifi(const char *ssid, const char *password);
bool store_load_cgm(cgm_state_t *st);
void store_save_cgm(void *ctx, const cgm_state_t *st);

/* panel.c: Wi-Fi (station or access point) and the HTTP control panel. */
void panel_start(dash_pod_t *pod);
