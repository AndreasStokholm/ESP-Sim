/* The ESP32 side of ESP-Sim: radio, storage and control panel.
 * SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

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

/* store.c: NVS. */
void store_init(void);
bool store_load_state(dash_state_t *st);
void store_save_state(void *ctx, const dash_state_t *st);
bool store_load_wifi(char ssid[33], char password[65]);
void store_save_wifi(const char *ssid, const char *password);

/* panel.c: Wi-Fi (station or access point) and the HTTP control panel. */
void panel_start(dash_pod_t *pod);
