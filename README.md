# ESP-Sim: an Omnipod DASH and Omnipod 5 pod simulator on the ESP32-S3

> **Test equipment only.** ESP-Sim pretends to be an insulin pod so that
> controller apps (Loop, Trio and others using OmnipodKit) can be developed
> and tested without a real pod. It delivers no insulin, and nothing it
> reports reflects a real pod. Never use it — or an app paired to it — for
> anyone's therapy. This is not medical advice; talk to your care team about
> your own treatment.

This is a C port of the Go DASH simulator
([jeremybarnum/pod](https://github.com/jeremybarnum/pod) at
`a491a5e`, itself from [LoopKit/pod](https://github.com/loopkit/pod) and
0pen-dash) from a Raspberry Pi to an ESP32. It speaks the same Bluetooth
protocol — pairing, EAP-AKA sessions, encrypted pod commands — and serves the
same control panel, from a board that needs no Pi, no Linux and no Go.

It can also be an Omnipod 5 pod: see [Omnipod 5](#omnipod-5) below.

## Hardware

Any ESP32-S3 board with 8 MB of flash (developed on an ESP32-S3 QFN56 rev
v0.2 with 8 MB flash and 8 MB PSRAM, over its built-in USB serial/JTAG port).

## Build and flash

You need [ESP-IDF v5.5](https://docs.espressif.com/projects/esp-idf/en/v5.5.6/esp32s3/get-started/)
(this was built with v5.5.6). On macOS, ESP-IDF's installer leaves out CMake
and Ninja: add them with `python $IDF_PATH/tools/idf_tools.py install cmake ninja`.

```bash
. ~/esp/esp-idf/export.sh
```

```bash
idf.py set-target esp32s3
```

```bash
idf.py -p /dev/cu.usbmodem1101 build flash monitor
```

(Use your board's port: `ls /dev/cu.usbmodem*`.)

## Using it

At boot the board advertises as an unpaired DASH pod named ` :: Fake POD ::`.
Pair it from the app as a new Omnipod DASH pod.

**Control panel.** The serial console prints where it is:

- With no Wi-Fi network saved, the board runs its own access point,
  `ESP-Sim-Pod-XXXX`. Its password, derived from the chip's MAC, is printed
  at boot. Join it and open http://192.168.4.1/.
- In the panel's Wi-Fi card, save your network: the board restarts, joins it,
  takes the time from NTP and prints its address.

The panel is the Go simulator's: set the reservoir, the pod's age, alerts and
faults, and make the next command go unanswered to test the app's recovery.
Its JSON API is unchanged — `GET /status`, `POST /command` with
`{"command": "changeReservoir"|"setActiveTime"|"setAlerts"|"setFault"|"crashNextCommand"|"resetPod", ...}` —
plus `POST /wifi` with `{"ssid": ..., "password": ...}` (empty to forget).

**State** is kept in flash: a reboot is the same pod, still paired.

**Time.** The pod's age and its delivery timing come from the clock. With a
Wi-Fi network the clock is set by NTP; without one it resumes from the pod's
last save, so it loses the time the board was off. The pod reports its
activation time in the zone set in `idf.py menuconfig` → *ESP-Sim DASH pod*
(UTC by default).

## Differences from the Go simulator

- **Deactivating** the pod from the app makes the board a new, unpaired pod.
  (The Go simulator exits and needs restarting with `-fresh`.) The panel's
  *New pod* button does the same.
- **"Crash" on the next command** reboots the board, which comes back as the
  same pod.
- **Malformed commands** (too short to parse) end the connection instead of
  crashing the simulator.
- Not ported: the websocket API for `ps2/pod_simulator_frontend`, and the
  ImpossiBLE transport for the iOS Simulator.
- Like the Go simulator's Bluetooth radio, the advertisement carries the pod's
  service UUIDs (including its fault and alert status) but no manufacturer data.

Everything else, including the Go code's quirks that apps already accept,
is kept byte for byte: see the tests.

## Layout

| Path | What |
|---|---|
| `components/dashpod/` | The pod, as portable C: crypto (AES-CCM, CMAC, X25519, Milenage; AES, SHA-256 and P-256 from mbedTLS), messages, link layer, pairing (DASH and Omnipod 5), EAP-AKA, commands, responses, state machine |
| `main/` | The ESP32 side: NimBLE GATT and advertising (`ble.c`), NVS (`store.c`), Wi-Fi and the HTTP panel (`panel.c`, `panel.html`) |
| `test/host/` | Host tests (macOS) |
| `tools/golden/` | Generates `test/host/golden_dash.h` by running the upstream Go code |
| `tools/o5golden/` | Generates `test/host/golden_o5.h` by running OmnipodKit's Omnipod 5 code |

## Tests

```bash
make -C test/host
```

The host tests run the same C core that runs on the board, with mbedTLS built
from ESP-IDF's copy. They check:

- CRC-32, AES-CMAC (RFC 4493), AES-CCM (RFC 3610), X25519 (RFC 7748) and
  Milenage (3GPP TS 35.208) against their published vectors;
- pairing, EAP-AKA, message encryption, every response type and the link
  layer's fragmentation byte for byte against the Go simulator's own output
  (`tools/golden/gen.sh` regenerates it from the pinned upstream commit);
- a whole run against a simulated phone: pairing, a session, commands,
  control-panel faults, a reconnect, a bad message, and deactivation.

## Omnipod 5

In the control panel's *Pod type* card, switch to Omnipod 5: the board
becomes a new, unpaired Omnipod 5 pod (and back to DASH the same way).

The Omnipod 5 side follows the controller that apps use,
[OmnipodKit](https://github.com/loopandlearn/OmnipodKit) (`8df3d7b`),
rather than the Python emulator in vicktor/openpod-5, whose pairing doesn't
match it. An Omnipod 5 pod speaks DASH's protocol with these differences, all
simulated:

- **Bluetooth:** it advertises one 128-bit UUID,
  `CE1F923D-C539-48EA-7300-0A<controller id>00` (`FFFFFFFE` before pairing),
  sends data on characteristic `…2443`, uses 244-byte packets and no RTS/CTS.
- **Pairing:** `SPS0` picks P-256 with certificates; `SPS1` exchanges P-256
  keys; conf and the LTK come from SHA-256; `SPS2.1` and `SPS2` exchange
  certificates (and signatures) encrypted with AES-CCM.
- **Certificates:** the pod's is self-signed with a P-256 key it makes when it
  becomes a new pod. OmnipodKit reads the key from it and checks the pod's
  signature, but not who issued it. No Insulet key or certificate is used or
  needed, and the pod doesn't check the phone's.
- **Commands:** signed (Type 4) commands are accepted (the signature isn't
  checked); responses carry the Omnipod CRC-16, which OmnipodKit checks for
  Omnipod 5; the version and setup responses say product 5.
- **AID setup commands** (`S3.9=8,G3.9`, `SE255.2=…`, `G3.11`…) are answered
  with the prefixes OmnipodKit expects; their values are not otherwise used.

What a real Omnipod 5 pod says in its AID answers, and its certificates'
contents, are not public: the simulator gives OmnipodKit what it checks.

## Tests (Omnipod 5)

`make -C test/host` also runs the Omnipod 5 tests: P-256 and the
certificate, AID answers, 244-byte packets, and, when `test/host/golden_o5.h`
is present, a comparison with OmnipodKit's own code and a whole pairing and
session against a simulated phone using OmnipodKit's messages.

`tools/o5golden` builds OmnipodKit's Omnipod 5 files (key exchange, packet
splitting, message encoding, CRC, AID commands) with stubs, runs them on fixed
inputs and writes `golden_o5.h`:

```bash
tools/o5golden/gen.sh
```

## License

GPL-3.0-or-later, as the code it was ported from.
