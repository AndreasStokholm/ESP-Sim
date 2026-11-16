# Handover: ESP-IDF submodule `lib_esp32c3_family` missing `esp32s3/libbtdm_app.a`

**For a local agent on the Mac.** Goal: make `idf.py build` work for
`~/Documents/code/diabetes/ESP-Sim` by repairing the ESP-IDF submodule. This is
an ESP-IDF/tooling problem, not a problem in the ESP-Sim branch.

## Symptom

```
$ idf.py -p /dev/cu.usbmodem101 build flash monitor
Executing action: all (aliases: build)
Running ninja in directory /Users/stokholm/Documents/code/diabetes/ESP-Sim/build
Executing "ninja all"...
ninja: error: '/Users/stokholm/esp/esp-idf/components/bt/controller/lib_esp32c3_family/esp32s3/libbtdm_app.a', needed by 'esp_sim_dash.elf', missing and no known rule to make it
ninja failed with exit code 1
```

## Environment (this Mac)

- macOS, user `stokholm`.
- ESP-IDF at `~/esp/esp-idf`: `git describe --tags` = **v5.5.6**, HEAD
  `880a203ae603d08a94d06aa01e0d6761958e5e9e`.
- Project at `~/Documents/code/diabetes/ESP-Sim`, branch
  `medtrum-patch/integration`, build dir `build/`.
- Python env error was already fixed: `~/esp/esp-idf/install.sh esp32s3` was run.

## Ground truth (from a working VM with the *same* IDF commit)

- Superproject pin: `160000 commit 0a08c4b32f3666003080b662a1a61794da24ff0f
  components/bt/controller/lib_esp32c3_family`
- Submodule HEAD on the working VM: `0a08c4b32f3666003080b662a1a61794da24ff0f`
  (`fix(bt): Update bt lib for ESP32-C3 and ESP32-S3(51d9dfde)`).
- At that commit the submodule tracks exactly:
  - `esp32s3/libbtdm_app.a` (~1.5 MB)
  - `esp32s3/libbtdm_app_flash.a` (~1.8 MB)
- **No Git LFS** (no LFS filters in `.gitattributes`).
- Submodule URL is **relative**: `../../espressif/esp32c3-bt-lib.git`
  (resolves to `https://github.com/espressif/esp32c3-bt-lib.git`).

## What is observed on this Mac

- `git ls-tree HEAD components/bt/controller/lib_esp32c3_family` -> pinned
  `0a08c4b…` (**correct**).
- `git -C components/bt/controller/lib_esp32c3_family rev-parse HEAD` ->
  `0a08c4b` (**correct**).
- `ls components/bt/controller/lib_esp32c3_family/esp32s3/` -> **file missing**.
- `git submodule update --init --recursive` -> "already current", no change.

So HEAD and the index match the pin, but the **working tree does not**. That is
one of:

1. The file is deleted in the submodule working tree (dirty submodule);
   `git submodule update` will not restore it without `--force`.
2. `skip-worktree` / `assume-unchanged` set on those paths, hiding the deletion.
3. A stale/broken `.git/modules/...` gitdir.
4. A partial/filtered clone (blob filter) so the blob was never fetched.
5. Sparse checkout excluding `esp32s3/`.

## Step 1 - diagnose (run inside the submodule)

```bash
cd ~/esp/esp-idf/components/bt/controller/lib_esp32c3_family
git status --short
git ls-files -v esp32s3/          # 'S' = skip-worktree, 'h' = assume-unchanged
git ls-files -t esp32s3/
git sparse-checkout list 2>&1
git config --get extensions.partialclone
git config --get remote.origin.promisor
git rev-parse --is-shallow-repository
git cat-file -s 0a08c4b32f3666003080b662a1a61794da24ff0f:esp32s3/libbtdm_app.a
git remote -v
```

Interpretation:

- `git status --short` shows ` D esp32s3/libbtdm_app.a` -> case 1.
- `git ls-files -v` shows `S` or `h` -> case 2.
- `git cat-file -s …` errors ("could not read"/"missing") -> case 4.
- `git sparse-checkout list` is non-empty -> case 5.
- `git status` is **clean** and `cat-file` succeeds but the file is absent ->
  case 2 (a skip-worktree bit hides the deletion).

## Step 2 - fix by case

### Case 1 / 2 - restore in place

```bash
cd ~/esp/esp-idf/components/bt/controller/lib_esp32c3_family
git update-index --no-skip-worktree --no-assume-unchanged \
  esp32s3/libbtdm_app.a esp32s3/libbtdm_app_flash.a
git checkout -- esp32s3/
ls -la esp32s3/
```

### Case 3 - force a clean submodule re-clone

```bash
cd ~/esp/esp-idf
git submodule sync --recursive
git submodule deinit -f components/bt/controller/lib_esp32c3_family
rm -rf components/bt/controller/lib_esp32c3_family
rm -rf .git/modules/components/bt/controller/lib_esp32c3_family
git submodule update --init components/bt/controller/lib_esp32c3_family
ls -la components/bt/controller/lib_esp32c3_family/esp32s3/
```

### Case 4 - blob not in the object store (partial clone)

```bash
cd ~/esp/esp-idf/components/bt/controller/lib_esp32c3_family
git config --unset extensions.partialclone
git config --unset remote.origin.promisor
git fetch --refetch --no-filter origin 0a08c4b32f3666003080b662a1a61794da24ff0f
git checkout -- .
ls -la esp32s3/
```

### Case 5 - sparse checkout

```bash
cd ~/esp/esp-idf/components/bt/controller/lib_esp32c3_family
git sparse-checkout disable
git checkout -- .
ls -la esp32s3/
```

### Last resort - clean ESP-IDF re-clone

```bash
rm -rf ~/esp/esp-idf
git clone -b v5.5.6 --recursive https://github.com/espressif/esp-idf.git ~/esp/esp-idf
cd ~/esp/esp-idf && ./install.sh esp32s3
python3 tools/idf_tools.py install cmake ninja   # macOS installer omits these
```

## Step 3 - verify

```bash
ls -la ~/esp/esp-idf/components/bt/controller/lib_esp32c3_family/esp32s3/   # both .a present
. ~/esp/esp-idf/export.sh
cd ~/Documents/code/diabetes/ESP-Sim
idf.py build
```

Success is `Project build complete`. `build` needs no USB; only `flash`/`monitor` do.

## Context (optional)

`medtrum-patch/integration` adds a **Medtrum pump-base + patch simulator** to
ESP-Sim (ESP32-S3): `components/medtrumpatch/` (portable C core: CRC8, crypto,
framing, request reassembly, session, delivery, status), `main/medtrum_app.c` +
`main/ble.c` (NimBLE advertising + GATT), a "Medtrum patch" panel card, and host
tests. On the VM, `idf.py build` and `make -C test/host medtrum`
(**340 checks, 0 failures**) are green against this exact IDF tag. Nothing in
this Mac error relates to the branch.

Once it builds and flashes:

```bash
idf.py -p /dev/cu.usbmodem101 flash monitor
```

Then pair from Trio/MedtrumKit with serial `4A12D828` (200U/MD0201) or
`52DF1614` (300U/MD8301); use the panel's "Medtrum patch" card.
