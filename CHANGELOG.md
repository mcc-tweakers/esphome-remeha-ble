# Changelog

## v2.2.3 (2026-11-24)

- **Fix: many entities got no values.** All bulk objects went out in one GetList. With
  more than about 100 objects the appliance did not answer it at all (seen on an Elga
  Ace with 255), and the count byte also capped a list at 255, so any further objects
  were silently left out. The bulk objects are now split into GetLists of at most 100
  objects, as the Remeha PRO app does, sent one after the other in each poll cycle. An
  object that several entities use is asked once.

## v2.2.2 (2026-11-23)

- **Fix:** the board search logged every absent node (no answer) as a warning. Those
  refusals are expected; the check for "is this the scan's own read" ran after the scan
  had already moved on to the next read, so it never matched. They are debug lines again.
- **Names without '/'.** ESPHome reserves '/' in names and will refuse it from 2027.7.0
  (43 codebook names contain one). Names filled in from the codebook and names in the
  configurator's YAML now use the same replacement as ESPHome (U+2044 fraction slash),
  so existing names and entity IDs stay the same. A `name:` you wrote yourself is not
  changed by the component.
- **Read all / All adjustable** buttons next to Quick select: they tick everything the
  search and filters show at that moment (thanks andrePKI).
- The status line shows a board without a name by its role, such as "4 (extension)".

## v2.2.1 (2026-11-23)

- **Fix:** a received message was capped at 2 kB since v2.2.0, but a menu block can be
  larger (block 2 of node 4 on a Confida 40 is about 2.3 kB). That block was dropped on
  every try. The cap is now 4 kB, with its own warning in the log.

## v2.2.0 (2026-11-23)

- **Fix: menu description on a Confida 40 after a restart.** Before reading the menu
  description (0x502B) of a board, the PRO app reads 0x502C and writes that value
  (`02`) to 0x502D. The component now does the same, in the scan and when it reads the
  limits after connecting. Without it every block of every board returned "general
  error" once the indoor unit had restarted, so the scan found nothing.
- **Scan: a menu block without an answer is read once more** (for example after a lost
  BLE fragment) instead of being skipped. The wait for an answer is 8 s instead of 20 s.
- **Fix: HM160 (current thermal output) is signed** in the codebook. During a defrost it
  is negative and showed as about 6550 kW.
- **Second authorization, as the Remeha PRO app does.** After the CAN-IP handshake
  the component now also authorizes protocol 02.00 at level 5, as seen in the app's
  traffic. No answer or an unexpected one: the component continues without it.
- **Objects outside the menu** in the configurator. *+ From codebook* searches the
  codebook by code, index or name, reads an object once and adds it to the table.
  Codes from the Remeha app for array elements (such as `AC089`, `CP083`) are
  recognised. *Clear not-in-menu rows* removes added rows that are not chosen.
- **The scan also looks for other boards.** After reading node 1 and 4 as before, it
  asks node 2 to 16 for their name and reads the menu description of every extra board
  that answers. The status line lists the boards found. Menu blocks are read 1 to 15
  (16 to 20 do not exist); a block that returns "general error" (0x08000000) is retried
  twice, and a board whose blocks keep failing is skipped. Refusals that the scan
  expects (absent boards, level-5 blocks) are logged quietly.
- **Fix:** a U8 measurement of 0xFF (such as a water pressure of 25.5 bar on an
  appliance without that sensor) is now "no value" instead of a number.
- **Fix:** the scan read past the end of the menu description (0x502B) and showed the
  data there as objects with nonsense ranges and levels (seen on an Elga Ace; a few on
  a Confida 40). A record that cannot be real is now skipped; index 0 or three bad
  records in a row end the list. This holds for the scan and for the limits of numbers
  and selects. Older scans in the browser are filtered too; scanning again is better.
  The log shows per block how many records the appliance reports, the block size and
  the first record that was skipped, so a different layout can be recognised.
- **Fix:** an answer with a lost Bluetooth fragment was glued to the next answer,
  which then failed its CRC check as well. A gap in the fragment count now drops just
  that answer (logged as a warning), and a reassembled message is capped (4 kB since v2.2.1).
- **Fix:** every Bluetooth device in range was remembered to log it once. Phones change
  their address every few minutes, so over days this ate the heap of the ESP (slow web
  page, slow OTA). Only named devices are logged now, at most 48.
- The Remeha **Elga Ace** (controlbox, article number 7854722) is recognised by name
  (thanks andrePKI).

## v2.1.0 (2026-11-20)

- **Read a value from the configurator:** a button in the new *Value* column reads the
  current value of one object once (`/remeha/read` on the ESP) and shows it with unit
  or choice text, or why the appliance refused it.
- The preset YAMLs (`presets/`) are gone: they were made for a heat pump and did not
  fit other appliances. The quick select buttons in the configurator stay; they only
  tick what the scanned appliance has.
- The start YAML now only reads a few values every Remeha EHC appliance has (status,
  flow temperature, water pressure, outdoor temperature).

## v2.0.0 (2026-11-20)

### Breaking: the component is now called `remeha_ble`
The name no longer refers to one appliance. In your YAML:

| v1.x | v2.0 |
|---|---|
| `components: [remeha_confida]` | `components: [remeha_ble]` |
| `remeha_confida:` (the hub) | `remeha_ble:` |
| `platform: remeha_confida` | `platform: remeha_ble` |
| `remeha_confida_id:` (on an entity) | `remeha_ble_id:` |

The start YAML and the configurator also use `id: remeha` and
`ble_client_id: remeha_client`; your own ids may stay as they are. Easiest: open the
configurator, choose *Read a YAML* and paste your old YAML; it accepts the old name and
writes a YAML with the new one, keeping your entity names. Entity names and the
behaviour in Home Assistant do not change.

### Other changes
- *Use the choice of this ESP* now also takes over the entity names and the device
  name, so existing entities stay the same entities in Home Assistant.
- Clearer note under the YAML.
- The status line after taking over a choice follows a language switch.
- README: screenshots and an explanation of the rows with a **+**.
- No compiler warning about an empty `else` in `dump_config` with log level INFO.

## v1.0.0 (2026-11-20)

First release under the name **esphome-remeha-ble**: a generic Bluetooth component for
Remeha appliances instead of a fixed configuration for one model.

### Configurator
- **Configurator on the ESP** (`configurator: true`, needs `web_server:`): open
  `http://<esp-ip>/remeha`, press *Scan appliance*, choose what to read and what to be
  able to change, copy the YAML. About 140 kB of flash.
- The scan reads the appliance's own menu description (0x502B) and is streamed to the
  page in small pieces, so the ESP only needs a few kB of memory.
- **Three languages** (English, Dutch, German) for the page, object names, choice texts
  and the generated YAML. The short English and German names come from Remeha's own
  translations (`data/translations.json`).
- Objects with several elements (per zone, activity or producer) on **one row** with a
  button to show the elements; one tick selects them all.
- **Start from your current choice:** take over what the ESP reads now, or read a pasted
  YAML (names you gave yourself are kept). Objects that work but are not in the menu
  description are kept as well.
- Quick select buttons (Basic, Energy, Outdoor unit, Room, Heating curve), search and
  filters, *Read* / *Adjustable* tick boxes.

### Component
- **`code:`**: declare an entity with just the appliance code (for example
  `code: HM001`); index, subindex, data type, scaling, unit, classes and name come from
  the built-in codebook. ESPHome checks that the platform fits the object.
- New platforms: **`binary_sensor`** (on/off values), **`switch`** (adjustable on/off),
  **`select`** (adjustable choice lists with texts); **`text_sensor`** shows choice lists
  as text.
- **Limits from the appliance:** a `number` takes over the real minimum, maximum and step
  (kept in flash) and refuses values outside them; a `select` refuses choices the
  appliance does not allow. Switch off per number with `device_limits: false`.
- **`read: auto`** (default with `code:`): bulk read first, single read when the
  appliance does not return the object in bulk. Objects that do not exist on the
  appliance are reported once and no longer requested.
- **Appliance recognition:** article number and internal name in the log, optional
  `appliance:` entity and `expected_article_number:` warning (also shown in the
  appliance entity).
- **One YAML for both Bluetooth routes:** `connection: auto` (default) recognises the
  built-in Bluetooth (`EHC-...`, paired with the sticker passkey) and the GTW-IoT hub
  (`GTW-IOT...`, no pairing) by the advertised name. `connection: paired` / `plain` force
  a route; the old `requires_pairing:` still works.
- Faster first values after connecting.
- Discovery dump for development: `id(confida).start_discovery_dump()` logs raw
  identification and discovery objects (contains serial numbers, do not share publicly).
  Based on a proposal by Robert Klep (@robertklep) in PR #1.

### Upgrading from an earlier version
- The example YAMLs `remeha-confida.yaml` and `remeha-confida-gtwiot.yaml` and the
  separate GTW-IoT start YAML are gone. Use [`remeha-start.yaml`](remeha-start.yaml)
  and the configurator. If you referenced the old files from GitHub, pin them to commit
  `a651e64` until you have switched.
- The offline configurator page (`configurator/index.html`) is gone; the configurator
  now runs on the ESP.
- Seven values moved from `sensor` to `binary_sensor` in the old example YAML (HM007,
  HM030, HM008, HM009, AM015, 0x502E:1, 0x502E:7). In Home Assistant they get a new
  entity id; update automations and dashboards.
- A `number` now uses the limits of the appliance, which can replace the limits in your
  YAML (for example AP058 becomes 0 to 2.0 bar).
- The repository was renamed to `esphome-remeha-ble`; the old name redirects.
