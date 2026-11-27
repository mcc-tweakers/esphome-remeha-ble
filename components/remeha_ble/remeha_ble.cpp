// ============================================================================
//  Remeha BLE -> ESPHome component  (implementation)
// ----------------------------------------------------------------------------
//  WHAT THIS DOES, END TO END
//  The ESP32 speaks the heat pump's native BLE protocol: it bonds to the
//  heat pump's onboard Bluetooth, passes two challenge/response gates, then
//  reads objects by CANopen-style index/subindex and (optionally) writes them.
//
//  CONNECTION SEQUENCE (state machine St, see .h):
//    1. OPEN            -> request an encrypted (bonded) link (LESC passkey =
//                          the number on the appliance's BLE sticker).
//    2. SEARCH_CMPL     -> resolve the GATT handles (resolve_handles_).
//    3. enable notifies -> on 4 characteristics (start_notify_); when all CCCDs
//                          are written we start the handshake.
//    4. GATE handshake  -> a 0-byte write to 0x1B makes the module send an
//                          8-byte challenge on 0x1D; we answer on 0x20 with a
//                          TEA response (tea_); it acks on 0x22.  (gate_trigger_)
//    5. CANIP handshake -> session-start + a second TEA challenge/response over
//                          the CANIP data channel (canip_handshake_).
//    6. RUN             -> normal polling: read everything, write when asked.
//
//  WIRE FRAME (all data rides the CANIP write/notify chars, handles 0x0E/0x10):
//    message = 01 02 00 00 00 | OP | RESV | <op-specific payload> | CRChi CRClo
//      - "01 02 00 00 00" is the 5-byte start marker of every message.
//      - OP (offset 5): 0x00 read-req, 0x01 read-resp, 0x04 write-req,
//                       0x05 write-resp, 0x08 GetList-req, 0x09 GetList-resp.
//      - CRC is CRC-16/MODBUS over everything before it, stored BIG-endian.
//    There is NO extra 0xFF in front of a message: the 0xFF seen at the start
//    of a single-fragment write/read is the fragment seq byte below.
//
//  FRAGMENTATION: every message is split into <=20-byte BLE notifications.
//    Each fragment is [seq][payload]; seq counts 0,1,2,... and the LAST
//    fragment uses seq=0xFF. We strip the seq byte and concatenate payloads
//    until we see 0xFF (send_next_fragment_ on TX, NOTIFY handler on RX).
//
//  OBJECTS: each value is addressed by (node, index, subindex). Many objects
//    are ARRAYS (MaxArraySize=5) whose real value lives at subindex >= 1, not
//    0 -- e.g. zone objects at sub 1 (active zone CIRCA), energy totals at
//    sub 1. Reading the wrong subindex returns a 0/sentinel. See RemehaItem.
//
//  TWO READ PATHS:
//    - BULK (default): GetList requests of at most 100 objects each (as the PRO
//      app does) list every bulk object; each reply packs its objects (no
//      per-record CRC) and is reassembled from fragments.
//    - SINGLE (read: single): an individual read request (op 0x00) per object,
//      for scalars the appliance does not surface in the bulk GetList. Chained
//      one-after-each-response so they finish inside one poll cycle.
//
//  WRITE: RemehaNumber::control -> enqueue_write builds an op 0x04 frame; it is
//    sent before the next poll; the appliance replies with an op 0x05 resp.
// ============================================================================
#ifdef USE_ESP32
#include "remeha_ble.h"
#include "esphome/core/log.h"
#include "esphome/core/application.h"
#include <algorithm>
#include <cctype>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <cmath>
#include <esp_err.h>
#include <esp_heap_caps.h>

namespace esphome {
namespace remeha_ble {

// CRC-16/MODBUS (poly 0xA001, init 0xFFFF), stored big-endian on the wire.

static const char *const TAG = "remeha_ble";
static const size_t FRAG_DATA = 19;
static const size_t SEEN_MAX = 48;      // named BLE devices logged once (bounded)
static const size_t RX_MAX = 4096;      // longest reassembled message we accept (a menu block can be 2.3 kB)

// RUN-phase watchdog thresholds (ms). The poll interval is 30 s, so RUN_RX_TIMEOUT
// is ~6 missed polls of silence before we give up on the link; TX_STUCK is how long
// a single request may sit half-sent (fragment write never acked) before reconnect.
static const uint32_t RUN_RX_TIMEOUT_MS = 180000;  // 3 min with no response -> reconnect
static const uint32_t TX_STUCK_MS = 15000;         // TX latched 15 s -> reconnect

// ---------------------------------------------------------------------------
// PAIRING RULES of the appliance's BLE gateway (GTW-Blue, node 5). These are the
// gateway's own rules, observed from its behaviour:
//  1. After a WRONG PIN the gateway is "not available for 60 seconds". Any new
//     pairing attempt in that window is refused with SMP "Repeated Attempts"
//     (ESP auth fail 0x56). Retrying every few seconds keeps it locked forever,
//     so after a failure we stay quiet for at least PAIR_MIN_GAP_MS.
//  2. It keeps at most 3 pairings; pairing a 4th device makes it forget the
//     OLDEST. When that is the ESP, our stored key is stale: encryption with it
//     fails. Then we delete our own bond once so the next attempt pairs afresh.
//  3. An aborted pairing may count as a failed one, so the watchdog never cuts
//     off a pairing that is still running (PAIR_TIMEOUT_MS).
// ---------------------------------------------------------------------------
static const uint32_t PAIR_MIN_GAP_MS = 90000;   // > the gateway's 60 s lock-out
static const uint32_t PAIR_TIMEOUT_MS = 30000;   // let a running pairing finish
static const uint32_t PAIR_BACKOFF_S[] = {90, 180, 300, 600};  // grows per consecutive failure

// ESP-IDF reports auth_cmpl.fail_reason as 77 (0x4D) + SMP reason (Core spec
// Vol 3 Part H 3.5.5), followed by stack-internal codes. E.g. 0x56 = 86 = 77 + 9.
static const char *auth_fail_str(uint8_t r) {
  switch (r) {
    case 0x4E: return "Passkey Entry Failed";
    case 0x50: return "Authentication Requirements";
    case 0x51: return "Confirm Value Failed - passkey klopt niet?";
    case 0x52: return "Pairing Not Supported";
    case 0x53: return "Encryption Key Size";
    case 0x55: return "Unspecified Reason";
    case 0x56: return "Repeated Attempts - gateway geblokkeerd na mislukte poging";
    case 0x57: return "Invalid Parameters";
    case 0x58: return "DHKey Check Failed";
    case 0x60: return "SMP busy";
    case 0x61: return "Encryption failed - gateway kent ons niet meer?";
    case 0x63: return "SMP response timeout";
    case 0x66: return "connection timeout";
    default:   return "zie ESP-IDF esp_ble_auth_fail_rsn_t";
  }
}
// CANopen SDO abort codes, as carried in the appliance's error responses
// (op 0x02 = read failed, op 0x06 = write failed; 4 bytes little-endian).
static const char *sdo_abort_str(uint32_t c) {
  switch (c) {
    case 0x05040000: return "geen antwoord (time-out)";
    case 0x05040001: return "ongeldig commando";
    case 0x06010000: return "geen toegang tot object";
    case 0x06010001: return "object is alleen-schrijven";
    case 0x06010002: return "object is alleen-lezen";
    case 0x06020000: return "object bestaat niet (op deze node)";
    case 0x06040041: return "object kan niet gemapt worden";
    case 0x06040043: return "parameter niet compatibel";
    case 0x06040047: return "interne incompatibiliteit";
    case 0x06060000: return "hardwarefout bij toegang";
    case 0x06070010: return "datatype/lengte klopt niet";
    case 0x06070012: return "datatype klopt niet, te lang";
    case 0x06070013: return "datatype klopt niet, te kort";
    case 0x06090011: return "subindex bestaat niet";
    case 0x06090030: return "waarde buiten toegestaan bereik";
    case 0x06090031: return "waarde te hoog";
    case 0x06090032: return "waarde te laag";
    case 0x06090036: return "maximum kleiner dan minimum";
    case 0x08000000: return "algemene fout";
    case 0x08000020: return "kan niet opslaan";
    case 0x08000021: return "kan niet opslaan (lokale besturing)";
    case 0x08000022: return "kan niet opslaan (huidige toestand van het toestel)";
    case 0x08000024: return "geen data beschikbaar";
    default:         return "onbekende abortcode";
  }
}

// Failures that say nothing about the stored key: never delete the bond for these.
static bool transient_fail(uint8_t r) { return r == 0x60 || r == 0x63 || r == 0x66; }

// Fixed UUIDs of the Confida BLE module's "gate" service + characteristics.
// These are the anchors: handles are looked up from the GATT database by UUID
// at connect time (resolve_handles_), so nothing here depends on fixed handles.
static const char *GATE_SVC = "6a37b97e-779d-457f-8182-edf334edd01f";
static const char *GATE_1B  = "94e54dc4-f69a-4c0c-8a6f-cc8f3135c665";  // write (trigger)
static const char *GATE_1D  = "69092300-a182-4fea-803b-24ada406da8a";  // notify (challenge)
static const char *GATE_20  = "f1ca5aeb-02cd-44a8-972b-44b6e7250d0b";  // write (response)
static const char *GATE_22  = "e2c47825-6dff-4d79-b74a-5bdc4f4661cf";  // notify (ack)
// Second notify characteristic inside the CANIP service (props 0x18 =
// notify+indicate) that is also subscribed to. Fixed UUID; handle resolved.
static const char *CANIP_EXTRA = "cff32957-5279-4075-bf3d-8e583d418c0d";

uint16_t RemehaBle::crc_modbus_(const uint8_t *d, size_t n) {
  uint16_t crc = 0xFFFF;
  for (size_t i = 0; i < n; i++) {
    crc ^= d[i];
    for (int b = 0; b < 8; b++) crc = (crc & 1) ? (crc >> 1) ^ 0xA001 : (crc >> 1);
  }
  return crc;
}

// TEA encrypt of block (level,level), key [0x15EFA43F, serial, chal, level], 32 rounds.
void RemehaBle::tea_(uint8_t level, uint32_t serial, uint32_t chal, uint32_t &o1, uint32_t &o2) {
  const uint32_t delta = 0x9E3779B9u, k0 = 0x15EFA43Fu;
  uint32_t v0 = level, v1 = level, s = delta;
  for (int i = 0; i < 32; i++) {
    v0 += ((k0 + (v1 << 4)) ^ (serial + (v1 >> 5)) ^ (v1 + s));
    v1 += ((chal + (v0 << 4)) ^ (s + v0) ^ ((uint32_t) level + (v0 >> 5)));
    s += delta;
  }
  o1 = v0; o2 = v1;
}

static std::string tohex(const uint8_t *d, size_t n) {
  static const char *H = "0123456789abcdef";
  std::string s;
  for (size_t i = 0; i < n; i++) { s.push_back(H[d[i] >> 4]); s.push_back(H[d[i] & 0xF]); }
  return s;
}
static uint32_t le32(const uint8_t *p) { return p[0] | (p[1] << 8) | (p[2] << 16) | ((uint32_t) p[3] << 24); }
static uint32_t be32(const uint8_t *p) { return (p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3]; }

void RemehaBle::setup() {
  rx_msg_.reserve(RX_MAX + 32);  // one reassembly buffer for the whole run (see NOTIFY)
  gate_svc_ = espbt::ESPBTUUID::from_raw(GATE_SVC);
  gate_1b_ = espbt::ESPBTUUID::from_raw(GATE_1B);
  gate_1d_ = espbt::ESPBTUUID::from_raw(GATE_1D);
  gate_20_ = espbt::ESPBTUUID::from_raw(GATE_20);
  gate_22_ = espbt::ESPBTUUID::from_raw(GATE_22);
  canip_extra_ = espbt::ESPBTUUID::from_raw(CANIP_EXTRA);
  // BLE security params only matter when we pair (Confida/GTW-22). The GTW-IoT
  // hub accepts a plain, unencrypted connection, so we configure no passkey/bond
  // and never request encryption (see ESP_GATTC_OPEN_EVT).
  // auto starts as "paired" (built-in Bluetooth is the common case); a GTW-IoT
  // name in the advertisement switches it to plain before connecting.
  requires_pairing_ = (conn_mode_ != 2);
  if (requires_pairing_) {
    esp_ble_auth_req_t auth = ESP_LE_AUTH_REQ_SC_MITM_BOND;
    esp_ble_io_cap_t iocap = ESP_IO_CAP_IN;
    uint8_t ks = 16, ik = 0x0F, rk = 0x0F;
    esp_ble_gap_set_security_param(ESP_BLE_SM_AUTHEN_REQ_MODE, &auth, sizeof(auth));
    esp_ble_gap_set_security_param(ESP_BLE_SM_IOCAP_MODE, &iocap, sizeof(iocap));
    esp_ble_gap_set_security_param(ESP_BLE_SM_MAX_KEY_SIZE, &ks, sizeof(ks));
    esp_ble_gap_set_security_param(ESP_BLE_SM_SET_INIT_KEY, &ik, sizeof(ik));
    esp_ble_gap_set_security_param(ESP_BLE_SM_SET_RSP_KEY, &rk, sizeof(rk));
    if (has_passkey_) { uint32_t pk = passkey_; esp_ble_gap_set_security_param(ESP_BLE_SM_SET_STATIC_PASSKEY, &pk, sizeof(pk)); }
  }

  // Auto-connect mode: if the ble_client MAC is left at 00:00:00:00:00:00, we
  // discover the appliance by advertised-name prefix. Register as a scan
  // listener so parse_device() sees every advertisement. With a real MAC filled
  // in, ble_client handles the connection itself and we skip scanning entirely.
  uint64_t cfg_addr = this->parent()->get_address();
  scan_mode_ = (cfg_addr == 0);
  if (!scan_mode_) addr_resolved_ = true;
  // The scan-listener is registered at build time (see __init__.py), so
  // parse_device() receives advertisements. Logged at INFO (not CONFIG) so it is
  // always captured in the live log.
  static const char *const MODES[] = {"automatisch (op naam)", "koppelen met passkey", "zonder koppelen (GTW-IoT)"};
  ESP_LOGI(TAG, "init: geconfigureerd MAC=0x%012llX  scan_mode=%d  prefix='%s'  verbinding=%s",
           (unsigned long long) cfg_addr, (int) scan_mode_, name_prefix_.empty() ? "EHC-/GTW-IOT" : name_prefix_.c_str(),
           MODES[conn_mode_ % 3]);
  ESP_LOGCONFIG(TAG, "Remeha BLE set up (%d items)", (int) items_.size());
}

uint8_t RemehaBle::match_name_(const std::string &name) const {
  if (name.empty()) return 0;
  auto starts = [&name](const char *p) {
    size_t n = strlen(p);
    if (name.size() < n) return false;
    for (size_t i = 0; i < n; i++)
      if (toupper((unsigned char) name[i]) != toupper((unsigned char) p[i])) return false;
    return true;
  };
  bool gtw = starts("GTW-IOT");
  if (!name_prefix_.empty()) return starts(name_prefix_.c_str()) ? (gtw ? 2 : 1) : 0;
  if (gtw) return 2;
  return starts("EHC-") ? 1 : 0;
}

bool RemehaBle::parse_device(const esp32_ble_tracker::ESPBTDevice &device) {
  uint64_t addr = device.address_uint64();
  const std::string &name = device.get_name();

  // MAC as text, formatted here from the 48-bit address: avoids the deprecated
  // ESPBTDevice::address_str() and works on old and new ESPHome versions alike.
  char mac[18];
  snprintf(mac, sizeof(mac), "%02X:%02X:%02X:%02X:%02X:%02X",
           (unsigned) ((addr >> 40) & 0xFF), (unsigned) ((addr >> 32) & 0xFF), (unsigned) ((addr >> 24) & 0xFF),
           (unsigned) ((addr >> 16) & 0xFF), (unsigned) ((addr >> 8) & 0xFF), (unsigned) (addr & 0xFF));

  // Log every distinct NAMED BLE device once, so a user with several appliances
  // can read off which MAC to put in the YAML. Devices without a name (phones and
  // the like, which change their address every few minutes) are not kept: the set
  // of seen addresses would otherwise keep growing and eat the heap over days.
  if (name.empty()) {
    ESP_LOGV(TAG, "BLE gezien: %s (zonder naam) rssi=%d", mac, device.get_rssi());
  } else if (seen_.size() < SEEN_MAX && seen_.find(addr) == seen_.end()) {
    seen_.insert(addr);
    ESP_LOGI(TAG, "BLE gezien: %s  naam='%s'  rssi=%d", mac, name.c_str(), device.get_rssi());
  }

  // Only in scan-mode: first device whose name matches -> pin its MAC on the
  // ble_client and let ble_client connect on the next advertisement.
  uint8_t kind = match_name_(name);
  bool ours = scan_mode_ ? (!addr_resolved_ && kind != 0) : (addr == this->parent()->get_address());
  if (ours && kind != 0 && conn_mode_ == 0) {
    requires_pairing_ = (kind == 1);  // auto: route follows the advertised name
    if (!route_logged_) {
      route_logged_ = true;
      ESP_LOGI(TAG, "route herkend aan de naam: %s", kind == 1 ? "ingebouwde Bluetooth (koppelen met passkey)"
                                                               : "GTW-IoT (zonder koppelen)");
    }
  }
  if (scan_mode_ && !addr_resolved_ && kind != 0) {
    addr_resolved_ = true;
    this->parent()->set_address(addr);
    ESP_LOGI(TAG, "Remeha-toestel gevonden: %s (%s) - verbinden",
             name.c_str(), mac);
  }
  return false;  // never claim the advertisement; ble_client drives the connection
}

void RemehaBle::dump_config() {
  ESP_LOGCONFIG(TAG, "Remeha BLE: items=%d", (int) items_.size());
  // Show only the last two digits: enough to spot a wrong/mangled secret
  // (e.g. a leading zero read as octal) without putting the PIN in the log.
  if (conn_mode_ == 2) {
    ESP_LOGCONFIG(TAG, "  verbinding: zonder koppelen (GTW-IoT)");
  } else if (has_passkey_) {
    ESP_LOGCONFIG(TAG, "  verbinding: %s, passkey ****%02u (laatste 2 cijfers, controleer tegen de sticker)",
                  conn_mode_ == 0 ? "automatisch" : "koppelen", (unsigned) (passkey_ % 100));
  } else if (conn_mode_ == 1) {
    ESP_LOGW(TAG, "  GEEN passkey ingesteld - koppelen gaat mislukken");
  } else {
    ESP_LOGCONFIG(TAG, "  verbinding: automatisch, geen passkey (werkt alleen met een GTW-IoT)");
  }
}

void RemehaBle::publish_reason_(const char *why) {
  if (reason_ts_ != nullptr) reason_ts_->publish_state(why);
}

// After a failed pairing/encryption: drop the link, stop ble_client from
// reconnecting, and wait (see PAIRING RULES). If the failure happened while we
// still hold a bond for the appliance, that key is stale (rule 2): delete it so
// the next attempt is a fresh passkey pairing - but only after the wait.
void RemehaBle::pairing_failed_(const uint8_t *bda, uint8_t reason) {
  bool had_bond = false;
  int n = esp_ble_get_bond_device_num();
  if (n > 0) {
    std::vector<esp_ble_bond_dev_t> list(n);
    if (esp_ble_get_bond_device_list(&n, list.data()) == ESP_OK) {
      for (int i = 0; i < n; i++)
        if (memcmp(list[i].bd_addr, bda, 6) == 0) had_bond = true;
    }
  }
  if (had_bond && !transient_fail(reason)) {
    ESP_LOGW(TAG, "opgeslagen sleutel werkt niet meer (gateway heeft ons vergeten?) - bond wissen, daarna vers koppelen");
    esp_bd_addr_t a;
    memcpy(a, bda, 6);
    esp_ble_remove_bond_device(a);
  } else if (reason == 0x51 || reason == 0x4E) {
    ESP_LOGE(TAG, "passkey lijkt niet te kloppen - controleer remeha_bt_key in secrets.yaml");
  }

  const size_t nb = sizeof(PAIR_BACKOFF_S) / sizeof(PAIR_BACKOFF_S[0]);
  const uint32_t wait_s = PAIR_BACKOFF_S[pair_fails_ < nb ? pair_fails_ : nb - 1];
  if (pair_fails_ < 255) pair_fails_++;
  last_fail_ = millis();
  ever_failed_ = true;
  backoff_ = true;
  backoff_until_ = last_fail_ + wait_s * 1000UL;
  pairing_ = false;
  reconnects_++;
  char msg[96];
  snprintf(msg, sizeof(msg), "koppelen mislukt 0x%02X - wacht %u s", reason, (unsigned) wait_s);
  ESP_LOGW(TAG, "%s (poging %u op rij)", msg, (unsigned) pair_fails_);
  publish_reason_(msg);
  if (reconnect_sensor_ != nullptr) reconnect_sensor_->publish_state((float) reconnects_);
  st_ = ST_INIT;
  tx_busy_ = false;
  rx_msg_.clear(); rx_bad_ = false; rx_next_ = 0; indiv_q_.clear();
  this->parent()->set_enabled(false);  // disconnects AND stops ble_client from reconnecting
}

void RemehaBle::write_raw_(uint16_t handle, const uint8_t *d, size_t n) {
  // On a plain (GTW-IoT) link, requesting MITM auth would make the stack try to
  // elevate security (pairing) before the write; use AUTH_REQ_NONE there.
  esp_gatt_auth_req_t auth = requires_pairing_ ? ESP_GATT_AUTH_REQ_MITM : ESP_GATT_AUTH_REQ_NONE;
  esp_err_t e = esp_ble_gattc_write_char(this->parent()->get_gattc_if(), this->parent()->get_conn_id(),
                                         handle, n, const_cast<uint8_t *>(d),
                                         ESP_GATT_WRITE_TYPE_RSP, auth);
  if (e != ESP_OK)
    ESP_LOGW(TAG, "write_char(0x%04X, %d bytes) returned %s", handle, (int) n, esp_err_to_name(e));
}

// Dump the complete GATT attribute database (services, characteristics,
// descriptors) with real handles and 128-bit UUIDs, for diagnostics. The
// actual handle resolution happens in resolve_handles_(); this is read-only.
void RemehaBle::dump_gatt_() {
  auto if_ = this->parent()->get_gattc_if();
  auto conn = this->parent()->get_conn_id();
  uint16_t count = 0;
  esp_gatt_status_t s = esp_ble_gattc_get_attr_count(if_, conn, ESP_GATT_DB_ALL, 0x0001, 0xFFFF, 0, &count);
  if (s != ESP_GATT_OK || count == 0) { ESP_LOGW(TAG, "get_attr_count st=%d count=%d", s, count); return; }
  esp_gattc_db_elem_t *db = (esp_gattc_db_elem_t *) malloc(sizeof(esp_gattc_db_elem_t) * count);
  if (db == nullptr) { ESP_LOGW(TAG, "db malloc failed (%d attrs)", count); return; }
  uint16_t got = count;
  s = esp_ble_gattc_get_db(if_, conn, 0x0001, 0xFFFF, db, &got);
  if (s != ESP_GATT_OK) { ESP_LOGW(TAG, "get_db st=%d", s); free(db); return; }
  ESP_LOGI(TAG, "==== GATT DB: %d attributes ====", got);
  for (uint16_t i = 0; i < got; i++) {
    esp_gattc_db_elem_t &e = db[i];
    char u[40];
    if (e.uuid.len == ESP_UUID_LEN_16) snprintf(u, sizeof(u), "0x%04X", e.uuid.uuid.uuid16);
    else if (e.uuid.len == ESP_UUID_LEN_32) snprintf(u, sizeof(u), "0x%08lX", (unsigned long) e.uuid.uuid.uuid32);
    else {
      const uint8_t *p = e.uuid.uuid.uuid128;  // stored little-endian
      snprintf(u, sizeof(u), "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
               p[15], p[14], p[13], p[12], p[11], p[10], p[9], p[8], p[7], p[6], p[5], p[4], p[3], p[2], p[1], p[0]);
    }
    const char *t = e.type == ESP_GATT_DB_PRIMARY_SERVICE ? "SVC" :
                    e.type == ESP_GATT_DB_SECONDARY_SERVICE ? "SV2" :
                    e.type == ESP_GATT_DB_CHARACTERISTIC ? "CHR" :
                    e.type == ESP_GATT_DB_DESCRIPTOR ? "DSC" : "oth";
    ESP_LOGI(TAG, "  %s h=0x%04X props=0x%02X uuid=%s", t, e.attribute_handle, e.properties, u);
  }
  free(db);
}

// Resolve every characteristic + CCCD handle dynamically from the GATT database
// by matching each characteristic's UUID. Nothing here depends on fixed handle
// numbers: the CANIP write/notify + the extra CANIP notify characteristic and the
// four gate characteristics are located by UUID, and each notify characteristic's
// CCCD (the 0x2902 descriptor that follows it) is taken from the next attribute.
// This keeps the component working even if an appliance lays out its attribute
// table with different handles. Safe to call repeatedly: returns false until
// service discovery is ready, so poll() retries on the next round.
bool RemehaBle::resolve_handles_() {
  if (h_canip_w_ != 0) return true;  // already resolved

  auto if_ = this->parent()->get_gattc_if();
  auto conn = this->parent()->get_conn_id();
  uint16_t count = 0;
  esp_gatt_status_t s = esp_ble_gattc_get_attr_count(if_, conn, ESP_GATT_DB_ALL, 0x0001, 0xFFFF, 0, &count);
  if (s != ESP_GATT_OK || count == 0) return false;  // discovery not complete yet
  esp_gattc_db_elem_t *db = (esp_gattc_db_elem_t *) malloc(sizeof(esp_gattc_db_elem_t) * count);
  if (db == nullptr) { ESP_LOGW(TAG, "db malloc failed (%d attrs)", count); return false; }
  uint16_t got = count;
  s = esp_ble_gattc_get_db(if_, conn, 0x0001, 0xFFFF, db, &got);
  if (s != ESP_GATT_OK) { ESP_LOGW(TAG, "get_db st=%d", s); free(db); return false; }

  // Each characteristic UUID we need, with where to store its value handle and
  // (for notify characteristics) its CCCD handle.
  struct Target { const espbt::ESPBTUUID &uuid; uint16_t *h; uint16_t *cccd; };
  Target targets[] = {
    { write_uuid_,  &h_canip_w_, nullptr },
    { notify_uuid_, &h_canip_n_, &cccd_canip_ },
    { canip_extra_, &h_13_,      &cccd_13_ },
    { gate_1b_,     &h_1b_,      nullptr },
    { gate_1d_,     &h_1d_,      &cccd_1d_ },
    { gate_20_,     &h_20_,      nullptr },
    { gate_22_,     &h_22_,      &cccd_22_ },
  };
  const int NT = sizeof(targets) / sizeof(targets[0]);
  for (int k = 0; k < NT; k++) { *targets[k].h = 0; if (targets[k].cccd) *targets[k].cccd = 0; }

  int cur = -1;  // index of the target matched by the characteristic we are inside
  for (uint16_t i = 0; i < got; i++) {
    esp_gattc_db_elem_t &e = db[i];
    if (e.type == ESP_GATT_DB_CHARACTERISTIC) {
      cur = -1;
      espbt::ESPBTUUID cu = espbt::ESPBTUUID::from_uuid(e.uuid);
      for (int k = 0; k < NT; k++) {
        if (cu == targets[k].uuid) { *targets[k].h = e.attribute_handle; cur = k; break; }
      }
    } else if (e.type == ESP_GATT_DB_DESCRIPTOR &&
               e.uuid.len == ESP_UUID_LEN_16 && e.uuid.uuid.uuid16 == 0x2902) {
      if (cur >= 0 && targets[cur].cccd != nullptr) *targets[cur].cccd = e.attribute_handle;
    }
  }
  free(db);

  // CANIP read/write is mandatory; without it there is nothing to do, so retry.
  // Leave every handle at 0 so poll()'s `h_1b_ == 0` retry gate stays consistent.
  if (h_canip_w_ == 0 || h_canip_n_ == 0) {
    ESP_LOGW(TAG, "GATT: CANIP-characteristics nog niet gevonden (w=0x%04X n=0x%04X)", h_canip_w_, h_canip_n_);
    for (int k = 0; k < NT; k++) { *targets[k].h = 0; if (targets[k].cccd) *targets[k].cccd = 0; }
    return false;
  }
  if (h_1b_ == 0 || h_1d_ == 0 || h_20_ == 0 || h_22_ == 0)
    ESP_LOGW(TAG, "GATT: niet alle gate-characteristics gevonden (1b=0x%04X 1d=0x%04X 20=0x%04X 22=0x%04X)",
             h_1b_, h_1d_, h_20_, h_22_);

  // Print the full GATT table once per connection (alle service- en characteristic-
  // UUID's), zodat je je eigen Confida-UUID's rechtstreeks uit de log kunt aflezen/
  // verifieren - net als een nRF Connect-scan, maar zonder telefoon.
  if (!dumped_) { dump_gatt_(); dumped_ = true; }

  ESP_LOGI(TAG, "handles (dynamisch): canip w=0x%04X n=0x%04X extra=0x%04X (cccd n=0x%04X extra=0x%04X) | "
                "gate 1b=0x%04X 1d=0x%04X 20=0x%04X 22=0x%04X (cccd 1d=0x%04X 22=0x%04X)",
           h_canip_w_, h_canip_n_, h_13_, cccd_canip_, cccd_13_,
           h_1b_, h_1d_, h_20_, h_22_, cccd_1d_, cccd_22_);
  start_notify_();
  return true;
}

void RemehaBle::start_notify_() {
  reg_done_ = descr_done_ = 0;
  auto if_ = this->parent()->get_gattc_if();
  auto bda = this->parent()->get_remote_bda();
  const uint16_t hs[] = {h_1d_, h_22_, h_canip_n_, h_13_};
  notify_expected_ = 0;
  for (uint16_t h : hs) if (h != 0) notify_expected_++;
  ESP_LOGI(TAG, "enabling notifications on 0x%04X, 0x%04X, 0x%04X, 0x%04X", h_1d_, h_22_, h_canip_n_, h_13_);
  for (uint16_t h : hs) if (h != 0) esp_ble_gattc_register_for_notify(if_, bda, h);
}

void RemehaBle::gate_trigger_() {
  st_ = ST_GATE_WAIT_CHAL;
  rx_msg_.clear(); rx_bad_ = false; rx_next_ = 0;
  // The appliance issues the challenge only on a ZERO-length Write Request to
  // 0x1B. esp_ble_gattc_write_char refuses len 0, but write_char_descr accepts
  // (value==nullptr && len==0) and emits the same ATT Write Request (0x12) to
  // the handle - on air this is "12 1b 00".
  ESP_LOGI(TAG, ">> gate: trigger (0-byte write to 0x%04X)", h_1b_);
  esp_gatt_auth_req_t auth = requires_pairing_ ? ESP_GATT_AUTH_REQ_MITM : ESP_GATT_AUTH_REQ_NONE;
  esp_err_t e = esp_ble_gattc_write_char_descr(this->parent()->get_gattc_if(), this->parent()->get_conn_id(),
                                               h_1b_, 0, nullptr, ESP_GATT_WRITE_TYPE_RSP, auth);
  if (e != ESP_OK) ESP_LOGW(TAG, "gate write_char_descr returned %s", esp_err_to_name(e));
}

void RemehaBle::canip_start_() {
  st_ = ST_CANIP_WAIT_CHAL;
  rx_msg_.clear(); rx_bad_ = false; rx_next_ = 0;
  static const uint8_t f[] = {0xff, 0x01, 0x02, 0x01, 0x00, 0x02, 0x00, 0x03, 0x23, 0xd6};
  ESP_LOGI(TAG, ">> canip: session start");
  write_raw_(h_canip_w_, f, sizeof(f));
}

void RemehaBle::gap_event_handler(esp_gap_ble_cb_event_t event, esp_ble_gap_cb_param_t *param) {
  switch (event) {
    case ESP_GAP_BLE_PASSKEY_REQ_EVT: esp_ble_passkey_reply(param->ble_security.ble_req.bd_addr, true, passkey_); break;
    case ESP_GAP_BLE_NC_REQ_EVT:      esp_ble_confirm_reply(param->ble_security.ble_req.bd_addr, true); break;
    case ESP_GAP_BLE_SEC_REQ_EVT:     esp_ble_gap_security_rsp(param->ble_security.ble_req.bd_addr, true); break;
    case ESP_GAP_BLE_AUTH_CMPL_EVT: {
      // This event reaches us twice (esp32_ble AND ble_client): handle it once.
      if (auth_handled_) break;
      auth_handled_ = true;
      pairing_ = false;
      const auto &ac = param->ble_security.auth_cmpl;
      if (ac.success) {
        ESP_LOGI(TAG, "pairing SUCCESS");
        pair_fails_ = 0;
        if (gate_pending_ && st_ == ST_INIT) {
          gate_pending_ = false;
          ESP_LOGI(TAG, "pairing done - starting gate handshake");
          gate_trigger_();
        }
      } else {
        ESP_LOGE(TAG, "pairing FAILED 0x%02X = %s", ac.fail_reason, auth_fail_str(ac.fail_reason));
        if (active_) pairing_failed_(ac.bd_addr, ac.fail_reason);
      }
      break;
    }
    default: break;
  }
}

void RemehaBle::gattc_event_handler(esp_gattc_cb_event_t event, esp_gatt_if_t gattc_if,
                                        esp_ble_gattc_cb_param_t *param) {
  switch (event) {
    case ESP_GATTC_OPEN_EVT:
      if (!active_) {  // released while a connect slipped through: drop it again
        // ...and stop ble_client from reconnecting. Needed after boot with the switch
        // restored to OFF: set_active(false) then ran before ble_client's own setup
        // re-enabled it, giving a connect/close loop every ~0.7 s.
        esp_ble_gattc_close(this->parent()->get_gattc_if(), this->parent()->get_conn_id());
        this->parent()->set_enabled(false);
        break;
      }
      if (param->open.status != ESP_GATT_OK) break;
      auth_handled_ = false;
      gate_pending_ = false;
      if (requires_pairing_) {
        // Confida/GTW-22: request an encrypted (bonded) link; the gate handshake
        // starts from AUTH_CMPL (the gate only answers on an encrypted link).
        pairing_ = true;
        pair_start_ = millis();
        ESP_LOGI(TAG, "verbonden - encryptie aanvragen (pairing)");
        esp_ble_set_encryption(param->open.remote_bda, ESP_BLE_SEC_ENCRYPT_MITM);
      } else {
        // GTW-IoT: no pairing. Leave pairing_ false so the gate handshake fires
        // straight after the notifications are enabled (see WRITE_DESCR_EVT).
        pairing_ = false;
        ESP_LOGI(TAG, "verbonden - GEEN pairing (GTW-IoT): direct door naar service discovery");
      }
      break;
    case ESP_GATTC_SEARCH_CMPL_EVT:
      ESP_LOGI(TAG, "SEARCH_CMPL received - resolving handles");
      resolve_handles_();
      break;
    case ESP_GATTC_REG_FOR_NOTIFY_EVT:
      // ESPHome's BLEClientBase writes the CCCD itself on this event, so we only
      // count registrations here (writing it again just doubles the traffic).
      reg_done_++;
      ESP_LOGD(TAG, "reg_for_notify ok ch=0x%04X (%d/%d)", param->reg_for_notify.handle, reg_done_, notify_expected_);
      break;
    case ESP_GATTC_WRITE_DESCR_EVT:
      if (st_ == ST_INIT) {
        descr_done_++;
        ESP_LOGD(TAG, "CCCD %d/%d status 0x%02X", descr_done_, notify_expected_, param->write.status);
        if (descr_done_ >= notify_expected_) {
          if (pairing_) {
            // A fresh passkey pairing is still running. The gate ignores a trigger on
            // a link that is not encrypted yet (the handshake then stalls and costs a
            // reconnect), so start it from AUTH_CMPL instead.
            if (!gate_pending_) ESP_LOGI(TAG, "notifications enabled - gate waits for pairing");
            gate_pending_ = true;
          } else {
            ESP_LOGI(TAG, "notifications enabled - starting gate handshake");
            gate_trigger_();
          }
        }
      } else {
        ESP_LOGD(TAG, "descr write 0x%04X status 0x%02X", param->write.handle, param->write.status);
      }
      break;
    case ESP_GATTC_WRITE_CHAR_EVT:
      if (param->write.status != 0) {
        ESP_LOGW(TAG, "write 0x%04X status 0x%02X", param->write.handle, param->write.status);
      } else if (st_ != ST_RUN) {
        ESP_LOGD(TAG, "write 0x%04X ok", param->write.handle);
      }
      if (st_ == ST_RUN && tx_busy_) {
        send_next_fragment_();
        // The response to a request can arrive BEFORE the ack of its last fragment
        // (tx_busy_ still set at that moment). Then the chained next read was
        // skipped; send it now that the TX is free, instead of waiting for the
        // next poll tick (30 s).
        if (!tx_busy_ && chain_next_) { chain_next_ = false; send_next_individual_(); }
      }
      break;
    case ESP_GATTC_NOTIFY_EVT: {
      uint16_t h = param->notify.handle;
      const uint8_t *v = param->notify.value;
      uint16_t n = param->notify.value_len;
      ESP_LOGD(TAG, "<< NOTIFY h=0x%04X (%d) %s", h, n, tohex(v, n).c_str());
      if (h == h_1d_ && st_ == ST_GATE_WAIT_CHAL && n >= 8) {
        uint32_t serial = le32(v), chal = le32(v + 4), w1, w2;
        tea_(auth_level_, serial, chal, w1, w2);
        uint8_t resp[9] = {auth_level_,
                           (uint8_t) w1, (uint8_t)(w1 >> 8), (uint8_t)(w1 >> 16), (uint8_t)(w1 >> 24),
                           (uint8_t) w2, (uint8_t)(w2 >> 8), (uint8_t)(w2 >> 16), (uint8_t)(w2 >> 24)};
        ESP_LOGI(TAG, ">> gate: challenge %s -> response %s", tohex(v, 8).c_str(), tohex(resp, 9).c_str());
        st_ = ST_GATE_WAIT_ACK;
        write_raw_(h_20_, resp, sizeof(resp));
      } else if (h == h_22_ && st_ == ST_GATE_WAIT_ACK) {
        ESP_LOGI(TAG, ">> gate: ack %s - gate passed", tohex(v, n).c_str());
        pairing_ = false;  // the gate only answers on an encrypted link, so pairing is done
        canip_start_();
      } else if (h == h_canip_n_) {
        if (n < 1) break;
        // Reassembly: fragments count 0, 1, 2, ... and the last one is 0xFF. A
        // fragment 0 starts a new message; a gap in the count (a lost
        // notification) spoils the message, which is then dropped as a whole
        // instead of being glued to the next one (that gave CRC errors).
        uint8_t seq = v[0];
        if (seq == 0) { rx_msg_.clear(); rx_bad_ = false; rx_next_ = 0; }
        if (seq != 0xFF) {
          if (seq != rx_next_) rx_bad_ = true;
          rx_next_ = seq + 1;
        }
        if (!rx_bad_) rx_msg_.insert(rx_msg_.end(), v + 1, v + n);
        if (rx_msg_.size() > RX_MAX) {
          if (!rx_bad_) ESP_LOGW(TAG, "antwoord langer dan %u bytes: weggegooid", (unsigned) RX_MAX);
          rx_msg_.clear();
          rx_bad_ = true;
        }
        if (seq != 0xFF) break;
        if (rx_bad_) {
          rx_dropped_++;
          ESP_LOGW(TAG, "antwoord met ontbrekend fragment weggegooid (%u keer sinds start)", (unsigned) rx_dropped_);
          rx_msg_.clear(); rx_bad_ = false; rx_next_ = 0;
          // the request is lost: let the chain continue with the next read
          if (st_ == ST_RUN) { if (tx_busy_) chain_next_ = true; else send_next_individual_(); }
          break;
        }
        rx_next_ = 0;
        // Hand the buffer over without a copy and take it back afterwards, so the
        // reassembly buffer is allocated once (setup) instead of per answer: with
        // many entities the heap is tight, and growing or copying a 1-2 kB vector
        // here crashed the ESP (seen with 5 GetLists on an Elga Ace).
        std::vector<uint8_t> m = std::move(rx_msg_);
        rx_msg_.clear();
        if (st_ == ST_RUN) {
          responses_++;
          last_rx_ = millis();   // link is alive (feeds the RUN watchdog)
          parse_response_(m);
          // Chain the next single-read request right after this response so all
          // individual reads finish within the current poll cycle (not one per tick).
          // If the TX is still finishing (ack pending), WRITE_CHAR_EVT sends it.
          if (tx_busy_) chain_next_ = true;
          else send_next_individual_();
        } else { ESP_LOGD(TAG, "<< canip %s", tohex(m.data(), m.size()).c_str()); canip_handshake_(m); }
        m.clear();
        rx_msg_ = std::move(m);  // keeps its capacity for the next answer
      }
      break;
    }
    case ESP_GATTC_DISCONNECT_EVT:
      ESP_LOGW(TAG, "disconnected");
      pairing_ = false;
      gate_pending_ = false;
      st_ = ST_INIT; h_canip_w_ = h_canip_n_ = h_1b_ = h_1d_ = h_20_ = h_22_ = h_13_ = 0;
      cccd_1d_ = cccd_22_ = cccd_canip_ = cccd_13_ = 0;
      reg_done_ = descr_done_ = notify_expected_ = 0; dumped_ = false;
      tx_busy_ = false; rx_msg_.clear(); rx_bad_ = false; rx_next_ = 0; tx_msg_.clear(); tx_queue_.clear(); indiv_q_.clear();
      chain_next_ = false;
      menu_q_.clear(); menu_left_ = 0; id_left_ = 0;  // not finished: read again after reconnect
      if (scan_state_ == 2) { scan_left_ = 0; scan_inflight_ = false; scan_pending_ = true; scan_state_ = 1; update_scan_json_(); }
      if (!dump_q_.empty() || dump_left_ > 0) ESP_LOGW(TAG, "DUMP afgebroken door verbroken verbinding");
      dump_q_.clear(); dump_keys_.clear(); dump_arrays_.clear(); dump_left_ = 0;
      break;
    default: break;
  }
}

// The PRO app authorizes TWICE: first protocol 02.01 (level 4, broadcast), then,
// before it reads or writes parameters, protocol 02.00 at level 5 (same TEA, see
// docs/readme.md). Without the second one a Confida 40 can refuse the menu
// description 0x502B with "general error" (seen after a restart of the indoor unit;
// an earlier PRO-app session had apparently left that authorization in place).
// Frames (body, without FF seq and CRC):
//   ESP: 01 02 00 00 02 00 00                         challenge request
//   dev: 01 02 00 00 02 01 00 <serial:4> <chal:4>
//   ESP: 01 02 00 00 02 02 00 ff <level> <tea:8>
//   dev: 01 02 00 00 02 03 00 ff <level> ff 01        accepted
static const uint8_t AUTH0_LEVEL = 5;
static const uint32_t AUTH0_TIMEOUT_MS = 3000;

void RemehaBle::send_canip_body_(const uint8_t *body, size_t len) {
  uint8_t f[24];
  if (len + 3 > sizeof(f)) return;
  f[0] = 0xff;
  memcpy(f + 1, body, len);
  uint16_t c = crc_modbus_(body, len);
  f[len + 1] = (uint8_t) (c >> 8);
  f[len + 2] = (uint8_t) (c & 0xFF);
  write_raw_(h_canip_w_, f, len + 3);
}

void RemehaBle::enter_run_() {
  st_ = ST_RUN;
  last_rx_ = millis();   // arm the RUN watchdog from a fresh timestamp
  // Publish "verbonden" once (first connect) so the reason entity isn't empty and
  // shows a clean baseline; after that it holds the LAST reconnect reason.
  if (reason_ts_ != nullptr && !connected_once_) reason_ts_->publish_state("verbonden");
  if (reconnect_sensor_ != nullptr && !connected_once_) reconnect_sensor_->publish_state(0);
  connected_once_ = true;
  ESP_LOGI(TAG, ">> handshake complete - starting GetList polling");
  // First poll right away (after a short pause for the last handshake write),
  // instead of waiting up to a full update_interval for the next tick.
  this->set_timeout("first_poll", 300, [this]() {
    if (st_ == ST_RUN && !tx_busy_ && tx_queue_.empty()) start_poll_cycle_();
  });
}

void RemehaBle::canip_handshake_(const std::vector<uint8_t> &m) {
  if (m.size() < 7) return;
  uint8_t cls = m[4], step = m[5];
  if (st_ == ST_AUTH0_WAIT_CHAL || st_ == ST_AUTH0_WAIT_ACK) {
    // second authorization (protocol 02.00); anything unexpected: continue without it
    if (m[2] == 0x00 && cls == 0x02 && step == 0x01 && m.size() >= 15 && st_ == ST_AUTH0_WAIT_CHAL) {
      uint32_t serial = be32(&m[7]), chal = be32(&m[11]), w1, w2;
      tea_(AUTH0_LEVEL, serial, chal, w1, w2);
      const uint8_t body[17] = {0x01, 0x02, 0x00, 0x00, 0x02, 0x02, 0x00, 0xff, AUTH0_LEVEL,
                                (uint8_t) (w1 >> 24), (uint8_t) (w1 >> 16), (uint8_t) (w1 >> 8), (uint8_t) w1,
                                (uint8_t) (w2 >> 24), (uint8_t) (w2 >> 16), (uint8_t) (w2 >> 8), (uint8_t) w2};
      ESP_LOGI(TAG, ">> canip 02.00: challenge -> authorize level %u", AUTH0_LEVEL);
      st_ = ST_AUTH0_WAIT_ACK;
      auth0_ms_ = millis();
      send_canip_body_(body, sizeof(body));
      return;
    }
    if (m[2] == 0x00 && cls == 0x02 && step == 0x03 && m.size() >= 11 && m[10] == 0x01) {
      ESP_LOGI(TAG, ">> canip 02.00: authorized (level %u)", m[8]);
    } else {
      ESP_LOGW(TAG, ">> canip 02.00: onverwacht antwoord %s - verder zonder", tohex(m.data(), m.size()).c_str());
    }
    enter_run_();
    return;
  }
  if (cls == 0x02 && step == 0x01 && m.size() >= 15) {
    uint32_t serial = be32(&m[7]), chal = be32(&m[11]), w1, w2;
    tea_(auth_level_, serial, chal, w1, w2);
    ESP_LOGI(TAG, ">> canip: challenge serial=%08lX chal=%08lX -> authorize", (unsigned long) serial, (unsigned long) chal);
    uint8_t body[17] = {0x01, 0x02, 0x01, 0x00, 0x02, 0x02, 0x03, 0xff, auth_level_,
                        (uint8_t)(w1 >> 24), (uint8_t)(w1 >> 16), (uint8_t)(w1 >> 8), (uint8_t) w1,
                        (uint8_t)(w2 >> 24), (uint8_t)(w2 >> 16), (uint8_t)(w2 >> 8), (uint8_t) w2};
    uint16_t c = crc_modbus_(body, sizeof(body));
    uint8_t f[20]; f[0] = 0xff; memcpy(f + 1, body, sizeof(body));
    f[18] = (uint8_t)(c >> 8); f[19] = (uint8_t)(c & 0xFF);
    st_ = ST_CANIP_WAIT_ACK;
    write_raw_(h_canip_w_, f, sizeof(f));
  } else if (cls == 0x02 && step == 0x03) {
    static const uint8_t f[] = {0xff, 0x01, 0x02, 0x01, 0x00, 0x00, 0x00, 0x03, 0xff, 0x58, 0x2a, 0x00, 0xe5, 0x44};
    ESP_LOGI(TAG, ">> canip: authorized - follow-up");
    st_ = ST_CANIP_WAIT_RX6;
    write_raw_(h_canip_w_, f, sizeof(f));
  } else if (cls == 0x00 && step == 0x02) {
    // second authorization, as the PRO app does (see above)
    static const uint8_t body[7] = {0x01, 0x02, 0x00, 0x00, 0x02, 0x00, 0x00};
    ESP_LOGI(TAG, ">> canip 02.00: session start");
    st_ = ST_AUTH0_WAIT_CHAL;
    auth0_ms_ = millis();
    send_canip_body_(body, sizeof(body));
  } else {
    ESP_LOGW(TAG, "unexpected canip msg cls=0x%02X step=0x%02X", cls, step);
  }
}

// The Remeha PRO app never asks for more than 100 objects in one GetList (seen in
// its traffic: 147 objects went out as 100 + 47). A larger one got no answer at
// all on an Elga Ace (255 objects); the count byte also caps a list at 255. So
// the bulk objects are split into GetLists of at most GETLIST_MAX, sent one
// after the other in the same cycle.
static const uint8_t GETLIST_MAX = 100;

std::vector<std::vector<uint8_t>> RemehaBle::build_requests_() {
  std::vector<std::vector<uint8_t>> out;
  std::vector<uint8_t> m;
  uint8_t count = 0, batch = 0;
  auto finish = [&]() {
    if (count == 0) return;
    m[7] = count;
    uint16_t c = crc_modbus_(m.data(), m.size());
    m.push_back((uint8_t)(c >> 8)); m.push_back((uint8_t)(c & 0xFF));
    out.push_back(std::move(m));
    m.clear(); count = 0; batch++;
  };
  for (auto &it : items_) {
    if (it.single || it.missing) continue;
    // the same object for several entities is asked once
    bool dup = false;
    for (auto &o : items_) {
      if (&o == &it) break;
      if (!o.single && !o.missing && o.node == it.node && o.index == it.index && o.sub == it.sub) {
        it.batch = o.batch; dup = true; break;
      }
    }
    if (dup) continue;
    if (count == GETLIST_MAX) finish();
    if (count == 0) m.insert(m.end(), {0x01, 0x02, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00});
    m.push_back(0x00); m.push_back(it.node);
    m.push_back((uint8_t)(it.index >> 8)); m.push_back((uint8_t)(it.index & 0xFF)); m.push_back(it.sub);
    it.batch = batch;
    count++;
  }
  finish();
  return out;
}

// Build an individual READ request (operation 0x00) for one object:
// 01 02 00 00 00 00 00 <node> <idxHi> <idxLo> <sub> <crcHi> <crcLo>.
// NO leading 0xFF: the 0xFF seen on the wire is the fragment seq byte
// (last fragment), which send_next_fragment_ adds. (Until 16 okt 2026 we added
// an extra 0xFF here, so on air it read "FF FF 01 02 ..." and the appliance
// silently ignored every single read and every write.)
std::vector<uint8_t> RemehaBle::build_read_frame_(uint8_t node, uint16_t index, uint8_t sub) {
  std::vector<uint8_t> body = {0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, node,
                               (uint8_t)(index >> 8), (uint8_t)(index & 0xFF), sub};
  uint16_t c = crc_modbus_(body.data(), body.size());
  std::vector<uint8_t> frame;
  frame.reserve(body.size() + 2);
  frame.insert(frame.end(), body.begin(), body.end());
  frame.push_back((uint8_t)(c >> 8));
  frame.push_back((uint8_t)(c & 0xFF));
  return frame;
}

// Same for a write (op 0x04) with its value bytes.
std::vector<uint8_t> RemehaBle::build_write_frame_(uint8_t node, uint16_t index, uint8_t sub,
                                                    const std::vector<uint8_t> &data) {
  std::vector<uint8_t> frame = {0x01, 0x02, 0x00, 0x00, 0x00, 0x04, 0x00, node,
                                (uint8_t)(index >> 8), (uint8_t)(index & 0xFF), sub};
  frame.insert(frame.end(), data.begin(), data.end());
  uint16_t c = crc_modbus_(frame.data(), frame.size());
  frame.push_back((uint8_t)(c >> 8));
  frame.push_back((uint8_t)(c & 0xFF));
  return frame;
}

// (Re)fill the individual-read queue: one request frame per single-read item.
void RemehaBle::queue_individual_reads_() {
  indiv_q_.clear();
  for (auto &it : items_) {
    if (it.single && !it.missing) indiv_q_.push_back(build_read_frame_(it.node, it.index, it.sub));
  }
}

// Pop and send the next queued individual read. Returns false when the queue is empty.
bool RemehaBle::send_next_individual_() {
  if (tx_busy_) return false;
  if (indiv_q_.empty()) {
    if (!menu_q_.empty()) {  // menu descriptor blocks (once per boot)
      auto f = menu_q_.front();
      menu_q_.erase(menu_q_.begin());
      start_tx_(std::move(f));
      return true;
    }
    // Discovery dump reads go out once the normal single reads are done; while a
    // dump is pending, update() keeps draining it before starting a new GetList.
    if (dump_q_.empty()) return false;
    auto d = dump_q_.front();
    dump_q_.erase(dump_q_.begin());
    start_tx_(std::move(d));
    return true;
  }
  auto f = indiv_q_.front();
  indiv_q_.erase(indiv_q_.begin());
  ESP_LOGD(TAG, "sending individual read (%d bytes), %d left", (int) f.size(), (int) indiv_q_.size());
  start_tx_(std::move(f));
  return true;
}

// Switch handler: release the BLE link (so a phone or service tool can connect) or resume.
void RemehaBle::set_active(bool a) {
  if (a == active_) return;
  active_ = a;
  if (a) {
    // Manual "on" skips the remaining back-off, but never re-enters the gateway's
    // 60 s lock-out window after a failed pairing (that would only extend it).
    if (ever_failed_ && millis() - last_fail_ < PAIR_MIN_GAP_MS) {
      backoff_ = true;
      backoff_until_ = last_fail_ + PAIR_MIN_GAP_MS;
      ESP_LOGI(TAG, "uitlezing INGESCHAKELD - wacht eerst tot %u s na de mislukte koppeling",
               (unsigned) (PAIR_MIN_GAP_MS / 1000));
      publish_reason_("wacht na mislukte koppeling");
      return;
    }
    backoff_ = false;
    ESP_LOGI(TAG, "uitlezing INGESCHAKELD - opnieuw verbinden");
    publish_reason_("verbonden");
    this->parent()->set_enabled(true);   // ble_client mag weer verbinden
  } else {
    ESP_LOGW(TAG, "uitlezing VRIJGEGEVEN - BLE loslaten (telefoon/installateur kan verbinden)");
    if (reason_ts_ != nullptr) reason_ts_->publish_state("vrijgegeven");
    st_ = ST_INIT;
    tx_busy_ = false; rx_msg_.clear(); rx_bad_ = false; rx_next_ = 0; indiv_q_.clear(); tx_queue_.clear();
    this->parent()->set_enabled(false);  // verbreekt de verbinding EN stopt herverbinden
  }
}

void RemehaBle::update() {
  if (!active_) {        // released: don't drive the connection
    if (this->parent()->enabled) this->parent()->set_enabled(false);
    return;
  }
  if (backoff_) {        // waiting after a failed pairing (PAIRING RULES 1)
    if ((int32_t) (millis() - backoff_until_) >= 0) {
      backoff_ = false;
      ESP_LOGI(TAG, "wachttijd voorbij - nieuwe koppelpoging");
      publish_reason_("nieuwe koppelpoging");
      this->parent()->set_enabled(true);
    }
    return;
  }
  if (pairing_) {        // pairing/encryption still running: never cut it off (RULES 3)
    if (millis() - pair_start_ < PAIR_TIMEOUT_MS) return;
    ESP_LOGW(TAG, "koppelen geeft na %u s geen resultaat", (unsigned) (PAIR_TIMEOUT_MS / 1000));
    pairing_failed_(this->parent()->get_remote_bda(), 0x63);  // treat as timeout: keep the bond
    return;
  }
  if (st_ == ST_RUN) {
    const uint32_t now = millis();
    // WATCHDOG 1 - silent link: in RUN there is otherwise NO liveness check, so a
    // link that dies without a DISCONNECT event (zombie link, appliance BLE reset)
    // would freeze polling forever. If nothing has been received for too long,
    // treat the link as dead and reconnect.
    if (now - last_rx_ > RUN_RX_TIMEOUT_MS) {
      force_reconnect_("no BLE response in RUN");
      return;
    }
    // WATCHDOG 2 - stuck TX: tx_busy_ is only cleared when a fragment write is
    // acked (WRITE_CHAR_EVT). If that ack never comes (link went away mid-send),
    // tx_busy_ would latch true and every poll below would early-return forever.
    // Break out of a TX that has been in progress too long.
    if (tx_busy_) {
      if (now - tx_start_ > TX_STUCK_MS) force_reconnect_("TX stuck in RUN");
      return;
    }
    // Pending parameter writes go out first, before the next GetList poll.
    if (!tx_queue_.empty()) {
      auto f = tx_queue_.front();
      tx_queue_.erase(tx_queue_.begin());
      ESP_LOGD(TAG, "sending queued write (%d bytes)", (int) f.size());
      start_tx_(std::move(f));
      return;
    }
    // Individual reads from the previous cycle still draining (recovery if a
    // response was missed; normally they chain off each response, see NOTIFY).
    if (send_next_individual_()) return;
    start_poll_cycle_();
    return;
  }

  // Not yet running: drive the connection sequence from here so we don't depend
  // on catching SEARCH_CMPL at exactly the right instant.
  if (h_1b_ == 0) {
    if (!resolve_handles_()) {
      ESP_LOGD(TAG, "waiting for service discovery (node_state=%d)", (int) this->node_state);
    }
    return;  // resolve_handles_ starts notify registration on success
  }
  if (st_ == ST_INIT) {
    // Handles resolved but the gate never started: notifications not confirmed.
    ESP_LOGW(TAG, "notifications not confirmed (%d/%d) - re-registering", descr_done_, notify_expected_);
    start_notify_();
    return;
  }
  // The gate/CANIP handshake started but did not reach RUN before this tick.
  // The appliance issues only ONE gate challenge per connection, so re-triggering
  // the gate mid-session cannot recover - force a clean reconnect and start over.
  char msg[48];
  snprintf(msg, sizeof(msg), "handshake stalled (st=%d)", (int) st_);
  force_reconnect_(msg);
}

// Start a fresh cycle: one bulk GetList, then queue the single-read items.
void RemehaBle::start_poll_cycle_() {
  auto lists = build_requests_();
  queue_individual_reads_();
  if (lists.empty()) { send_next_individual_(); return; }
  // the other GetLists go first in the queue, before the single reads; each one
  // goes out after the answer to the previous request (see the NOTIFY chain)
  indiv_q_.insert(indiv_q_.begin(), std::make_move_iterator(lists.begin() + 1), std::make_move_iterator(lists.end()));
  ESP_LOGD(TAG, "polling: %u GetList(s), first %d bytes, responses %u", (unsigned) lists.size(),
           (int) lists[0].size(), (unsigned) responses_);
  start_tx_(std::move(lists[0]));
}

// Close the GATT link and reset state so ESPHome's ble_client reconnects cleanly.
// Used both for a stalled handshake and for the RUN-phase watchdogs. Resetting
// tx_busy_ here is what guarantees a wedged TX can never stay latched.
void RemehaBle::force_reconnect_(const char *why) {
  ESP_LOGW(TAG, "%s - forcing reconnect", why);
  reconnects_++;
  // Mirror the reason + count to the optional HA diagnostic entities, so it can be
  // reviewed later from HA history without watching the live ESPHome log.
  if (reason_ts_ != nullptr) reason_ts_->publish_state(why);
  if (reconnect_sensor_ != nullptr) reconnect_sensor_->publish_state((float) reconnects_);
  st_ = ST_INIT;
  tx_busy_ = false;
  rx_msg_.clear(); rx_bad_ = false; rx_next_ = 0; indiv_q_.clear();
  esp_ble_gattc_close(this->parent()->get_gattc_if(), this->parent()->get_conn_id());
}

void RemehaBle::start_tx_(std::vector<uint8_t> frame) {
  tx_msg_ = std::move(frame);
  tx_off_ = 0; tx_seq_ = 0; tx_busy_ = true; tx_start_ = millis();
  send_next_fragment_();
}

// Build a WRITE frame (operation 0x04) and queue it. No leading 0xFF (see
// build_read_frame_): on air it becomes FF 01 02 00 00 00 04 00 ... Sent
// immediately when the bus is idle and the session is running, otherwise on the
// next poll tick.
void RemehaBle::enqueue_write(uint8_t node, uint16_t index, uint8_t sub,
                                  const std::vector<uint8_t> &data) {
  std::vector<uint8_t> body = {0x01, 0x02, 0x00, 0x00, 0x00, 0x04, 0x00, node,
                               (uint8_t)(index >> 8), (uint8_t)(index & 0xFF), sub};
  body.insert(body.end(), data.begin(), data.end());
  uint16_t c = crc_modbus_(body.data(), body.size());
  std::vector<uint8_t> frame;
  frame.reserve(body.size() + 2);
  frame.insert(frame.end(), body.begin(), body.end());
  frame.push_back((uint8_t)(c >> 8));
  frame.push_back((uint8_t)(c & 0xFF));
  ESP_LOGI(TAG, ">> queue WRITE 0x%04X:%u = %s (frame %s)", index, sub,
           tohex(data.data(), data.size()).c_str(), tohex(frame.data(), frame.size()).c_str());
  tx_queue_.push_back(std::move(frame));
  if (st_ == ST_RUN && !tx_busy_) {
    auto f = tx_queue_.front();
    tx_queue_.erase(tx_queue_.begin());
    start_tx_(std::move(f));
  }
}

void RemehaBle::send_next_fragment_() {
  if (tx_off_ >= tx_msg_.size()) { tx_busy_ = false; return; }
  size_t remain = tx_msg_.size() - tx_off_;
  size_t chunk = remain > FRAG_DATA ? FRAG_DATA : remain;
  bool last = (tx_off_ + chunk) >= tx_msg_.size();
  uint8_t buf[1 + FRAG_DATA];
  buf[0] = last ? 0xFF : tx_seq_++;
  memcpy(buf + 1, tx_msg_.data() + tx_off_, chunk);
  tx_off_ += chunk;
  write_raw_(h_canip_w_, buf, chunk + 1);
}

// Decode one object's value bytes and publish it to whichever platform(s) the
// matching item is bound to. Shared by the bulk GetList path and the individual
// read path. `flag` 0x02 = "typed" (2-byte value + 2-byte type tag); anything
// else = raw little-endian value in `len` bytes.
void RemehaBle::decode_and_publish_(RemehaItem &it, uint8_t flag, const uint8_t *data, uint8_t len) {
  if (it.enum_map != nullptr && (it.text_sensor != nullptr || it.select_ != nullptr)) {
    // Enum shown as text: 1-byte choice number (or the low byte of a typed value).
    if (len < 1) return;
    int32_t raw = data[0];
    if (flag == 0x02 && len >= 2 && data[0] == 0xFF && data[1] == 0xFF) return;  // not available
    const char *txt = nullptr;
    for (auto &p : *it.enum_map) {
      if (p.first == raw) { txt = p.second; break; }
    }
    ESP_LOGD(TAG, "0x%04X:%u = %ld -> %s", it.index, it.sub, (long) raw, txt ? txt : "?");
    if (it.select_ != nullptr) {
      if (txt != nullptr) it.select_->publish_state(std::string(txt));
      else ESP_LOGW(TAG, "0x%04X:%u: keuze %ld staat niet in de lijst", it.index, it.sub, (long) raw);
    }
    if (it.text_sensor != nullptr) {
      if (txt != nullptr) it.text_sensor->publish_state(txt);
      else it.text_sensor->publish_state("onbekend (" + std::to_string(raw) + ")");
    }
    return;
  }
  if (it.text_sensor != nullptr) {
    std::string s;
    for (uint8_t j = 0; j < len && data[j]; j++) s.push_back((char) data[j]);
    it.text_sensor->publish_state(s);
    return;
  }
  if (it.sensor == nullptr && it.number == nullptr && it.binary_sensor == nullptr &&
      it.switch_ == nullptr) return;  // (select/text enums are handled above)
  int64_t raw = 0; bool ok = true;
  bool is_signed = (it.type == VT_I8 || it.type == VT_I16 || it.type == VT_I32);
  if (flag == 0x02) {
    ok = len >= 2;
    if (ok) {
      uint16_t v = (uint16_t)(data[0] | (data[1] << 8));
      raw = is_signed ? (int16_t) v : (int64_t) v;
    }
  } else {
    switch (it.type) {
      case VT_U8: case VT_ENUM: case VT_BOOL: ok = len >= 1; if (ok) raw = data[0]; break;
      case VT_I8:  ok = len >= 1; if (ok) raw = (int8_t) data[0]; break;
      case VT_U16: ok = len >= 2; if (ok) raw = (uint16_t)(data[0] | data[1] << 8); break;
      case VT_I16: ok = len >= 2; if (ok) raw = (int16_t)(data[0] | data[1] << 8); break;
      case VT_U32: ok = len >= 4; if (ok) raw = (uint32_t)(data[0] | data[1] << 8 | data[2] << 16 | (uint32_t) data[3] << 24); break;
      case VT_I32: ok = len >= 4; if (ok) raw = (int32_t)(data[0] | data[1] << 8 | data[2] << 16 | (uint32_t) data[3] << 24); break;
    }
  }
  // "not available" sentinels for sensors that aren't fitted
  bool na = (raw == -32768 && is_signed) ||
            (raw == 0xFFFF && !is_signed && (flag == 0x02 || it.type == VT_U16)) ||
            (it.type == VT_I32 && flag != 0x02 && raw == -2147483648LL) ||
            (it.type == VT_U32 && flag != 0x02 && raw == 0xFFFFFFFFLL) ||
            // a U8 measurement of 0xFF (e.g. water pressure 25.5 bar on an Elga Ace
            // without that sensor) means "no value"; settings and choices keep 255
            (it.type == VT_U8 && raw == 0xFF && it.sensor != nullptr && it.number == nullptr);
  if (!ok || na) return;
  // On/off entities: decided on the RAW value, before any bool/gain mapping.
  if (it.binary_sensor != nullptr || it.switch_ != nullptr) {
    bool on = it.has_true_value ? (raw == it.true_value) : (raw != 0);
    ESP_LOGD(TAG, "0x%04X:%u = %lld -> %s", it.index, it.sub, (long long) raw, on ? "aan" : "uit");
    if (it.binary_sensor != nullptr) it.binary_sensor->publish_state(on);
    if (it.switch_ != nullptr) it.switch_->publish_state(on);  // actual current state
    return;
  }
  // Boolean status flags (e.g. 0x502E:x) use 0 = no and 0xFF = yes (shown as
  // "Ja"). Map any non-zero value to 1.
  if (it.type == VT_BOOL) raw = raw != 0 ? 1 : 0;
  float val = (float) raw * it.gain;
  ESP_LOGD(TAG, "0x%04X:%u = %.3f", it.index, it.sub, val);
  if (it.sensor != nullptr) it.sensor->publish_state(val);
  if (it.number != nullptr) {
    ESP_LOGI(TAG, "read-back 0x%04X:%u = %.3f (number)", it.index, it.sub, val);
    it.number->publish_state(val);  // actual current value
  }
}

void RemehaBle::parse_response_(const std::vector<uint8_t> &m) {
  if (m.size() < 10) return;
  if (crc_modbus_(m.data(), m.size() - 2) != (uint16_t)((m[m.size() - 2] << 8) | m[m.size() - 1])) {
    ESP_LOGW(TAG, "response CRC mismatch (%u bytes)", (unsigned) m.size());
    return;
  }
  const size_t end = m.size() - 2;
  uint8_t op = m[5];  // 0x09 = bulk GetList response, 0x01 = individual read response, 0x05 = write response
  if ((op == 0x01 || op == 0x02) && probe_inflight_ && end >= 11) {
    uint32_t key = ((uint32_t) m[7] << 24) | ((uint32_t) ((m[8] << 8) | m[9]) << 8) | m[10];
    if (key == probe_expect_) probe_done_(op == 0x01, &m[11], end - 11, nullptr);
  }
  // Decide now whether this is the scan's own read: handle_scan_response_ moves
  // on to the next read, after which the check below could never match (every
  // expected refusal of the board search was then logged as a warning).
  const bool scan_own = scan_inflight_ && end >= 11 &&
                        scan_expect_ == (((uint32_t) m[7] << 24) | ((uint32_t) ((m[8] << 8) | m[9]) << 8) | m[10]);
  if ((op == 0x01 || op == 0x02) && scan_left_ > 0 && scan_inflight_ && end >= 11) {
    // handle_scan_response_ only takes the read it is waiting for
    handle_scan_response_(m[7], (uint16_t) (m[8] << 8) | m[9], m[10], &m[11], end - 11, op == 0x01);
  }
  if ((op == 0x01 || op == 0x02) && id_left_ > 0 && end >= 11 && m[7] == 1 &&
      ((m[8] == 0x20 && m[9] == 0x00 && m[10] == 9) || (m[8] == 0x30 && m[9] == 0x47 && m[10] == 0))) {
    handle_identification_((uint16_t) (m[8] << 8) | m[9], &m[11], end - 11, op == 0x01);
  }
  if ((op == 0x01 || op == 0x02) && menu_left_ > 0 && end >= 11 && m[8] == 0x50 && m[9] == 0x2B) {
    if (op == 0x01) parse_menu_block_(m[7], &m[11], end - 11);
    if (--menu_left_ == 0) {
      menu_done_ = true;
      ESP_LOGI(TAG, "menubeschrijving (0x502B) verwerkt");
    }
    // no return: a discovery dump may want this block too
  }
  if ((op == 0x01 || op == 0x02) && dump_left_ > 0 && dump_handle_(m, op)) return;

  if (op == 0x01) {
    // Individual read response: <01><00><node><idxHi><idxLo><sub><value...>
    // The whole remaining payload (offset 11 .. end) is the raw LE value.
    if (end < 12) { ESP_LOGW(TAG, "short individual response (%u bytes)", (unsigned) m.size()); return; }
    uint8_t node = m[7];
    uint16_t index = (uint16_t)(m[8] << 8) | m[9];
    uint8_t sub = m[10];
    const uint8_t *data = &m[11];
    uint8_t len = (uint8_t)(end - 11);
    for (auto &it : items_) {  // all entities bound to this object (e.g. sensor + select)
      if (it.node == node && it.index == index && it.sub == sub) decode_and_publish_(it, 0x01, data, len);
    }
    return;
  }

  if ((op == 0x05 || op == 0x06) && end >= 11 && m[8] == 0x50 && m[9] == 0x2D) {
    // menu format selection (start_menu_read_ / scan): not a user write
    uint32_t code = (op == 0x06 && end >= 15) ? le32(&m[11]) : 0;
    if (op == 0x05) ESP_LOGI(TAG, "menuformaat gekozen op node %u (0x502D)", m[7]);
    else ESP_LOGI(TAG, "menuformaat kiezen op node %u geweigerd: %s", m[7], sdo_abort_str(code));
    if (scan_left_ > 0 && scan_inflight_)
      handle_scan_response_(m[7], 0x502D, m[10], op == 0x06 ? &m[11] : nullptr, op == 0x06 ? end - 11 : 0, op == 0x05);
    return;
  }
  if (op == 0x05 && end >= 11) {  // write accepted (no payload)
    uint16_t index = (uint16_t)(m[8] << 8) | m[9];
    char msg[64];
    snprintf(msg, sizeof(msg), "OK: 0x%04X:%u node %u", index, m[10], m[7]);
    ESP_LOGI(TAG, "<< WRITE geaccepteerd 0x%04X:%u (node %u)", index, m[10], m[7]);
    if (write_result_ts_ != nullptr) write_result_ts_->publish_state(msg);
    return;
  }

  if ((op == 0x02 || op == 0x06) && end >= 11) {
    // Error response: <op><00><node><idxHi><idxLo><sub><abort code: 4 bytes LE>
    uint16_t index = (uint16_t)(m[8] << 8) | m[9];
    uint32_t code = (end >= 15) ? le32(&m[11]) : 0;
    const char *what = (op == 0x06) ? "WRITE GEWEIGERD" : "READ MISLUKT";
    // the configurator scan expects refusals (absent boards, level-5 blocks):
    // its own reads are logged quietly, the scan reports a summary
    if (scan_own) {
      ESP_LOGD(TAG, "<< %s 0x%04X:%u (node %u): abort 0x%08lX = %s", what, index, m[10], m[7],
               (unsigned long) code, sdo_abort_str(code));
    } else {
      ESP_LOGW(TAG, "<< %s 0x%04X:%u (node %u): abort 0x%08lX = %s", what, index, m[10], m[7],
               (unsigned long) code, sdo_abort_str(code));
    }
    // Object or subindex does not exist on this appliance: stop polling it, so
    // a value from the codebook that this model lacks does not cost a read every
    // cycle (and does not show a bogus value).
    if (op == 0x02 && (code == 0x06020000UL || code == 0x06090011UL)) {
      for (auto &it : items_) {
        if (it.node == m[7] && it.index == index && it.sub == m[10] && !it.missing) {
          it.missing = true;
          ESP_LOGW(TAG, "0x%04X:%u (node %u) bestaat niet op dit toestel: wordt niet meer uitgelezen",
                   index, m[10], m[7]);
        }
      }
    }
    if (op == 0x06 && write_result_ts_ != nullptr) {
      char msg[96];
      snprintf(msg, sizeof(msg), "geweigerd 0x%04X:%u: %s (0x%08lX)", index, m[10], sdo_abort_str(code),
               (unsigned long) code);
      write_result_ts_->publish_state(msg);
    }
    return;
  }

  if (op != 0x09) {  // anything else: nothing to publish
    ESP_LOGD(TAG, "response op 0x%02X (%u bytes): %s", op, (unsigned) m.size(), tohex(m.data(), m.size()).c_str());
    return;
  }

  // Bulk GetList response. Each entry: <flag:1><node:1><idxHi:1><idxLo:1><sub:1><status:2><len:1><data:len>
  // Which of the cycle's GetLists this answers: the batch of its first entry.
  int batch = -1;
  if (end >= 16) {
    uint16_t i0 = (uint16_t)(m[10] << 8) | m[11];
    for (auto &it : items_)
      if (!it.single && !it.missing && it.node == m[9] && it.index == i0 && it.sub == m[12]) { batch = it.batch; break; }
  }
  for (auto &it : items_) if (it.batch == batch) it.seen = false;
  size_t i = 8;
  while (i + 8 <= end) {
    uint8_t flag = m[i];
    uint8_t node = m[i + 1];
    uint16_t index = (uint16_t)(m[i + 2] << 8) | m[i + 3];
    uint8_t sub = m[i + 4];
    uint16_t status = (uint16_t)(m[i + 5] << 8) | m[i + 6];
    uint8_t len = m[i + 7];
    const uint8_t *data = &m[i + 8];
    if (i + 8 + len > end) break;
    if (status != 0x0000) {  // unavailable entry: log once per object so odd statuses become visible
      ESP_LOGV(TAG, "GetList 0x%04X:%u status 0x%04X", index, sub, status);
      i += 8 + len; continue;
    }
    for (auto &it : items_) {  // all entities bound to this object
      if (it.node == node && it.index == index && it.sub == sub) {
        it.seen = true;
        decode_and_publish_(it, flag, data, len);
      }
    }
    i += 8 + len;
  }
  // read: auto - an object the appliance does not return in the bulk GetList
  // (missing, or a non-zero status) is switched to an individual read at once,
  // and read in this same cycle.
  for (auto &it : items_) {
    if (it.single || !it.auto_read || it.missing || batch < 0 || it.batch != batch) continue;
    if (it.seen) { it.miss = 0; continue; }
    if (++it.miss >= 1) {
      it.single = true;
      indiv_q_.push_back(build_read_frame_(it.node, it.index, it.sub));  // read it in this cycle already
      ESP_LOGI(TAG, "0x%04X:%u (node %u) zit niet in de bulk-lijst: voortaan los uitgelezen", it.index, it.sub,
               it.node);
    }
  }
  // Menu descriptor (device limits) only after the first values are in.
  if ((!menu_done_ || !id_done_) && menu_left_ == 0 && id_left_ == 0 && menu_q_.empty()) start_menu_read_();
}

// ---- menu descriptor 0x502B: device limits for numbers and selects ----
// Before the blocks the PRO app reads 0x502C (answer 02) and writes that value
// to 0x502D, per board. Without it a Confida 40 answered every block with
// "general error" after the indoor unit had restarted; the selection then holds
// until the next restart, which is why the scan worked for weeks before.
// Each sub (1..20) is a block: u16 count (LE), 2 bytes (02 00), then count x 15
// bytes: [0] flags [1] size [2..3] index LE [4..7] min i32 LE [8..11] max i32 LE
// [12] subindex [13] step (raw) [14] user level. min = max = -1: no range.
static const uint8_t MENU_FORMAT = 0x02;

void RemehaBle::start_menu_read_() {
  menu_q_.clear(); menu_nodes_.clear(); menu_left_ = 0; id_left_ = 0;
  if (!id_done_) {  // which appliance is this? (once per boot)
    menu_q_.push_back(build_read_frame_(1, 0x2000, 9));
    menu_q_.push_back(build_read_frame_(1, 0x3047, 0));
    id_left_ = 2;
  }
  if (menu_done_) return;
  for (auto &it : items_) {
    if (it.number == nullptr && it.select_ == nullptr) continue;
    if (std::find(menu_nodes_.begin(), menu_nodes_.end(), it.node) == menu_nodes_.end())
      menu_nodes_.push_back(it.node);
  }
  if (menu_nodes_.empty()) { menu_done_ = true; return; }
  for (uint8_t n : menu_nodes_) {
    // as the PRO app does: select menu format 2 (0x502D), otherwise a board can
    // answer every block with "general error" (seen on a Confida 40 after a restart)
    menu_q_.push_back(build_write_frame_(n, 0x502D, 0, {MENU_FORMAT}));
    // Only blocks 1-5: the settings per access level 1-5 (6-10 are measurements,
    // 11-15 counters, 16+ do not exist). Limits are only needed for settings, and
    // each block can be 2 kB: with many entities the heap is tight.
    for (uint8_t s = 1; s <= 5; s++) { menu_q_.push_back(build_read_frame_(n, 0x502B, s)); menu_left_++; }
  }
  ESP_LOGI(TAG, "menubeschrijving (0x502B) lezen voor de grenzen van instellingen (%u blokken), vrij geheugen %u (grootste blok %u)",
           (unsigned) menu_left_, (unsigned) heap_caps_get_free_size(MALLOC_CAP_8BIT),
           (unsigned) heap_caps_get_largest_free_block(MALLOC_CAP_8BIT));
}

// One 15-byte record of 0x502B: <2><index:2 LE><min:4 LE><max:4 LE><sub><step><level>.
// After the last real record a block can continue with other data, which would
// read as records with nonsense ranges and levels (seen on an Elga Ace; on a
// Confida 40 only a few at the end). The first record that fails these checks
// ends the list of that block. Returns false for such a record.
bool RemehaBle::menu_record_(const uint8_t *r, MenuRec &out) {
  out.index = r[2] | (r[3] << 8);
  out.sub = r[12];
  out.step = r[13];
  out.level = r[14];
  int32_t mn = (int32_t) le32(r + 4), mx = (int32_t) le32(r + 8);
  out.raw_min = mn;
  out.raw_max = mx;
  if (out.index == 0) return false;
  if (out.level > 5 && out.level != 15) return false;
  if (mn == -1 && mx == -1) { out.min = mn; out.max = mx; return true; }  // no range
  // some modules store a negative minimum of a 16/8-bit object without sign
  // extension (e.g. 0x0000F63C for -2500): fix it when min would exceed max
  if (mn > mx && mn >= 0x8000 && mn <= 0xFFFF) mn = (int16_t) mn;
  else if (mn > mx && mn >= 0x80 && mn <= 0xFF) mn = (int8_t) mn;
  // and a 32-bit unsigned maximum (0xFFFFFFFE) reads as negative
  double mxd = (mx < mn && mx < 0) ? (double) (uint32_t) mx : (double) mx;
  if ((double) mn > mxd) return false;
  out.min = mn;
  out.max = mxd;
  return true;
}

// Bytes per record of a 0x502B block: 15 on the appliances seen so far. When the
// block length does not fit 15-byte records but does fit `count` equal records
// of another size, use that size (the first 15 bytes keep the same layout).
size_t RemehaBle::menu_stride_(const uint8_t *d, size_t len) {
  if (len < 4) return 15;
  size_t count = d[0] | (d[1] << 8), avail = len - 4;
  if (count == 0 || avail % 15 == 0) return 15;
  if (avail % count == 0 && avail / count > 15 && avail / count <= 32) return avail / count;
  return 15;
}

void RemehaBle::parse_menu_block_(uint8_t node, const uint8_t *d, size_t len) {
  if (len < 4) return;
  size_t count = d[0] | (d[1] << 8), rs = menu_stride_(d, len);
  size_t bad = 0;
  for (size_t k = 0; k < count && 4 + rs * (k + 1) <= len; k++) {
    MenuRec rec;
    if (!menu_record_(d + 4 + rs * k, rec)) {  // see handle_scan_response_: same rule
      if (rec.index == 0 || ++bad >= 3) break;
      continue;
    }
    bad = 0;
    uint16_t index = rec.index;
    uint8_t sub = rec.sub, step = rec.step;
    int32_t mn = rec.min, mx = rec.raw_max;
    float mxf = (float) rec.max;
    if (rec.raw_min == -1 && rec.raw_max == -1) continue;
    for (auto &it : items_) {
      if (it.node != node || it.index != index || it.sub != sub) continue;
      if (it.number != nullptr) {
        float g = it.gain == 0.0f ? 1.0f : it.gain;
        static_cast<RemehaNumber *>(it.number)->apply_device_limits(mn * g, mxf * g, step > 0 ? step * g : NAN);
      }
      if (it.select_ != nullptr) static_cast<RemehaSelect *>(it.select_)->set_device_range(mn, mx);
    }
  }
}

// Known appliances by article number (0x2000:09). Others are logged so users can
// report them; the number alone already distinguishes models.
struct KnownAppliance { uint32_t article; const char *name; };
static const KnownAppliance KNOWN_APPLIANCES[] = {
  {7887477, "Remeha Confida 40"},
  {7854722, "Remeha Elga Ace"},   // Elga Ace controlbox, same for the 4, 6 and 8 kW monoblock
};

void RemehaBle::handle_identification_(uint16_t index, const uint8_t *d, size_t len, bool ok) {
  if (ok && index == 0x2000 && len >= 4) article_ = le32(d);
  if (ok && index == 0x3047) {
    appliance_name_.clear();
    for (size_t i = 0; i < len && d[i]; i++) appliance_name_.push_back((char) d[i]);
  }
  if (--id_left_ > 0) return;
  id_done_ = true;
  const char *known = nullptr;
  for (auto &k : KNOWN_APPLIANCES) if (k.article == article_) known = k.name;
  char buf[96];
  if (article_ == 0 || article_ == 0xFFFFFFFFUL) {
    snprintf(buf, sizeof(buf), "onbekend%s%s", appliance_name_.empty() ? "" : " - ", appliance_name_.c_str());
  } else if (known != nullptr) {
    snprintf(buf, sizeof(buf), "%s (%lu)", known, (unsigned long) article_);
  } else {
    snprintf(buf, sizeof(buf), "artikelnummer %lu%s%s", (unsigned long) article_, appliance_name_.empty() ? "" : " - ",
             appliance_name_.c_str());
  }
  ESP_LOGI(TAG, "toestel: %s (interne naam '%s')%s", buf, appliance_name_.c_str(),
           known ? "" : " - onbekend type: geef het artikelnummer door, dan nemen we het op");
  bool other = !expected_articles_.empty() &&
               std::find(expected_articles_.begin(), expected_articles_.end(), article_) == expected_articles_.end();
  if (other) {
    ESP_LOGW(TAG, "LET OP: deze configuratie is gemaakt voor een ander toestel (artikelnummer %lu niet in "
             "expected_article_number). Controleer of de entiteiten kloppen.", (unsigned long) article_);
    size_t n = strlen(buf);
    snprintf(buf + n, sizeof(buf) - n, " - YAML voor ander toestel");
  }
  if (appliance_ts_ != nullptr) appliance_ts_->publish_state(buf);
}

uint32_t RemehaNumber::pref_hash_() const {
  uint32_t h = 0x811C9DC5UL;  // FNV-1a over a tag + node/index/sub
  const uint8_t key[] = {'r', 'l', 'i', 'm', node_, (uint8_t) (index_ >> 8), (uint8_t) index_, sub_};
  for (uint8_t b : key) { h ^= b; h *= 16777619UL; }
  return h;
}

void RemehaNumber::setup() {
  if (!use_device_limits_) return;
  pref_ = global_preferences->make_preference<LimitsPref>(pref_hash_(), true);
  LimitsPref p{};
  if (pref_.load(&p) && p.magic == 0x524C4D31UL && p.max >= p.min) {
    traits.set_min_value(p.min);
    traits.set_max_value(p.max);
    if (!std::isnan(p.step) && p.step > 0) traits.set_step(p.step);
    dev_min_ = p.min; dev_max_ = p.max; limits_known_ = true;
    ESP_LOGD(TAG, "number 0x%04X:%u: opgeslagen toestelgrenzen %.3f..%.3f", index_, sub_, p.min, p.max);
  }
}

void RemehaNumber::apply_device_limits(float min, float max, float step) {
  if (!use_device_limits_ || max < min) return;
  bool same = limits_known_ && fabsf(min - dev_min_) < 1e-4f && fabsf(max - dev_max_) < 1e-4f &&
              (std::isnan(step) || fabsf(step - traits.get_step()) < 1e-4f);
  traits.set_min_value(min);
  traits.set_max_value(max);
  if (!std::isnan(step) && step > 0) traits.set_step(step);
  dev_min_ = min; dev_max_ = max; limits_known_ = true;
  if (same) return;
  ESP_LOGI(TAG, "number 0x%04X:%u: grenzen van het toestel %.3f..%.3f stap %.3f (opgeslagen; HA ziet ze na "
           "de volgende herstart of herverbinding)", index_, sub_, min, max, traits.get_step());
  LimitsPref p{min, max, std::isnan(step) ? NAN : step, 0x524C4D31UL};
  pref_.save(&p);
}

void RemehaSelect::set_device_range(int32_t lo, int32_t hi) {
  if (hi < lo) return;
  range_known_ = true; dev_lo_ = lo; dev_hi_ = hi;
  ESP_LOGD(TAG, "select 0x%04X:%u: toestel staat keuzes %ld..%ld toe", index_, sub_, (long) lo, (long) hi);
}

// What this firmware currently reads/writes, so the configurator page can start
// from it: device names plus [[node, index, sub, writable, "entity name"], ...].
// items_ and the names are fixed after setup, so reading them from the HTTP task
// is safe.
static void json_str_(std::string &j, const char *s, size_t n) {
  j += '"';
  for (size_t i = 0; i < n; i++) {
    char c = s[i];
    if (c == '"' || c == '\\') { j += '\\'; j += c; }
    else if ((unsigned char) c < 0x20) j += ' ';
    else j += c;
  }
  j += '"';
}

std::string RemehaBle::current_json() const {
  std::string j;
  j.reserve(80 + items_.size() * 70);
  j += "{\"device\":";
  json_str_(j, App.get_name().c_str(), App.get_name().size());
  j += ",\"friendly\":";
  json_str_(j, App.get_friendly_name().c_str(), App.get_friendly_name().size());
  j += ",\"items\":[";
  char buf[40];
  bool first = true;
  for (auto &it : items_) {
    bool w = it.number != nullptr || it.switch_ != nullptr || it.select_ != nullptr;
    EntityBase *e = it.sensor != nullptr ? (EntityBase *) it.sensor
                  : it.text_sensor != nullptr ? (EntityBase *) it.text_sensor
                  : it.binary_sensor != nullptr ? (EntityBase *) it.binary_sensor
                  : it.number != nullptr ? (EntityBase *) it.number
                  : it.switch_ != nullptr ? (EntityBase *) it.switch_
                  : (EntityBase *) it.select_;
    snprintf(buf, sizeof(buf), "%s[%u,%u,%u,%u,", first ? "" : ",", (unsigned) it.node, (unsigned) it.index,
             (unsigned) it.sub, (unsigned) w);
    j += buf;
    if (e != nullptr) {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
      const StringRef &n = e->get_name();  // get_name_to() only exists from ESPHome 2026.11
#pragma GCC diagnostic pop
      json_str_(j, n.c_str(), n.size());
    } else {
      j += "\"\"";
    }
    j += ']';
    first = false;
  }
  j += "]}";
  return j;
}

// ---- configurator "read" button ----
std::string RemehaBle::probe_request(uint8_t node, uint16_t index, uint8_t sub) {
  std::lock_guard<std::mutex> lock(scan_mtx_);
  probe_node_ = node; probe_index_ = index; probe_sub_ = sub;
  probe_id_++;
  char buf[48];
  snprintf(buf, sizeof(buf), "{\"state\":\"pending\",\"id\":%u}", (unsigned) probe_id_);
  probe_json_ = buf;
  probe_req_.store(true);
  return probe_json_;
}

std::string RemehaBle::probe_poll() {
  std::lock_guard<std::mutex> lock(scan_mtx_);
  return probe_json_;
}

// Result as raw bytes (the page decodes them with the codebook); a refused read
// carries the abort code in its first 4 bytes.
void RemehaBle::probe_done_(bool ok, const uint8_t *d, size_t len, const char *err) {
  probe_inflight_ = false;
  if (len > 64) len = 64;
  std::string j;
  j.reserve(80 + len * 2);
  std::lock_guard<std::mutex> lock(scan_mtx_);
  if (probe_req_.load()) return;  // a newer request is waiting; that one answers
  char buf[64];
  snprintf(buf, sizeof(buf), "{\"state\":\"done\",\"id\":%u,\"ok\":%s,\"err\":\"%s\",\"hex\":\"",
           (unsigned) probe_id_, ok ? "true" : "false", err != nullptr ? err : "");
  j += buf;
  static const char HEX[] = "0123456789abcdef";
  for (size_t k = 0; k < len; k++) { j += HEX[d[k] >> 4]; j += HEX[d[k] & 15]; }
  j += "\"}";
  probe_json_.swap(j);
}

// ---- configurator scan (for the page on the ESP, see configurator_web.cpp) ----
// 1. 0x2000:09 (article number) and 0x3047 (name) on node 1, the controller.
// 2. 0x502B:1..15 on node 1 and node 4 (1-5 settings, 6-10 measurements, 11-15
//    counters, per access level 1-5), exactly as before the board search.
//    Per board first 0x502C (menu format) and a write of that value to 0x502D,
//    as the PRO app does; see start_menu_read_.
// 3. Find other boards: 0x3047 on node 2..SCAN_NODE_MAX. A node that answers,
//    with a value or with a 0x06...... abort, is there; "general error" or no
//    answer means no board. Then 0x502B:1..15 of each extra board found.
//    The search comes last on purpose: on a Confida 40 the menu reads failed
//    with "general error" after the search had addressed other nodes.
// "General error" is retried twice; a board whose blocks keep failing is skipped.
// One read at a time; every menu block becomes a JSON chunk for the page. At most
// SCAN_MAX_CHUNKS chunks wait for the page; beyond that the scan pauses.
static const uint8_t SCAN_NODE_MAX = 16;
static const uint8_t SCAN_MENU_SUBS = 15;
static const size_t SCAN_MAX_CHUNKS = 3;
static const uint32_t SCAN_PAUSE_TIMEOUT_MS = 60000;
static const uint32_t SCAN_READ_TIMEOUT_MS = 8000;    // a full block takes ~1.5 s
static const uint32_t SCAN_PROBE_TIMEOUT_MS = 2500;   // node search: an absent node may not answer
static const uint32_t SCAN_RETRY_DELAY_MS = 500;
static const uint32_t ABORT_GENERAL = 0x08000000UL;
static const size_t SCAN_MIN_FREE_BLOCK = 8192;  // keep this much contiguous heap free for BLE/wifi

void RemehaBle::request_scan() {
  scan_poll_ms_.store(millis());
  scan_req_.store(true);
}

std::string RemehaBle::scan_poll(int gen, uint16_t from) {
  scan_poll_ms_.store(millis());
  std::lock_guard<std::mutex> lock(scan_mtx_);
  if (gen != (int) scan_gen_.load()) from = 0;  // page is behind: send everything of this run
  // the page has these chunks: free them
  scan_chunks_.erase(std::remove_if(scan_chunks_.begin(), scan_chunks_.end(),
                                    [from](const std::pair<uint16_t, std::string> &c) { return c.first < from; }),
                     scan_chunks_.end());
  size_t n = scan_head_.size() + 32;
  for (auto &c : scan_chunks_) n += c.second.size() + 1;
  std::string j;
  j.reserve(n);
  j += scan_head_;
  j += ",\"recs\":[";
  uint16_t next = from;
  for (auto &c : scan_chunks_) {
    if (next != from) j += ',';
    j += c.second;
    next = c.first + 1;
  }
  char buf[24];
  snprintf(buf, sizeof(buf), "],\"next\":%u}", (unsigned) next);
  j += buf;
  return j;
}

void RemehaBle::loop() {
  // configurator "read" button: one read at a time, answered via probe_poll()
  if (probe_req_.exchange(false)) {
    uint8_t n, s;
    uint16_t i;
    {
      std::lock_guard<std::mutex> lock(scan_mtx_);
      n = probe_node_; i = probe_index_; s = probe_sub_;
    }
    if (st_ != ST_RUN) {
      probe_done_(false, nullptr, 0, "no_link");
    } else {
      menu_q_.push_back(build_read_frame_(n, i, s));
      probe_expect_ = ((uint32_t) n << 24) | ((uint32_t) i << 8) | s;
      probe_ms_ = millis();
      probe_inflight_ = true;
      if (!tx_busy_) send_next_individual_();
    }
  }
  if (probe_inflight_ && millis() - probe_ms_ > 10000) probe_done_(false, nullptr, 0, "timeout");
  if ((st_ == ST_AUTH0_WAIT_CHAL || st_ == ST_AUTH0_WAIT_ACK) && millis() - auth0_ms_ > AUTH0_TIMEOUT_MS) {
    ESP_LOGW(TAG, ">> canip 02.00: geen antwoord - verder zonder");
    enter_run_();
  }
  if (scan_req_.exchange(false)) {
    if (scan_state_ == 2) {
      // already reading: start over (the page lost its data, e.g. after a reload)
      if (scan_inflight_) scan_restart_ = true; else { scan_reset_(); scan_issue_next_(); }
    } else {
      scan_pending_ = true;
      scan_state_ = 1;
      update_scan_json_();
    }
  }
  // start once the link runs and the boot-time identification/menu reads are done
  if (scan_pending_ && st_ == ST_RUN && menu_left_ == 0 && id_left_ == 0 && !scan_inflight_) start_scan_();
  if (scan_state_ == 2 && scan_inflight_ &&
      millis() - scan_issue_ms_ > (((scan_expect_ >> 8) & 0xFFFF) == 0x3047 ? SCAN_PROBE_TIMEOUT_MS : SCAN_READ_TIMEOUT_MS)) {
    ESP_LOGW(TAG, "configurator: geen antwoord op 0x%04X:%u (node %u)",
             (unsigned) ((scan_expect_ >> 8) & 0xFFFF), (unsigned) (scan_expect_ & 0xFF), (unsigned) (scan_expect_ >> 24));
    handle_scan_response_(scan_expect_ >> 24, (scan_expect_ >> 8) & 0xFFFF, scan_expect_ & 0xFF, nullptr, 0, false);
  }
  if (scan_state_ == 2 && !scan_inflight_) {
    scan_issue_next_();  // resumes after the page fetched its chunks
    if (!scan_inflight_ && millis() - scan_poll_ms_.load() > SCAN_PAUSE_TIMEOUT_MS)
      scan_abort_("de pagina haalt de gegevens niet op");
  }
}

void RemehaBle::scan_reset_() {
  scan_restart_ = false;
  scan_article_ = 0;
  scan_name_.clear();
  scan_nodes_.clear();
  scan_steps_.clear();
  scan_steps_.push_back({1, 0x2000, 9, 0, SCAN_ARTICLE});
  scan_steps_.push_back({1, 0x3047, 0, 0, SCAN_NAME});
  for (uint8_t n : {1, 4}) push_menu_steps_(n);
  for (uint8_t n = 2; n <= SCAN_NODE_MAX; n++) scan_steps_.push_back({n, 0x3047, 0, 0, SCAN_FIND});
  scan_pos_ = 0;
  scan_retry_at_ = 0;
  scan_fails_ = 0;
  scan_total_ = scan_steps_.size();  // grows when extra boards are found
  scan_left_ = scan_total_;
  scan_seq_ = 0;
  scan_state_ = 2;
  {
    std::lock_guard<std::mutex> lock(scan_mtx_);
    scan_gen_++;
    scan_chunks_.clear();
    scan_chunks_.shrink_to_fit();
  }
  update_scan_json_();
}

// Per board: 0x502C (menu format), write it to 0x502D as the PRO app does, then the blocks.
void RemehaBle::push_menu_steps_(uint8_t node) {
  scan_steps_.push_back({node, 0x502C, 0, 0, SCAN_FMT});
  scan_steps_.push_back({node, 0x502D, 0, 0, SCAN_SELECT});
  for (uint8_t b = 1; b <= SCAN_MENU_SUBS; b++) scan_steps_.push_back({node, 0x502B, b, 0, SCAN_MENU});
}

void RemehaBle::start_scan_() {
  scan_pending_ = false;
  scan_poll_ms_.store(millis());
  scan_reset_();
  ESP_LOGI(TAG, "configurator: toestel scannen (%u reads), vrij geheugen %u (grootste blok %u)",
           (unsigned) scan_total_, (unsigned) heap_caps_get_free_size(MALLOC_CAP_8BIT),
           (unsigned) heap_caps_get_largest_free_block(MALLOC_CAP_8BIT));
  scan_issue_next_();
}

void RemehaBle::scan_issue_next_() {
  if (scan_state_ != 2 || scan_inflight_ || scan_pos_ >= scan_steps_.size()) return;
  if (scan_retry_at_ != 0 && (int32_t) (millis() - scan_retry_at_) < 0) return;  // waiting to retry
  scan_retry_at_ = 0;
  {
    std::lock_guard<std::mutex> lock(scan_mtx_);
    if (scan_chunks_.size() >= SCAN_MAX_CHUNKS) return;  // wait for the page
  }
  if (heap_caps_get_largest_free_block(MALLOC_CAP_8BIT) < SCAN_MIN_FREE_BLOCK) {
    scan_abort_("te weinig vrij geheugen op de ESP");
    return;
  }
  const ScanStep &st = scan_steps_[scan_pos_];
  uint8_t node = st.node, sub = st.sub;
  uint16_t index = st.index;
  if (st.kind == SCAN_SELECT) menu_q_.push_back(build_write_frame_(node, index, sub, {scan_fmt_}));
  else menu_q_.push_back(build_read_frame_(node, index, sub));
  scan_expect_ = ((uint32_t) node << 24) | ((uint32_t) index << 8) | sub;
  scan_issue_ms_ = millis();
  scan_inflight_ = true;
  if (!tx_busy_) send_next_individual_();
}

void RemehaBle::scan_abort_(const char *why) {
  ESP_LOGW(TAG, "configurator: scan afgebroken: %s", why);
  scan_state_ = 4;
  scan_left_ = 0;
  scan_inflight_ = false;
  scan_restart_ = false;
  char buf[160];
  snprintf(buf, sizeof(buf), "{\"state\":\"error\",\"gen\":%u,\"msg\":\"%s\"", (unsigned) scan_gen_.load(), why);
  std::lock_guard<std::mutex> lock(scan_mtx_);
  scan_chunks_.clear();
  scan_chunks_.shrink_to_fit();
  scan_head_ = buf;
}

void RemehaBle::handle_scan_response_(uint8_t node, uint16_t index, uint8_t sub, const uint8_t *d, size_t len,
                                          bool ok) {
  // only the read we are waiting for (not a late answer after a timeout or abort)
  if (!scan_inflight_ || scan_expect_ != (((uint32_t) node << 24) | ((uint32_t) index << 8) | sub)) return;
  scan_inflight_ = false;
  if (scan_restart_) {
    scan_reset_();
    scan_issue_next_();
    return;
  }
  uint32_t abort = (!ok && d != nullptr && len >= 4) ? le32(d) : 0;
  uint8_t kind = scan_pos_ < scan_steps_.size() ? scan_steps_[scan_pos_].kind : (uint8_t) SCAN_MENU;
  // "general error": the CAN bus or the board was busy; try the same read again.
  // No answer at all (a lost fragment, the read timed out): once more, except in
  // the board search, where no answer means no board.
  bool no_answer = !ok && d == nullptr;
  if (!ok && scan_pos_ < scan_steps_.size() &&
      ((abort == ABORT_GENERAL && scan_steps_[scan_pos_].tries < (kind == SCAN_FIND ? 1 : 2)) ||
       (no_answer && kind != SCAN_FIND && scan_steps_[scan_pos_].tries < 1))) {
    if (no_answer)
      ESP_LOGI(TAG, "configurator: 0x%04X:%u (node %u) opnieuw lezen", (unsigned) index, (unsigned) sub, (unsigned) node);
    scan_steps_[scan_pos_].tries++;
    scan_retry_at_ = millis() + SCAN_RETRY_DELAY_MS;
    if (scan_retry_at_ == 0) scan_retry_at_ = 1;
    return;  // the loop issues it again after the delay
  }
  scan_pos_++;
  if (kind == SCAN_FMT) {
    if (ok && len >= 1 && d[0] != 0) {
      scan_fmt_ = d[0];
      ESP_LOGI(TAG, "configurator: node %u menuformaat (0x502C) = %u", node, (unsigned) scan_fmt_);
    } else {
      scan_fmt_ = MENU_FORMAT;
      // object not there (older control): do not write 0x502D either
      if (!ok && abort != ABORT_GENERAL && abort != 0 && scan_pos_ < scan_steps_.size() &&
          scan_steps_[scan_pos_].kind == SCAN_SELECT && scan_steps_[scan_pos_].node == node) {
        scan_pos_++;
        if (scan_left_ > 1) scan_left_--;
      }
      ESP_LOGI(TAG, "configurator: node %u geen menuformaat (0x502C): %s", node,
               ok ? "leeg" : sdo_abort_str(abort));
    }
  }
  if (kind == SCAN_MENU) {
    // a board whose menu blocks keep failing (general error / no answer): skip the rest of it
    bool failed = !ok && (abort == ABORT_GENERAL || abort == 0);
    scan_fails_ = failed ? scan_fails_ + 1 : 0;
    if (scan_fails_ >= 3) {
      ESP_LOGW(TAG, "configurator: menu van node %u geeft steeds een fout, rest overgeslagen", node);
      while (scan_pos_ < scan_steps_.size() && scan_steps_[scan_pos_].kind == SCAN_MENU &&
             scan_steps_[scan_pos_].node == node) {
        scan_pos_++;
        if (scan_left_ > 1) scan_left_--;
      }
      scan_fails_ = 0;
    }
  }
  if (kind == SCAN_NAME || kind == SCAN_FIND) {
    // present when it answers with a value or with a 0x06.. abort
    if (ok || (abort >> 24) == 0x06) {
      std::string nm;
      for (size_t i = 0; ok && i < len && d[i] && nm.size() < 24; i++)
        if (isalnum(d[i]) || d[i] == '-' || d[i] == ' ' || d[i] == '_') nm.push_back((char) d[i]);
      if (kind == SCAN_NAME) scan_name_ = nm;
      scan_nodes_.emplace_back(node, nm);
      ESP_LOGI(TAG, "configurator: bord op node %u%s%s", node, nm.empty() ? "" : ": ", nm.c_str());
    }
    if (kind == SCAN_FIND && node == SCAN_NODE_MAX) {
      // search done: add the menu blocks of the extra boards
      std::string list;
      for (auto &n : scan_nodes_) {
        char b[40];
        snprintf(b, sizeof(b), "%s%u%s%s", list.empty() ? "" : ", ", (unsigned) n.first, n.second.empty() ? "" : " ",
                 n.second.c_str());
        list += b;
      }
      ESP_LOGI(TAG, "configurator: printen gevonden: %s", list.empty() ? "geen" : list.c_str());
      size_t added = 0;
      for (auto &n : scan_nodes_) {
        if (n.first == 1 || n.first == 4) continue;  // already read
        push_menu_steps_(n.first);
        added += SCAN_MENU_SUBS + 2;
      }
      scan_total_ += added;
      scan_left_ += added;
    }
  }
  if (ok && index == 0x2000 && len >= 4) scan_article_ = le32(d);
  if (ok && index == 0x502B && len >= 4) {
    parse_menu_block_(node, d, len);  // also apply the limits to numbers/selects
    size_t count = d[0] | (d[1] << 8);
    size_t rs = menu_stride_(d, len);
    size_t fit = len >= 4 ? (len - 4) / rs : 0;
    // diagnostics: block size and record size, so a different layout shows up in the log
    ESP_LOGI(TAG, "configurator: 0x502B:%u node %u: %u records opgegeven, %u bytes, record %u bytes%s", sub, node,
             (unsigned) count, (unsigned) len, (unsigned) rs, (len - 4) % rs ? " (rest past niet)" : "");
    if (count > fit) count = fit;
    if (count > 0) {
      if (heap_caps_get_largest_free_block(MALLOC_CAP_8BIT) < SCAN_MIN_FREE_BLOCK + count * 48) {
        scan_abort_("te weinig vrij geheugen op de ESP");
        return;
      }
      std::string c;
      c.reserve(count * 40);
      char buf[96];
      size_t kept = 0, bad = 0, skipped = 0;
      for (size_t k = 0; k < count; k++) {
        const uint8_t *r = d + 4 + rs * k;
        MenuRec rec;
        // A record that cannot be real is skipped. Index 0 ends the list (seen
        // after the last record on a Confida 40); three bad ones in a row mean
        // the rest is not records either.
        if (!menu_record_(r, rec)) {
          if (skipped == 0)
            ESP_LOGI(TAG, "configurator: 0x502B:%u node %u: record %u van %u niet geldig: %s", sub, node, (unsigned) k,
                     (unsigned) count, tohex(r, rs).c_str());
          skipped++;
          if (rec.index == 0 || ++bad >= 3) {
            ESP_LOGI(TAG, "configurator: 0x502B:%u node %u: einde van de lijst na record %u", sub, node, (unsigned) k);
            break;
          }
          continue;
        }
        bad = 0;
        // raw min/max as the appliance sends them; the page applies the same fixes
        snprintf(buf, sizeof(buf), "%s[%u,%u,%u,%ld,%ld,%u,%u]", kept ? "," : "", (unsigned) node,
                 (unsigned) rec.index, (unsigned) rec.sub, (long) rec.raw_min, (long) rec.raw_max,
                 (unsigned) rec.step, (unsigned) rec.level);
        c += buf;
        kept++;
      }
      std::lock_guard<std::mutex> lock(scan_mtx_);
      if (kept > 0) scan_chunks_.emplace_back(scan_seq_++, std::move(c));
    }
  }
  if (scan_left_ > 0) scan_left_--;
  if (scan_left_ == 0) {
    scan_state_ = 3;
    ESP_LOGI(TAG, "configurator: scan klaar, vrij geheugen %u (grootste blok %u)",
             (unsigned) heap_caps_get_free_size(MALLOC_CAP_8BIT),
             (unsigned) heap_caps_get_largest_free_block(MALLOC_CAP_8BIT));
  }
  update_scan_json_();
  scan_issue_next_();
}

// Status part of the poll answer (without the closing brace; scan_poll adds the chunks).
void RemehaBle::update_scan_json_() {
  if (scan_state_ == 4) return;  // keep the error text
  static const char *STATES[] = {"idle", "waiting", "scanning", "done"};
  char buf[200];
  snprintf(buf, sizeof(buf),
           "{\"state\":\"%s\",\"gen\":%u,\"progress\":%u,\"total\":%u,\"route\":\"%s\",\"article\":%lu,\"name\":\"%s\"",
           STATES[scan_state_ & 3], (unsigned) scan_gen_.load(), (unsigned) (scan_total_ - scan_left_), (unsigned) scan_total_,
           requires_pairing_ ? "gtw22" : "gtwiot", (unsigned long) scan_article_, scan_name_.c_str());
  std::string h = buf;
  h += ",\"nodes\":[";
  for (size_t k = 0; k < scan_nodes_.size(); k++) {
    char nb[48];
    snprintf(nb, sizeof(nb), "%s[%u,\"%s\"]", k ? "," : "", (unsigned) scan_nodes_[k].first, scan_nodes_[k].second.c_str());
    h += nb;
  }
  h += ']';
  std::lock_guard<std::mutex> lock(scan_mtx_);
  scan_head_.swap(h);
}

// ---- discovery dump (verkenning) ----
// Objects that may tell what a device is and what it offers (see the OBD
// function groups "Identification device", "Mandatory platform" and "System
// discovery"). Arrays: sub 0 is the entry count, then subs 1..count are read.
struct DumpObj { uint16_t index; uint8_t max_sub; };  // max_sub 0 = scalar (sub 0 only)
static const uint8_t DUMP_ID_NODES[] = {1, 3, 4, 5};
static const DumpObj DUMP_ID[] = {
  {0x1000, 0},   // canDeviceType
  {0x2000, 10},  // appliance info record
  {0x2001, 16},  // device info record (type, versions, article number)
  {0x300F, 0},   // device name
  {0x3018, 0},   // configuration CN1/CN2
  {0x3042, 0},   // short device name
  {0x3047, 0},   // appliance name
};
static const uint8_t DUMP_DISC_NODES[] = {1, 4};
static const DumpObj DUMP_DISC[] = {
  {0x2007, 40},   // parFunctionGroup: defined function groups
  {0x3019, 50},   // supported HMI function list
  {0x502C, 2},    // supported menu structure version
  {0x502D, 0},    // used menu structure version
  {0x502B, 20},   // varApMenuDescriptor: data objects available to the user
  {0x5826, 255},  // trending self-describer (layout of 0x501D)
  {0x3095, 20},   // nodes discovered
  {0x3096, 70},   // function groups discovered
  {0x3097, 12},   // zones discovered
  {0x3098, 8},    // producers discovered
  {0x50D8, 0},    // function group version
  {0x516B, 0},    // discovery status
  {0x516D, 255},  // discovered nodes
  {0x516E, 255},  // discovered devices
  {0x516F, 10},   // discovered appliances
  {0x5170, 255},  // discovered function groups
  {0x5171, 32},   // discovered producers
  {0x5172, 32},   // discovered zones
  {0x5173, 0},    // discovery version
  {0x5074, 0},    // discovered zones (JSON)
};

void RemehaBle::dump_queue_read_(uint8_t node, uint16_t index, uint8_t sub) {
  dump_q_.push_back(build_read_frame_(node, index, sub));
  dump_keys_.push_back(((uint32_t) node << 24) | ((uint32_t) index << 8) | sub);
  dump_left_++;
}

void RemehaBle::start_discovery_dump() {
  if (!dump_q_.empty()) { ESP_LOGW(TAG, "DUMP loopt al (%u reads in de wachtrij)", (unsigned) dump_q_.size()); return; }
  dump_q_.clear(); dump_keys_.clear(); dump_arrays_.clear(); dump_left_ = 0;
  auto add = [this](uint8_t node, const DumpObj &o) {
    dump_queue_read_(node, o.index, 0);
    if (o.max_sub > 0) dump_arrays_.push_back({((uint32_t) node << 16) | o.index, o.max_sub});
  };
  for (uint8_t n : DUMP_ID_NODES) for (const auto &o : DUMP_ID) add(n, o);
  for (uint8_t n : DUMP_DISC_NODES) for (const auto &o : DUMP_DISC) add(n, o);
  ESP_LOGI(TAG, "DUMP gestart: %u reads (alleen lezen); arrays worden daarna per element gelezen",
           (unsigned) dump_left_);
  if (st_ == ST_RUN) send_next_individual_();
  else ESP_LOGI(TAG, "DUMP wacht tot de verbinding loopt");
}

bool RemehaBle::dump_handle_(const std::vector<uint8_t> &m, uint8_t op) {
  const size_t end = m.size() - 2;
  if (end < 11) return false;
  uint8_t node = m[7];
  uint16_t index = (uint16_t)(m[8] << 8) | m[9];
  uint8_t sub = m[10];
  uint32_t key = ((uint32_t) node << 24) | ((uint32_t) index << 8) | sub;
  auto k = std::find(dump_keys_.begin(), dump_keys_.end(), key);
  if (k == dump_keys_.end()) return false;
  dump_keys_.erase(k);
  if (dump_left_ > 0) dump_left_--;
  if (op == 0x02) {
    uint32_t code = (end >= 15) ? le32(&m[11]) : 0;
    ESP_LOGI(TAG, "DUMP n%u 0x%04X:%02X fout 0x%08lX (%s)", node, index, sub, (unsigned long) code,
             sdo_abort_str(code));
  } else {
    const uint8_t *d = &m[11];
    size_t len = end - 11;
    if (len <= 32) {
      ESP_LOGI(TAG, "DUMP n%u 0x%04X:%02X len=%u %s", node, index, sub, (unsigned) len, tohex(d, len).c_str());
    } else {  // long value: chunks of 32 bytes so log lines are not truncated
      for (size_t o = 0; o < len; o += 32) {
        size_t c = (len - o) > 32 ? 32 : (len - o);
        ESP_LOGI(TAG, "DUMP n%u 0x%04X:%02X len=%u @%u %s", node, index, sub, (unsigned) len, (unsigned) o,
                 tohex(d + o, c).c_str());
      }
    }
    // Array: sub 0 holds the entry count -> queue subs 1..count (capped).
    if (sub == 0 && len >= 1) {
      uint32_t akey = ((uint32_t) node << 16) | index;
      for (auto &a : dump_arrays_) {
        if (a.first != akey) continue;
        uint8_t n = d[0] < a.second ? d[0] : a.second;
        for (uint8_t s = 1; s <= n && s != 0; s++) dump_queue_read_(node, index, s);
        if (n > 0) ESP_LOGI(TAG, "DUMP n%u 0x%04X: %u elementen in de wachtrij", node, index, n);
        break;
      }
    }
  }
  if (dump_left_ == 0) ESP_LOGI(TAG, "DUMP klaar");
  return true;
}

// ---- writable number parameter ----
void RemehaNumber::control(float value) {
  if (parent_ == nullptr) {
    ESP_LOGW(TAG, "number has no parent hub");
    return;
  }
  if (limits_known_ && (value < dev_min_ - 1e-4f || value > dev_max_ + 1e-4f)) {
    ESP_LOGW(TAG, "number 0x%04X:%u: %.3f valt buiten de grenzen van het toestel (%.3f..%.3f), niet geschreven",
             index_, sub_, value, dev_min_, dev_max_);
    if (this->has_state()) this->publish_state(this->state);  // put HA back on the actual value
    return;
  }
  float g = (gain_ == 0.0f) ? 1.0f : gain_;
  long raw = lroundf(value / g);
  std::vector<uint8_t> data;
  switch (type_) {
    case VT_U8: case VT_I8: case VT_ENUM:
      data.push_back((uint8_t)(raw & 0xFF));
      break;
    case VT_BOOL:  // write the appliance's own encoding: 0 = no, 0xFF = yes
      data.push_back(raw != 0 ? 0xFF : 0x00);
      break;
    case VT_U16: case VT_I16:
      data.push_back((uint8_t)(raw & 0xFF));
      data.push_back((uint8_t)((raw >> 8) & 0xFF));
      break;
    case VT_U32: case VT_I32:
      data.push_back((uint8_t)(raw & 0xFF));
      data.push_back((uint8_t)((raw >> 8) & 0xFF));
      data.push_back((uint8_t)((raw >> 16) & 0xFF));
      data.push_back((uint8_t)((raw >> 24) & 0xFF));
      break;
  }
  ESP_LOGI(TAG, "number set %.3f -> raw %ld -> write 0x%04X:%u", value, raw, index_, sub_);
  parent_->enqueue_write(node_, index_, sub_, data);
  this->publish_state(value);  // optimistic; the next poll confirms the read-back
}

void RemehaSelect::control(const std::string &value) {
  if (parent_ == nullptr || map_ == nullptr) {
    ESP_LOGW(TAG, "select 0x%04X:%u has no parent hub", index_, sub_);
    return;
  }
  for (auto &p : *map_) {
    if (value == p.second) {
      if (range_known_ && (p.first < dev_lo_ || p.first > dev_hi_)) {
        ESP_LOGW(TAG, "select 0x%04X:%u: '%s' (%ld) staat het toestel niet toe (%ld..%ld), niet geschreven",
                 index_, sub_, value.c_str(), (long) p.first, (long) dev_lo_, (long) dev_hi_);
        // nothing published: HA keeps showing the actual (read-back) choice
        return;
      }
      std::vector<uint8_t> data{(uint8_t) (p.first & 0xFF)};
      ESP_LOGI(TAG, "select '%s' -> write 0x%04X:%u = %ld", value.c_str(), index_, sub_, (long) p.first);
      parent_->enqueue_write(node_, index_, sub_, data);
      this->publish_state(value);  // optimistic; the next poll confirms the read-back
      return;
    }
  }
  ESP_LOGW(TAG, "select 0x%04X:%u: onbekende keuze '%s'", index_, sub_, value.c_str());
}

void RemehaSwitch::write_state(bool state) {
  if (parent_ == nullptr) {
    ESP_LOGW(TAG, "switch 0x%04X:%u has no parent hub", index_, sub_);
    return;
  }
  std::vector<uint8_t> data{(uint8_t)(state ? true_value_ : 0)};
  ESP_LOGI(TAG, "switch %s -> write 0x%04X:%u = 0x%02X", state ? "aan" : "uit", index_, sub_, data[0]);
  parent_->enqueue_write(node_, index_, sub_, data);
  this->publish_state(state);  // optimistic; the next poll confirms the read-back
}

}  // namespace remeha_ble
}  // namespace esphome
#endif
