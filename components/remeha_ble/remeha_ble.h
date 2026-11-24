// ============================================================================
//  Remeha BLE -> ESPHome component  (declarations)
// ----------------------------------------------------------------------------
//  RemehaBle is both a PollingComponent (update() every 30 s) and a
//  BLEClientNode (receives GATT events). It owns a list of RemehaItem, each
//  the binding between one appliance object (node/index/subindex) and one HA
//  entity (sensor / text_sensor / number / binary_sensor / switch). The full protocol is documented at
//  the top of remeha_ble.cpp; this header just declares the moving parts.
// ============================================================================
#pragma once
#ifdef USE_ESP32
#include <vector>
#include <set>
#include <string>
#include <array>
#include <atomic>
#include <mutex>
#include "esphome/core/defines.h"
#include "esphome/core/component.h"
#include "esphome/core/preferences.h"
#include "esphome/components/ble_client/ble_client.h"
#include "esphome/components/esp32_ble_tracker/esp32_ble_tracker.h"
#include "esphome/components/sensor/sensor.h"
#include "esphome/components/text_sensor/text_sensor.h"
#include "esphome/components/number/number.h"
#include "esphome/components/binary_sensor/binary_sensor.h"
#include "esphome/components/switch/switch.h"
#include "esphome/components/select/select.h"
#include <utility>
#include <esp_gattc_api.h>
#include <esp_gap_ble_api.h>

namespace esphome {
namespace remeha_ble {

namespace espbt = esphome::esp32_ble_tracker;

// How a value's raw bytes are interpreted. VT_ENUM is an 8-bit enumeration
// (status/on-off/option); the rest are little-endian integers of that width.
// VT_BOOL is an 8-bit flag stored as 0 / 0xFF (published as 0 / 1).
enum ValueType { VT_U8, VT_I8, VT_U16, VT_I16, VT_U32, VT_I32, VT_ENUM, VT_BOOL };

// Enum choices: raw value -> text (from the codebook or the YAML `options:`).
using EnumMap = std::vector<std::pair<int32_t, const char *>>;

// One appliance object <-> one HA entity. Exactly one of sensor/text_sensor is
// set for a read-only value; a writable parameter sets `number` (and is polled
// so the number shows the real read-back). The raw value is decoded as `type`
// and multiplied by `gain` (e.g. 0.01 for centidegrees).
struct RemehaItem {
  uint8_t node;                      // CAN node: 1 = EHC-16 heat-pump controller (default)
  uint16_t index;                    // CANopen object index (e.g. 0x4301 = flow temp)
  uint8_t sub;                       // subindex: 0 for scalars, >=1 for array objects (see .cpp)
  ValueType type;                    // how to decode the raw bytes
  float gain;                        // scale factor applied to the raw integer
  sensor::Sensor *sensor{nullptr};        // numeric read-only value
  text_sensor::TextSensor *text_sensor{nullptr};  // string value (e.g. device name)
  number::Number *number{nullptr};   // writable param: read-back is published here too
  binary_sensor::BinarySensor *binary_sensor{nullptr};  // on/off read-only value
  switch_::Switch *switch_{nullptr}; // writable on/off param: read-back is published here too
  select::Select *select_{nullptr};  // writable enum param: read-back published as its text
  const EnumMap *enum_map{nullptr};  // text_sensor/select: raw value -> text
  bool has_true_value{false};        // binary_sensor/switch: true = on only when raw == true_value
  uint8_t true_value{1};             //   (false = any non-zero raw value is on)
  bool single{false};                // true = read via individual request (op 0x00), not bulk GetList
  bool auto_read{false};             // read: auto - start in bulk, switch to single if not returned there
  // runtime state (not set from YAML)
  uint8_t miss{0};                   // auto: consecutive GetList replies without this object
  bool seen{false};                  // auto: value received in the current GetList reply
  uint8_t batch{0};                  // which GetList of the cycle asks for it (at most 100 objects each)
  bool missing{false};               // appliance says the object does not exist: no longer polled
};

// connection state machine
enum St { ST_INIT = 0, ST_GATE_WAIT_CHAL, ST_GATE_WAIT_ACK,
          ST_CANIP_WAIT_CHAL, ST_CANIP_WAIT_ACK, ST_CANIP_WAIT_RX6, ST_AUTH0_WAIT_CHAL, ST_AUTH0_WAIT_ACK,
          ST_RUN };

class RemehaBle : public PollingComponent,
                      public ble_client::BLEClientNode,
                      public esp32_ble_tracker::ESPBTDeviceListener {
 public:
  void setup() override;
  void update() override;
  void loop() override;  // only picks up a scan request from the configurator page
  void dump_config() override;
  float get_setup_priority() const override { return setup_priority::AFTER_BLUETOOTH; }

  void set_service_uuid(const std::string &u) { service_uuid_ = espbt::ESPBTUUID::from_raw(u); }
  void set_write_uuid(const std::string &u)   { write_uuid_   = espbt::ESPBTUUID::from_raw(u); }
  void set_notify_uuid(const std::string &u)  { notify_uuid_  = espbt::ESPBTUUID::from_raw(u); }
  void set_passkey(uint32_t pk) { passkey_ = pk; has_passkey_ = true; }
  // Whether the BLE link must be paired/encrypted (LESC passkey). true for the
  // Confida/GTW-22 onboard module; false for the GTW-IoT hub, which accepts a
  // plain connection and runs the gate handshake without any pairing.
  void set_requires_pairing(bool v) { conn_mode_ = v ? 1 : 2; }
  // 0 = auto (route from the advertised name: "EHC-" paired, "GTW-IOT" plain),
  // 1 = always paired (built-in Bluetooth), 2 = always plain (GTW-IoT hub).
  void set_connection_mode(uint8_t m) { conn_mode_ = m; }
  // Auto-connect by name: if the ble_client MAC is left as 00:00:00:00:00:00,
  // the hub scans and connects to the first device whose advertised name starts
  // with this prefix (default: "EHC-" or "GTW-IOT"). With a real MAC filled in,
  // scanning is skipped and that MAC is used directly.
  void set_name_prefix(const std::string &p) { name_prefix_ = p; }
  void add_item(const RemehaItem &it) { items_.push_back(it); }
  // Optional diagnostic entities (hub-level): last reconnect reason + reconnect count.
  void set_reason_sensor(text_sensor::TextSensor *t) { reason_ts_ = t; }
  void set_reconnect_sensor(sensor::Sensor *s) { reconnect_sensor_ = s; }
  // Optional: result of the last parameter write (accepted / refused + reason).
  void set_write_result_sensor(text_sensor::TextSensor *t) { write_result_ts_ = t; }
  // Appliance identification (article number 0x2000:09 + name 0x3047 on node 1).
  void set_appliance_sensor(text_sensor::TextSensor *t) { appliance_ts_ = t; }
  void add_expected_article(uint32_t a) { expected_articles_.push_back(a); }
  // Configurator page on the ESP (optional, `configurator: true`): the web handler
  // runs in the HTTP server task, so it only sets a flag and reads the JSON under
  // a mutex; the scan itself runs in the main loop like every other BLE request.
  // The result is streamed: every menu block becomes a small JSON chunk that the
  // page fetches and acknowledges (?from=N), after which the ESP frees it. The
  // scan pauses while the page has not picked up its chunks, so only a few kB are
  // ever held in RAM (holding the whole result at once crashed small ESP32s).
  void request_scan();  // called from the HTTP task
  std::string scan_poll(int gen, uint16_t from);
  std::string current_json() const;  // HTTP task: what this firmware reads/writes now
  // Configurator "read" button: read one object once and return its raw bytes.
  // probe_request() queues it (HTTP task), probe_poll() returns the result.
  std::string probe_request(uint8_t node, uint16_t index, uint8_t sub);
  std::string probe_poll();  // HTTP task: status + chunks >= from (frees older ones of that gen)
  // Enable/disable reading. false = release the BLE link and STOP reconnecting, so
  // a phone or service tool can connect; true = resume. Driven by a switch.
  void set_active(bool a);
  // Discovery dump (verkenning): read a fixed set of identification/discovery
  // objects once (read-only) and log their raw bytes as "DUMP" lines. Trigger it
  // from YAML, e.g. a template button: on_press: lambda: id(remeha).start_discovery_dump();
  void start_discovery_dump();

  // Queue a parameter WRITE (operation 0x04). data = value bytes, LITTLE-endian.
  // Sent as soon as the bus is idle; the appliance replies with a write-response.
  void enqueue_write(uint8_t node, uint16_t index, uint8_t sub, const std::vector<uint8_t> &data);

  void gattc_event_handler(esp_gattc_cb_event_t event, esp_gatt_if_t gattc_if,
                           esp_ble_gattc_cb_param_t *param) override;
  void gap_event_handler(esp_gap_ble_cb_event_t event, esp_ble_gap_cb_param_t *param);

  // esp32_ble_tracker listener: sees every advertisement during scanning. Used
  // only in auto-connect mode (MAC left at 0) to discover the appliance by name
  // and to log an overview of all BLE devices seen, so a user with several
  // appliances can read the right MAC from the log and pin it in the YAML.
  bool parse_device(const esp32_ble_tracker::ESPBTDevice &device) override;

 protected:
  // CANIP service (0x0e write, 0x10 notify) — configurable
  espbt::ESPBTUUID service_uuid_, write_uuid_, notify_uuid_;
  // gate service + its 4 characteristics (fixed UUIDs for the Confida BLE module)
  espbt::ESPBTUUID gate_svc_, gate_1b_, gate_1d_, gate_20_, gate_22_;
  // second CANIP notify characteristic that is also subscribed to (fixed UUID)
  espbt::ESPBTUUID canip_extra_;

  uint32_t passkey_{0};
  bool has_passkey_{false};
  bool requires_pairing_{true};  // false = GTW-IoT hub (no pairing/encryption)

  // resolved value handles
  uint16_t h_canip_w_{0}, h_canip_n_{0};
  uint16_t h_1b_{0}, h_1d_{0}, h_20_{0}, h_22_{0};
  uint16_t h_13_{0};  // extra CANIP notify char that is also subscribed to
  uint8_t reg_done_{0}, descr_done_{0}, notify_expected_{0};
  bool dumped_{false};
  uint16_t cccd_1d_{0}, cccd_22_{0}, cccd_canip_{0}, cccd_13_{0};
  St st_{ST_INIT};
  uint8_t auth_level_{4};

  std::vector<RemehaItem> items_;
  std::vector<std::vector<uint8_t>> tx_queue_;  // pending WRITE frames (sent before polling)
  std::vector<std::vector<uint8_t>> indiv_q_;   // pending individual-READ frames (op 0x00) for single-read items
  // discovery dump (see start_discovery_dump): pending read frames, the keys we
  // asked for (node<<24 | index<<8 | sub), and array objects whose sub 0 (entry
  // count) decides how many subs to read next (key node<<16 | index -> max subs).
  std::vector<std::vector<uint8_t>> dump_q_;
  bool chain_next_{false};
  // menu descriptor (0x502B): read once per boot after the handshake, to learn
  // the appliance's own min/max/step for numbers and allowed range for selects
  std::vector<std::vector<uint8_t>> menu_q_;
  std::vector<uint8_t> menu_nodes_;
  uint8_t menu_left_{0};
  bool menu_done_{false};
  void start_menu_read_();
  struct MenuRec {
    uint16_t index{0};
    uint8_t sub{0}, step{0}, level{0};
    int32_t raw_min{0}, raw_max{0};
    int32_t min{0};
    double max{0};
  };
  static bool menu_record_(const uint8_t *r, MenuRec &out);
  static size_t menu_stride_(const uint8_t *d, size_t len);
  // configurator scan state (see request_scan)
  std::atomic<bool> scan_req_{false};
  bool scan_pending_{false};
  bool scan_restart_{false};  // new request while reading: restart when the read in flight is answered
  bool scan_inflight_{false};
  uint32_t scan_expect_{0};    // node<<24 | index<<8 | sub of the read in flight
  uint32_t scan_issue_ms_{0};
  uint8_t scan_state_{0};  // 0 idle, 1 waiting for the connection, 2 scanning, 3 done, 4 error
  uint16_t scan_left_{0}, scan_total_{0}, scan_seq_{0};
  enum : uint8_t { SCAN_ARTICLE, SCAN_NAME, SCAN_MENU, SCAN_FIND, SCAN_FMT, SCAN_SELECT };
  struct ScanStep { uint8_t node; uint16_t index; uint8_t sub; uint8_t tries; uint8_t kind; };
  uint8_t scan_fmt_{2};               // menu format from 0x502C, written to 0x502D before the blocks
  uint8_t scan_fails_{0};             // menu blocks in a row that failed (skip the board at 3)
  std::vector<ScanStep> scan_steps_;  // reads of this scan, in order (grows after the board search)
  size_t scan_pos_{0};                // next step to issue
  uint32_t scan_retry_at_{0};         // millis() of the next retry, 0 = none
  std::vector<std::pair<uint8_t, std::string>> scan_nodes_;  // boards found: node, name
  std::atomic<uint16_t> scan_gen_{0};  // bumped on every (re)start, so the page knows to start over
  uint32_t scan_article_{0};
  std::string scan_name_;
  std::atomic<uint32_t> scan_poll_ms_{0};  // last poll by the page (pause timeout)
  // guarded by scan_mtx_ (shared with the HTTP task)
  std::string scan_head_{"{\"state\":\"idle\""};
  std::vector<std::pair<uint16_t, std::string>> scan_chunks_;
  std::mutex scan_mtx_;
  // one-off read for the configurator (see probe_request); params/json under scan_mtx_
  std::atomic<bool> probe_req_{false};
  uint8_t probe_node_{0}, probe_sub_{0};
  uint16_t probe_index_{0}, probe_id_{0};
  bool probe_inflight_{false};
  uint32_t probe_expect_{0}, probe_ms_{0};
  std::string probe_json_{"{\"state\":\"idle\",\"id\":0}"};
  void probe_done_(bool ok, const uint8_t *d, size_t len, const char *err);
  void start_scan_();
  void scan_reset_();
  void scan_issue_next_();
  void scan_abort_(const char *why);
  void update_scan_json_();
  void handle_scan_response_(uint8_t node, uint16_t index, uint8_t sub, const uint8_t *d, size_t len, bool ok);
  void start_poll_cycle_();
  void parse_menu_block_(uint8_t node, const uint8_t *d, size_t len);  // a response arrived while TX was busy: send the next queued read on TX done
  std::vector<uint32_t> dump_keys_;
  std::vector<std::pair<uint32_t, uint8_t>> dump_arrays_;
  uint16_t dump_left_{0};
  void dump_queue_read_(uint8_t node, uint16_t index, uint8_t sub);
  bool dump_handle_(const std::vector<uint8_t> &m, uint8_t op);  // log a DUMP line if this answers a dump read
  std::vector<uint8_t> tx_msg_;   // GetList request / write frame being fragmented
  size_t tx_off_{0};
  uint8_t tx_seq_{0};
  bool tx_busy_{false};
  uint32_t tx_start_{0};          // millis() when the current TX frame began (stuck-TX watchdog)
  std::vector<uint8_t> rx_msg_;   // CANIP notify reassembly
  uint8_t rx_next_{0};            // next expected fragment number
  bool rx_bad_{false};            // a fragment of this message went missing
  uint32_t rx_dropped_{0};
  uint32_t responses_{0};
  uint32_t last_rx_{0};           // millis() of last reassembled response (RUN liveness watchdog)
  uint32_t reconnects_{0};        // total forced reconnects since boot (diagnostic)
  bool connected_once_{false};    // so "verbonden" is published on the first RUN entry
  bool active_{true};             // false = released (link dropped, reconnect suppressed)
  // --- auto-connect by name (only when the configured MAC is 0) ---
  std::string name_prefix_;          // advertised-name prefix; empty = "EHC-" or "GTW-IOT"
  uint8_t conn_mode_{0};             // see set_connection_mode()
  bool route_logged_{false};
  uint8_t match_name_(const std::string &name) const;  // 0 no match, 1 built-in (paired), 2 GTW-IoT (plain)
  bool scan_mode_{false};            // true = MAC was 0, discover by name
  bool addr_resolved_{false};        // a matching device was found + address set
  std::set<uint64_t> seen_;          // MACs already logged (log each once)
  // --- pairing guard (see "PAIRING RULES" in the .cpp) ---
  bool pairing_{false};           // encryption/pairing requested, no AUTH_CMPL yet
  bool auth_handled_{false};      // AUTH_CMPL reaches us twice; act only once per connection
  bool gate_pending_{false};      // notifications ready, gate waits for pairing to finish
  uint32_t pair_start_{0};        // millis() when pairing was requested (never cut it off early)
  uint8_t pair_fails_{0};         // consecutive failed pairings (drives the wait length)
  bool backoff_{false};           // waiting after a failed pairing; ble_client disabled
  uint32_t backoff_until_{0};     // millis() when the next attempt is allowed
  uint32_t last_fail_{0};         // millis() of the last failed pairing
  bool ever_failed_{false};       // last_fail_ is valid
  text_sensor::TextSensor *reason_ts_{nullptr};   // optional: last reconnect reason
  sensor::Sensor *reconnect_sensor_{nullptr};     // optional: reconnect count
  text_sensor::TextSensor *write_result_ts_{nullptr};  // optional: last write result
  text_sensor::TextSensor *appliance_ts_{nullptr};     // optional: "Confida 40 (7887477)"
  std::vector<uint32_t> expected_articles_;
  uint32_t article_{0};
  std::string appliance_name_;
  uint8_t id_left_{0};
  bool id_done_{false};
  void handle_identification_(uint16_t index, const uint8_t *d, size_t len, bool ok);

  static uint16_t crc_modbus_(const uint8_t *d, size_t n);
  static void tea_(uint8_t level, uint32_t serial, uint32_t chal, uint32_t &o1, uint32_t &o2);
  void write_raw_(uint16_t handle, const uint8_t *d, size_t n);
  bool resolve_handles_();
  void dump_gatt_();
  void start_notify_();
  void gate_trigger_();
  void canip_start_();
  void canip_handshake_(const std::vector<uint8_t> &m);
  void send_canip_body_(const uint8_t *body, size_t len);
  void enter_run_();
  uint32_t auth0_ms_{0};
  std::vector<std::vector<uint8_t>> build_requests_();  // bulk GetLists of at most GETLIST_MAX objects
  std::vector<uint8_t> build_read_frame_(uint8_t node, uint16_t index, uint8_t sub);  // individual read (op 0x00)
  std::vector<uint8_t> build_write_frame_(uint8_t node, uint16_t index, uint8_t sub, const std::vector<uint8_t> &data);
  void push_menu_steps_(uint8_t node);  // scan: select the menu format, then 0x502B:1..15
  void queue_individual_reads_();         // (re)fill indiv_q_ with one read frame per single-read item
  bool send_next_individual_();           // pop+send one queued individual read; false if none
  void start_tx_(std::vector<uint8_t> frame);
  void force_reconnect_(const char *why);  // close link + reset state so ble_client reconnects
  void pairing_failed_(const uint8_t *bda, uint8_t reason);  // drop link, maybe clear stale bond, wait
  void publish_reason_(const char *why);
  void send_next_fragment_();
  void parse_response_(const std::vector<uint8_t> &m);
  void decode_and_publish_(RemehaItem &it, uint8_t flag, const uint8_t *data, uint8_t len);  // shared decode for bulk + individual
};

// Writable parameter exposed as a Home Assistant number. On change it builds a
// write frame (operation 0x04) and hands it to the hub's write queue.
class RemehaNumber : public number::Number, public Component {
 public:
  void set_parent(RemehaBle *p) { parent_ = p; }
  void set_node(uint8_t v) { node_ = v; }
  void set_index(uint16_t v) { index_ = v; }
  void set_sub(uint8_t v) { sub_ = v; }
  void set_value_type(ValueType v) { type_ = v; }
  void set_gain(float v) { gain_ = v; }
  void set_use_device_limits(bool v) { use_device_limits_ = v; }
  void setup() override;  // restores the device limits learned in an earlier session
  float get_setup_priority() const override { return setup_priority::DATA; }
  // Limits from the appliance's menu descriptor (0x502B), already scaled by gain.
  // Applied to the number traits and stored in flash, so HA gets them at the next
  // (API) connect even before the BLE link is up.
  void apply_device_limits(float min, float max, float step);
  bool matches(uint8_t node, uint16_t index, uint8_t sub) const {
    return node == node_ && index == index_ && sub == sub_;
  }

 protected:
  void control(float value) override;
  struct LimitsPref { float min; float max; float step; uint32_t magic; };
  uint32_t pref_hash_() const;
  RemehaBle *parent_{nullptr};
  uint8_t node_{1};
  uint16_t index_{0};
  uint8_t sub_{0};
  ValueType type_{VT_U16};
  float gain_{1.0f};
  bool use_device_limits_{true};
  bool limits_known_{false};
  float dev_min_{0}, dev_max_{0};
  ESPPreferenceObject pref_;
};

// Writable enum parameter exposed as a Home Assistant select. The chosen text is
// mapped back to its raw choice number and written (operation 0x04, 1 byte).
class RemehaSelect : public select::Select, public Component {
 public:
  void set_parent(RemehaBle *p) { parent_ = p; }
  void set_node(uint8_t v) { node_ = v; }
  void set_index(uint16_t v) { index_ = v; }
  void set_sub(uint8_t v) { sub_ = v; }
  void set_enum_map(const EnumMap *m) { map_ = m; }
  // Allowed raw range from the appliance's menu descriptor (0x502B): choices
  // outside it are refused instead of written.
  void set_device_range(int32_t lo, int32_t hi);

 protected:
  void control(const std::string &value) override;
  RemehaBle *parent_{nullptr};
  uint8_t node_{1};
  uint16_t index_{0};
  uint8_t sub_{0};
  const EnumMap *map_{nullptr};
  bool range_known_{false};
  int32_t dev_lo_{0}, dev_hi_{0};
};

// Writable on/off parameter (e.g. a YesNo/OffOn enum) exposed as a Home Assistant
// switch. On = write true_value (default 1), off = write 0. Like RemehaNumber it is
// also polled, so the switch shows the appliance's real read-back state.
class RemehaSwitch : public switch_::Switch, public Component {
 public:
  void set_parent(RemehaBle *p) { parent_ = p; }
  void set_node(uint8_t v) { node_ = v; }
  void set_index(uint16_t v) { index_ = v; }
  void set_sub(uint8_t v) { sub_ = v; }
  void set_true_value(uint8_t v) { true_value_ = v; }

 protected:
  void write_state(bool state) override;
  RemehaBle *parent_{nullptr};
  uint8_t node_{1};
  uint16_t index_{0};
  uint8_t sub_{0};
  uint8_t true_value_{1};
};

}  // namespace remeha_ble
}  // namespace esphome
#endif
