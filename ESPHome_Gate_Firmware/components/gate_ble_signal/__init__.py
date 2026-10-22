"""On-demand RSSI for an authenticated BLE server session."""
import esphome.codegen as cg
import esphome.config_validation as cv
from esphome.components import esp32_ble, esp32_ble_server
from esphome.const import CONF_ID

DEPENDENCIES = ["esp32_ble_server"]
ns = cg.esphome_ns.namespace("gate_ble_signal")
GateBLESignal = ns.class_("GateBLESignal", cg.Component)
CONFIG_SCHEMA = cv.Schema({
    cv.GenerateID(): cv.declare_id(GateBLESignal),
    cv.Required("ble_id"): cv.use_id(esp32_ble.ESP32BLE),
    cv.Required("server_id"): cv.use_id(esp32_ble_server.BLEServer),
}).extend(cv.COMPONENT_SCHEMA)

async def to_code(config):
    var = cg.new_Pvariable(config[CONF_ID])
    await cg.register_component(var, config)
    ble = await cg.get_variable(config["ble_id"])
    server = await cg.get_variable(config["server_id"])
    cg.add(var.set_server(server))
    esp32_ble.register_gap_event_handler(ble, var)
    esp32_ble.register_gatts_event_handler(ble, var)
    esp32_ble.register_ble_status_event_handler(ble, var)
