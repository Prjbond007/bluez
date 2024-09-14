#!/usr/bin/python3

ADAPTER_NAME = "hci0"

BLUEZ_SERVICE_NAME = "org.bluez"
BLUEZ_NAMESPACE = "/org/bluez/"
DBUS_PROPERTIES="org.freedesktop.DBus.Properties"
DBUS_OM_IFACE = 'org.freedesktop.DBus.ObjectManager'

ADAPTER_INTERFACE = BLUEZ_SERVICE_NAME + ".Adapter1"
DEVICE_INTERFACE = BLUEZ_SERVICE_NAME + ".Device1"
GATT_MANAGER_INTERFACE = BLUEZ_SERVICE_NAME + ".GattManager1"
GATT_SERVICE_INTERFACE = BLUEZ_SERVICE_NAME + ".GattService1"
GATT_CHARACTERISTIC_INTERFACE = BLUEZ_SERVICE_NAME + ".GattCharacteristic1"
GATT_DESCRIPTOR_INTERFACE = BLUEZ_SERVICE_NAME + ".GattDescriptor1"
ADVERTISEMENT_INTERFACE = BLUEZ_SERVICE_NAME + ".LEAdvertisement1"
ADVERTISING_MANAGER_INTERFACE = BLUEZ_SERVICE_NAME + ".LEAdvertisingManager1"

RESULT_OK = 0
RESULT_ERR = 1
RESULT_ERR_NOT_CONNECTED = 2
RESULT_ERR_NOT_SUPPORTED = 3
RESULT_ERR_SERVICES_NOT_RESOLVED = 4	
RESULT_ERR_WRONG_STATE = 5
RESULT_ERR_ACCESS_DENIED = 6
RESULT_EXCEPTION = 7
RESULT_ERR_BAD_ARGS = 8
RESULT_ERR_NOT_FOUND = 9

UUID_NAMES = {
    "00001801-0000-1000-8000-00805f9b34fb" : "Generic Attribute Service",
    "0000180a-0000-1000-8000-00805f9b34fb" : "Device Information Service",
    "e95d93b0-251d-470a-a062-fa1922dfa9a8" : "DFU Control Service",
    "e95d93af-251d-470a-a062-fa1922dfa9a8" : "Event Service",
    "e95d9882-251d-470a-a062-fa1922dfa9a8" : "Button Service",
    "e95d6100-251d-470a-a062-fa1922dfa9a8" : "Temperature Service",
    "e95dd91d-251d-470a-a062-fa1922dfa9a8" : "LED Service",
    "00002a05-0000-1000-8000-00805f9b34fb" : "Service Changed",
    "e95d93b1-251d-470a-a062-fa1922dfa9a8" : "DFU Control",
    "00002a05-0000-1000-8000-00805f9b34fb" : "Service Changed",
    "00002a24-0000-1000-8000-00805f9b34fb" : "Model Number String",
    "00002a25-0000-1000-8000-00805f9b34fb" : "Serial Number String",
    "00002a26-0000-1000-8000-00805f9b34fb" : "Firmware Revision String",
    "e95d9775-251d-470a-a062-fa1922dfa9a8" : "micro:bit Event",
    "e95d5404-251d-470a-a062-fa1922dfa9a8" : "Client Event",
    "e95d23c4-251d-470a-a062-fa1922dfa9a8" : "Client Requirements",
    "e95db84c-251d-470a-a062-fa1922dfa9a8" : "micro:bit Requirements",
    "e95dda90-251d-470a-a062-fa1922dfa9a8" : "Button A State",
    "e95dda91-251d-470a-a062-fa1922dfa9a8" : "Button B State",
    "e95d9250-251d-470a-a062-fa1922dfa9a8" : "Temperature",
    "e95d93ee-251d-470a-a062-fa1922dfa9a8" : "LED Text",
    "00002902-0000-1000-8000-00805f9b34fb" : "Client Characteristic Configuration",
}    

UUID_NAME_MAP = {
    "00001800-0000-1000-8000-00805f9b34fb": "0x1800 GAP Service",
    "00001801-0000-1000-8000-00805f9b34fb": "0x1801 GATT Service",
    "0000180a-0000-1000-8000-00805f9b34fb": "0x180a Device Information Service",
    "0000180f-0000-1000-8000-00805f9b34fb": "0x180f Battery Service",
    "00001844-0000-1000-8000-00805f9b34fb": "0x1844 Volume Control Service",
    "00001846-0000-1000-8000-00805f9b34fb": "0x1846 Coordinated Set Identification Service",
    "0000184d-0000-1000-8000-00805f9b34fb": "0x184D Microphone Control Service",
    "0000184e-0000-1000-8000-00805f9b34fb": "0x184E Audio Stream Control Service",
    "0000184f-0000-1000-8000-00805f9b34fb": "0x184F Broadcast Audio Scan Service",
    "00001850-0000-1000-8000-00805f9b34fb": "0x1850 Published Audio Capabilities Service",
    "00001853-0000-1000-8000-00805f9b34fb": "0x1853 Common Audio Service",
    "00001854-0000-1000-8000-00805f9b34fb": "0x1854 Hearing Access Service",
    "0000fd20-0000-1000-8000-00805f9b34fb": "0xFD20 GN Hearing A/S",
    "00001852-0000-1000-8000-00805f9b34fb": "0x1852 Broadcast Audio Announcement Service",
    "0000fdf0-0000-1000-8000-00805f9b34fb": "0xFDF0 Google LLC",
    "0000fefe-0000-1000-8000-00805f9b34fb": "0xFEFE GN Hearing A/S",
    "7d74f4bd-c74a-4431-862c-cce884371592": "0xf4bd Vendor specific",
    "8341f2b4-c013-4f04-8197-c4cdb42e26dc": "0xf2b4 Vendor specific",
    "a53062b9-7dfd-446c-bca5-1e13269560bd": "0x62b9 Vendor specific",
    "c623e110-3ef8-4388-8481-8666e1ce9796": "0xe110 Vendor specific",
    "d49ab80d-b084-4377-b2c7-d07a333d8068": "0xb80d Vendor specific"
}

DEVICE_INF_SVC_UUID = "0000180a-0000-1000-8000-00805f9b34fb"
MODEL_NUMBER_UUID    = "00002a24-0000-1000-8000-00805f9b34fb"

TEMPERATURE_SVC_UUID = "e95d6100-251d-470a-a062-fa1922dfa9a8"
TEMPERATURE_CHR_UUID = "e95d9250-251d-470a-a062-fa1922dfa9a8"

LED_SVC_UUID = "e95dd91d-251d-470a-a062-fa1922dfa9a8"
LED_TEXT_CHR_UUID = "e95d93ee-251d-470a-a062-fa1922dfa9a8"

BASS_SVC_UUID = "0000184f-0000-1000-8000-00805f9b34fb"
BRS_CHR_UUID = "00002bc8-0000-1000-8000-00805f9b34fb"
BASCP_CHR_UUID = "00002bc7-0000-1000-8000-00805f9b34fb"
