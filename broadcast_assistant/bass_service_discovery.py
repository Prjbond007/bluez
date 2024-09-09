import bluetooth_constants
import bluetooth_utils
import dbus
import dbus.mainloop.glib
import sys
from gi.repository import GLib

sys.path.insert(0, '.')

bus = None
device_interface = None
device_path = None
bascp_char_path = None
brs_char_path = None
operation = None

# Initialize DBus and set the global bus object
def init_dbus():
    global bus
    dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
    bus = dbus.SystemBus()

def decode_broadcast_state(broadcast_state):
    decoded = {}
    decoded['Source_ID'] = broadcast_state[0]
    decoded['Source_Address_Type'] = broadcast_state[1]
    decoded['Source_Address_Type_Description'] = (
        "Public Device Address or Public Identity Address"
        if decoded['Source_Address_Type'] == 0x00 else
        "Random Device Address or Random (static) Identity Address"
        if decoded['Source_Address_Type'] == 0x01 else
        "RFU"
    )
    decoded['Source_Address'] = ':'.join(f'{x:02X}' for x in reversed(broadcast_state[2:8]))
    decoded['Source_Adv_SID'] = broadcast_state[8]
    decoded['Broadcast_ID'] = int.from_bytes(broadcast_state[9:12], byteorder='big')

    decoded['PA_Sync_State'] = broadcast_state[12]
    pa_sync_state_map = {
        0x00: "Not synchronized to PA",
        0x01: "SyncInfo Request",
        0x02: "Synchronized to PA",
        0x03: "Failed to synchronize to PA",
        0x04: "No PAST"
    }
    decoded['PA_Sync_State_Description'] = pa_sync_state_map.get(decoded['PA_Sync_State'], "RFU")

    decoded['BIG_Encryption'] = broadcast_state[13]
    big_encryption_map = {
        0x00: "Not encrypted",
        0x01: "Broadcast_Code required",
        0x02: "Decrypting",
        0x03: "Bad_Code (incorrect encryption key)"
    }
    decoded['BIG_Encryption_Description'] = big_encryption_map.get(decoded['BIG_Encryption'], "RFU")

    decoded['Num_Subgroups'] = broadcast_state[14]

    subgroups = []
    offset = 15
    for i in range(decoded['Num_Subgroups']):
        subgroup = {}
        bis_sync_state = int.from_bytes(broadcast_state[offset:offset+4], byteorder='big')
        subgroup['BIS_Sync_State'] = bis_sync_state
        subgroup['BIS_Sync_State_Description'] = (
            "Not synchronized to BIS_index[x]"
            if bis_sync_state == 0x00000000 else
            "Failed to sync to BIG"
            if bis_sync_state == 0xFFFFFFFF else
            f"Synchronized to BIS_index[{bis_sync_state}]"
        )
        offset += 4
        metadata_length = broadcast_state[offset]
        subgroup['Metadata_Length'] = metadata_length
        offset += 1
        if metadata_length > 0:
            subgroup['Metadata'] = broadcast_state[offset:offset + metadata_length]
            offset += metadata_length
        subgroups.append(subgroup)
    decoded['Subgroups'] = subgroups
    return decoded

def broadcast_state_received(interface, changed, invalidated, path):
    if 'Value' in changed:
        broadcast_state = bluetooth_utils.dbus_to_python(changed['Value'])
        decoded_state = decode_broadcast_state(broadcast_state)

        # Printing the raw data as hex
        data_hex = ''.join(f'{x:02x}' for x in broadcast_state)
        print(f"Data[{len(broadcast_state)}]: {data_hex.upper()}")

        # Printing the decoded broadcast state
        print(f"Source_ID: {decoded_state['Source_ID']}")
        print(f"Source_Address_Type: {decoded_state['Source_Address_Type']}")
        print(f"Source_Address: {decoded_state['Source_Address']}")
        print(f"Source_Adv_SID: {decoded_state['Source_Adv_SID']}")
        print(f"Broadcast_ID: 0x{decoded_state['Broadcast_ID']:06X}")
        print(f"PA_Sync_State: {decoded_state['PA_Sync_State_Description']}")
        print(f"BIG_Encryption: {decoded_state['BIG_Encryption_Description']}")
        print(f"Num_Subgroups: {decoded_state['Num_Subgroups']}")

        # Looping through each subgroup and printing its details
        for i, subgroup in enumerate(decoded_state['Subgroups']):
            print(f"  Subgroup #{i}:")
            print(f"    BIS_Sync State: 0x{subgroup['BIS_Sync_State']:08X} ({subgroup['BIS_Sync_State_Description']})")
            if 'Metadata' in subgroup and subgroup['Metadata_Length'] > 0:
                metadata_hex = ' '.join(f'{x:02X}' for x in subgroup['Metadata'])
                print(f"    Metadata: #{i}: len 0x{subgroup['Metadata_Length']:02X} type 0x{subgroup['Metadata'][0]:02X}")
                print(f"    Metadata:   {metadata_hex}")
                
def start_broadcast_state_notifications():
    global brs_char_path
    char_proxy = bus.get_object(bluetooth_constants.BLUEZ_SERVICE_NAME, brs_char_path)
    char_interface = dbus.Interface(char_proxy, bluetooth_constants.GATT_CHARACTERISTIC_INTERFACE)
    
    bus.add_signal_receiver(
        broadcast_state_received,
        dbus_interface=bluetooth_constants.DBUS_PROPERTIES,
        signal_name="PropertiesChanged",
        path=brs_char_path,
        path_keyword="path"
    )
    try:
        char_interface.StartNotify()
        print("Started notifications for Broadcast Receive State")
    except Exception as e:
        print("Failed to start Broadcast Receive State notifications")
        print(e.get_dbus_name())
        print(e.get_dbus_message())
        return bluetooth_constants.RESULT_EXCEPTION

def stop_broadcast_state_notifications():
    global brs_char_path
    char_proxy = bus.get_object(bluetooth_constants.BLUEZ_SERVICE_NAME, brs_char_path)
    char_interface = dbus.Interface(char_proxy, bluetooth_constants.GATT_CHARACTERISTIC_INTERFACE)
    
    try:
        char_interface.StopNotify()
        print("Stopped notifications for Broadcast Receive State")
    except Exception as e:
        print("Failed to stop Broadcast Receive State notifications")
        print(e.get_dbus_name())
        print(e.get_dbus_message())
        return bluetooth_constants.RESULT_EXCEPTION

def write_broadcast_control_point(operation):
    global bascp_char_path
    char_proxy = bus.get_object(bluetooth_constants.BLUEZ_SERVICE_NAME, bascp_char_path)
    bascp_char_interface = dbus.Interface(char_proxy, bluetooth_constants.GATT_CHARACTERISTIC_INTERFACE)

    operations = {
        "start_stream": [0x02, 0x01, 0x3c, 0x18, 0x9f, 0xe8, 0x07, 0xc0, 0x01, 0x00, 0x00, 0x00, 0x02, 0xff, 0xff, 0x01, 0xff, 0xff, 0xff, 0xff, 0x00],
        "stop_stream": [0x03, 0x01, 0x00, 0xff, 0xff, 0x01, 0xff, 0xff, 0xff, 0xff, 0x00],
        "remove_source": [0x05, 0x01]
    }
    operation_bytes = operations.get(operation)

    if operation_bytes is not None:
        start_broadcast_state_notifications()
        try:
            print(f"Writing to Broadcast Control Point with operation: {operation}")
            bascp_char_interface.WriteValue(operation_bytes, {})
            GLib.timeout_add_seconds(5, stop_broadcast_state_notifications)
            print(f"Broadcast Control point written OK with operation: {operation}")
            return bluetooth_constants.RESULT_OK
        except Exception as e:
            print("Failed to write to Broadcast Control Point")
            print(e.get_dbus_name())
            print(e.get_dbus_message())
            return bluetooth_constants.RESULT_EXCEPTION

def discover_characteristics():
    global brs_char_path, bascp_char_path
    object_manager = dbus.Interface(bus.get_object(bluetooth_constants.BLUEZ_SERVICE_NAME, "/"), bluetooth_constants.DBUS_OM_IFACE)
    managed_objects = object_manager.GetManagedObjects()

    for path, ifaces in managed_objects.items():
        for iface_name in ifaces:
            if iface_name == bluetooth_constants.GATT_CHARACTERISTIC_INTERFACE:
                char_properties = ifaces[bluetooth_constants.GATT_CHARACTERISTIC_INTERFACE]
                char_uuid = char_properties["UUID"]
                if char_uuid == bluetooth_constants.BRS_CHR_UUID:
                    print(f"Broadcast Receive State Char Found: Path - {path}")
                    brs_char_path = path
                if char_uuid == bluetooth_constants.BASCP_CHR_UUID:
                    print(f"Broadcast Control Point Char Found: Path - {path}")
                    bascp_char_path = path

def service_discovery_completed():
    global brs_char_path, bascp_char_path

    # Reset characteristic paths
    brs_char_path, bascp_char_path = None, None
    discover_characteristics()

    if bascp_char_path and brs_char_path:
        print("Required services and characteristics found.")
    else:
        print("Required services and characteristics not found.")
