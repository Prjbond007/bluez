import bluetooth_constants
import bluetooth_utils
import dbus
import dbus.mainloop.glib
import sys
from gi.repository import GLib
import time
sys.path.insert(0, '.')

bus = None
device_interface = None
device_path = None
global broadcast_state 
global decoded_state
global bass_svc_path 
global brs_char_path 
global bascp_char_path 

# Initialize DBus and set the global bus object
def init_dbus():
    global bus
    dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
    bus = dbus.SystemBus()

def decode_metadata(metadata_bytes):
    """ Decode metadata bytes according to the specification. """
    metadata = []
    i = 0
    while i < len(metadata_bytes):
        length = metadata_bytes[i]
        type_code = metadata_bytes[i + 1]
        value = int.from_bytes(metadata_bytes[i + 2:i + 2 + length - 1], byteorder='little')
        
        description = "Unknown"
        if type_code == 0x01:  # Preferred_Audio_Contexts
            description = {
                0x0004: "Media",
                0x0044: "Media and Live"
            }.get(value, "Unknown")
        elif type_code == 0x02:  # Streaming_Audio_Contexts
            description = {
                0x0004: "Media",
                0x0044: "Media and Live"
            }.get(value, "Unknown")
        elif type_code == 0x09:  # Broadcast Audio Immediate Rendering Flag
            description = "Broadcast Audio Immediate Rendering Flag" if value == 0 else "Unknown"
        metadata.append({'Length': length, 'Type': type_code, 'Value': value, 'Description': description})
        i += length + 1
    return metadata

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
        0x01: "Broadcast Code required",
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
            "Pause - Not synchronized to BIS"
            if bis_sync_state == 0x00000000 else
            "Failed to sync to BIG"
            if bis_sync_state == 0xFFFFFFFF else
            f"Play - Synchronized to BIS]"
        )
        offset += 4
        metadata_length = broadcast_state[offset]
        subgroup['Metadata_Length'] = metadata_length
        offset += 1

        if metadata_length > 0:
            metadata_bytes = broadcast_state[offset:offset + metadata_length]
            subgroup['Metadata'] = decode_metadata(metadata_bytes)
            offset += metadata_length

        subgroups.append(subgroup)
    decoded['Subgroups'] = subgroups
    return decoded

def stop_broadcast_state_notifications():
    global brs_char_path, bus
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
    
def broadcast_state_received(interface, changed, invalidated, path):
    global broadcast_state, decoded_state, last_state_time, last_state
    new_state = []
    if 'Value' in changed:
        broadcast_state = bluetooth_utils.dbus_to_python(changed['Value'])
        decoded_state = decode_broadcast_state(broadcast_state)
        print("decoded_state: ", decoded_state)
        if new_state != broadcast_state:
            new_state = broadcast_state
            last_state_time = time.time()  # Update the last received time
            last_state = broadcast_state  # Update the last state
            

def monitor_state_change(interval=2):  # 2 seconds interval to check state change
    global last_state_time, monitor_timer
    current_time = time.time()
    if (current_time - last_state_time) > interval:
        stop_broadcast_state_notifications()
        return False  # Stop the timer
    return True  # Continue monitoring
    
def start_broadcast_state_notifications():
    global brs_char_path, last_state_time, monitor_timer
    last_state_time = time.time()  # Reset the last update time

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
        monitor_timer = GLib.timeout_add_seconds(1, monitor_state_change)  # Check every second
    except Exception as e:
        print("Failed to start Broadcast Receive State notifications")
        print(e.get_dbus_name())
        print(e.get_dbus_message())
        return bluetooth_constants.RESULT_EXCEPTION
    
def write_broadcast_control_point(operation, address=None, address_type_str=None, broadcast_code=None):
    global bascp_char_path, decoded_state
    char_proxy = bus.get_object(bluetooth_constants.BLUEZ_SERVICE_NAME, bascp_char_path)
    bascp_char_interface = dbus.Interface(char_proxy, bluetooth_constants.GATT_CHARACTERISTIC_INTERFACE)

    if operation == "set_code":
        if broadcast_code is None:
            print("Broadcast code is required for set_code operation")
            return bluetooth_constants.RESULT_EXCEPTION
        
        # Convert the entered code string (hex) to byte array
        broadcast_code_bytes = [int(broadcast_code[i:i + 2], 16) for i in range(0, len(broadcast_code), 2)]
        
        # Opcode: 0x04 (Set Broadcast Code), Source ID: 0x01
        operation_bytes = [0x04, 0x01] + broadcast_code_bytes

    else:
        # Convert address to the inverted byte form needed for the operation (only if operation isn't set_code)
        inverted_address = [int(octet, 16) for octet in address.split(':')][::-1] if address else []
        # Convert address type to octet (0x00 = public, 0x01 = random)
        address_type = 0x00 if address_type_str == "public" else 0x01 if address_type_str else None

        operations = {
            "add_stream": [0x02, address_type, *inverted_address, 0x01, 0x00, 0x00, 0x00, 0x02, 0xff, 0xff, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00],  # Add Source & stops Stream with bis sync=0b0 PA Sync=0x02 
            "start_stream": [0x02, address_type, *inverted_address, 0x01, 0x00, 0x00, 0x00, 0x02, 0xff, 0xff, 0x01, 0xff, 0xff, 0xff, 0xff, 0x00], # Add Source & Start Stream with bis sync=0xffffffff PA Sync=0x02 
            #"play_stream": [0x03, 0x01, 0x02, 0xff, 0xff, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00], # modify operation with bis_sync=0b1, pa_sync=0x02
            "pause_stream": [0x03, 0x01, 0x02, 0xff, 0xff, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00], # modify operation with bis_sync=0b0, pa_sync=0x02 
            "stop_stream": [0x03, 0x01, 0x00, 0xff, 0xff, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00], # Remove operation with bis_sync=0b0, pa_sync=0x00 
            # "remove_source": [0x05, 0x01]
        }
        operation_bytes = operations.get(operation)

    if operation_bytes is not None:
        try:
            start_broadcast_state_notifications()
            print(f"Writing to Broadcast Control Point with operation: {operation}")
            bascp_char_interface.WriteValue(operation_bytes, {})
            print("Write successful, waiting for notifications...")
            # GLib.timeout_add_seconds(5, stop_broadcast_state_notifications)
            
            return bluetooth_constants.RESULT_OK
        except Exception as e:
            print("Failed to write to Broadcast Control Point")
            print(e.get_dbus_name())
            print(e.get_dbus_message())
            return bluetooth_constants.RESULT_EXCEPTION


def service_discovery(selected_device_path, bus):
    global bass_svc_path, brs_char_path, bascp_char_path
    object_manager = dbus.Interface(bus.get_object(bluetooth_constants.BLUEZ_SERVICE_NAME, "/"), bluetooth_constants.DBUS_OM_IFACE)
    managed_objects = object_manager.GetManagedObjects()

    for path, ifaces in managed_objects.items():
        if not path.startswith(selected_device_path):
            continue
        for iface_name in ifaces:
            if iface_name == bluetooth_constants.GATT_SERVICE_INTERFACE:
                service_properties = ifaces[bluetooth_constants.GATT_SERVICE_INTERFACE]
                service_uuid = service_properties["UUID"]
                if service_uuid == bluetooth_constants.BASS_SVC_UUID:
                    print(f"Broadcast Audio Scan Service Found: Path - {path}")
                    bass_svc_path = path
            if iface_name == bluetooth_constants.GATT_CHARACTERISTIC_INTERFACE:
                char_properties = ifaces[bluetooth_constants.GATT_CHARACTERISTIC_INTERFACE]
                char_uuid = char_properties["UUID"]
                if char_uuid == bluetooth_constants.BRS_CHR_UUID:
                    print(f"Broadcast Receive State Char Found: Path - {path}")
                    brs_char_path = path
                if char_uuid == bluetooth_constants.BASCP_CHR_UUID:
                    print(f"Broadcast Control Point Char Found: Path - {path}")
                    bascp_char_path = path
