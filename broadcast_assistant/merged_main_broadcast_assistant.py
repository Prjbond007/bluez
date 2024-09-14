from flask import Flask, render_template, request, redirect, url_for, jsonify
import bass_service_discovery

import dbus
import dbus.mainloop.glib
from gi.repository import GLib
import bluetooth_constants
import bluetooth_utils
import sys
import threading
import time

if sys.version_info[0] >= 3:
    unicode = str

app = Flask(__name__)

# Setup DBus and GLib
dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)

# Global variables
bus = dbus.SystemBus()
mainloop = None

# Global variables to manage the Device Manager
adapter_interface = None
devices = {}
device_info = {}
device_interface = None
selected_device = None

# Global variables to manage the Broadcast Scanner
adapter_bcast_interface = None
broadcast = {}
broadcasters = {}  # Dictionary to store discovered broadcasters
selected_broadcaster = None 

# Global variables for selected devices
selected_device_info = {}
selected_broadcaster_info = {}

# Global variables for characteristic paths
bascp_char_path = None
brs_char_path = None

# Global variables for BASS Service Discovery
bass_svc_path = None
bascp_char_path = None
brs_char_path = None
operation = None
decoded_state = None
broadcast_state = None

uuid_mapping = {
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

#######################Device Manager#############################################

def set_device_interface(path, mode):
    global device_interface
    print("Mode: "+mode+"Path: "+path)
    device_proxy = bus.get_object(bluetooth_constants.BLUEZ_SERVICE_NAME, path)
    device_interface = dbus.Interface(device_proxy, bluetooth_constants.DEVICE_INTERFACE)

def interfaces_added(path, interfaces):
    global devices, device_info
    if not bluetooth_constants.DEVICE_INTERFACE in interfaces:
        return
    device_properties = interfaces[bluetooth_constants.DEVICE_INTERFACE]
    
    if device_properties:
        address = bluetooth_utils.dbus_to_python(device_properties['Address'])
        if address:
            print("New Path: ", path," New Addr: ", address)
            devices[path] = device_properties


def properties_changed(interface, changed, invalidated, path):
    global devices
    if interface != bluetooth_constants.DEVICE_INTERFACE:
        return
    
    if path in devices:
        devices[path] = dict(devices[path].items())
        devices[path].update(changed.items())

def stop_discovery():
    global adapter_interface, mainloop, bus
    try:
        adapter_interface.StopDiscovery()
        print("Discovery stopped successfully.")
    except dbus.exceptions.DBusException as e:
        if "org.bluez.Error.Failed" in e.get_dbus_name():
            print("No discovery to stop.")
        else:
            print(f"Error stopping discovery: {e.get_dbus_name()} - {e.get_dbus_message()}")
    finally:
        bus.remove_signal_receiver(interfaces_added,"InterfacesAdded")
        bus.remove_signal_receiver(properties_changed,"PropertiesChanged")
        mainloop.quit()

def get_known_devices():
    global devices

    object_manager = dbus.Interface(bus.get_object(bluetooth_constants.BLUEZ_SERVICE_NAME, "/"), bluetooth_constants.DBUS_OM_IFACE)
    managed_objects = object_manager.GetManagedObjects()

    # Construct the adapter path
    adapter_path_prefix = bluetooth_constants.BLUEZ_NAMESPACE + bluetooth_constants.ADAPTER_NAME

    for path, interfaces in managed_objects.items():
        # Check if the path starts with the adapter path prefix (e.g., /org/bluez/hci1)
        if path.startswith(adapter_path_prefix):
            for interfaces_name in interfaces:
                if interfaces_name == bluetooth_constants.DEVICE_INTERFACE:
                    devices[path] = interfaces[bluetooth_constants.DEVICE_INTERFACE]
    
def discover_devices(timeout=10):
    global adapter_interface, mainloop

    # Load known devices if not already loaded
    adapter_path = bluetooth_constants.BLUEZ_NAMESPACE + bluetooth_constants.ADAPTER_NAME
    adapter_object = bus.get_object(bluetooth_constants.BLUEZ_SERVICE_NAME, adapter_path)
    adapter_interface = dbus.Interface(adapter_object, bluetooth_constants.ADAPTER_INTERFACE)

    # Check if discovery is already active before starting a new one
    adapter_properties = dbus.Interface(adapter_object, "org.freedesktop.DBus.Properties")
    is_discovering = adapter_properties.Get("org.bluez.Adapter1", "Discovering")

    if is_discovering:
            print("Discovery already in progress, stopping first...")
            adapter_interface.StopDiscovery()

    bus.add_signal_receiver(interfaces_added,
                            dbus_interface="org.freedesktop.DBus.ObjectManager",
                            signal_name="InterfacesAdded")

    # PropertiesChanged signal is emitted by BlueZ when something re: a device already encountered
    # changes e.g., the RSSI value
    bus.add_signal_receiver(properties_changed,
                            dbus_interface=bluetooth_constants.DBUS_PROPERTIES,
                            signal_name="PropertiesChanged",
                            path_keyword="path")
    scan_filter = {
        "Transport": "le",
    }
    
    #timer_id = GLib.timeout_add(timeout, stop_discovery)
    adapter_interface.SetDiscoveryFilter(scan_filter)
    adapter_interface.StartDiscovery()
    print("Start Device Discovery")
    mainloop = GLib.MainLoop()
    GLib.timeout_add_seconds(timeout, stop_discovery)
    mainloop.run()

def connect():
    global device_interface
    try:
        device_interface.Connect()
        return ("Connected OK")
    except dbus.DBusException as e:
        return("Failed to connect: " + e.get_dbus_name() + " Message: " + e.get_dbus_message())

def disconnect():
    global device_interface
    try:
        device_interface.Disconnect()
        return ("Disconnected OK")
    except dbus.DBusException as e:
        return("Failed to connect: " + e.get_dbus_name() + " Message: " + e.get_dbus_message())

def pair():
    global device_interface
    try:
        device_interface.Pair()
        return("Pair OK")
    except dbus.DBusException as e:
        return("Failed to pair: ", e.get_dbus_name() + " Message: " + e.get_dbus_message())
    
def remove_device(device_path):
    global adapter_interface
    device_proxy = bus.get_object(bluetooth_constants.BLUEZ_SERVICE_NAME, device_path)
    try:
        adapter_interface.RemoveDevice(device_proxy.object_path)
        return("Unpair OK")
    except dbus.DBusException as e:
        return ("Failed to remove device: ", e.get_dbus_name() + " Message: " + e.get_dbus_message())
    
def is_connected(selected_device_path):
    device_info = devices.get(selected_device_path, {})
    if not device_info:
        return None
    
    try:
        return device_info.get('Connected', None)
    except dbus.exceptions.DBusException:
        return None

def is_paired(selected_device_path):
    device_info = devices.get(selected_device_path, {})
    if not device_info:
        return None
    
    try:
        return device_info.get('Paired', None)
    except dbus.exceptions.DBusException:
        return None

def check_leaudio(selected_device_path):
    device_info = devices.get(selected_device_path, {})
    if not device_info:
        return False
    
    try:
        uuids = device_info.get('UUIDs', [])
        # Check if the BASS service UUID is present
        bass_uuid = "0000184f-0000-1000-8000-00805f9b34fb"
        return bass_uuid in uuids
    except dbus.exceptions.DBusException:
        return False

##############################Broadcast Scanner#######################################

def interfaces_added_bcast(path, interfaces):
    global broadcast
    if bluetooth_constants.DEVICE_INTERFACE not in interfaces:
        return
    broadcast_properties = interfaces[bluetooth_constants.DEVICE_INTERFACE]
    if broadcast_properties:
        broadcast[path] = broadcast_properties
        update_broadcaster_list(broadcast[path])

def update_broadcaster_list(broadcast_interface):
    global broadcasters
    address = broadcast_interface.get("Address", "<unknown>")
    broadcasters[address] = bluetooth_utils.dbus_to_python(broadcast_interface)

def properties_changed_bcast(interface, changed, invalidated, path):
    global broadcast
    if interface != bluetooth_constants.DEVICE_INTERFACE:
        return

    if path in broadcast:
        broadcast[path] = dict(broadcast[path].items())
        broadcast[path].update(changed.items())
        update_broadcaster_list(broadcast[path])
    else:
        broadcast[path] = changed

def stop_discovery_bcast(adapter_interface, mainloop):
    global bus
    try:
        adapter_interface.StopDiscovery()
        print("Discovery stopped successfully.")
    except dbus.exceptions.DBusException as e:
        if "org.bluez.Error.Failed" in e.get_dbus_name():
            print("No discovery to stop.")
        else:
            print(f"Error stopping discovery: {e.get_dbus_name()} - {e.get_dbus_message()}")
    finally:
        mainloop.quit()
        bus.remove_signal_receiver(interfaces_added_bcast,"InterfacesAdded")
        bus.remove_signal_receiver(properties_changed_bcast,"PropertiesChanged")

def run_scanning():
    global adapter_bcast_interface, mainloop, bus

    try:
        adapter_bpath = bluetooth_constants.BLUEZ_NAMESPACE + "hci1"  # Ensure the correct adapter
        adapter_bobject = bus.get_object("org.bluez", adapter_bpath)
        adapter_bcast_interface = dbus.Interface(adapter_bobject, "org.bluez.Adapter1")

        # Check if discovery is already active before starting a new one
        adapter_properties = dbus.Interface(adapter_bobject, "org.freedesktop.DBus.Properties")
        is_discovering = adapter_properties.Get("org.bluez.Adapter1", "Discovering")

        if is_discovering:
            print("Discovery already in progress, stopping first...")
            adapter_bcast_interface.StopDiscovery()

        # Adding signal receivers for handling new interfaces and property changes
        bus.add_signal_receiver(interfaces_added_bcast,
                                dbus_interface="org.freedesktop.DBus.ObjectManager",
                                signal_name="InterfacesAdded")
        bus.add_signal_receiver(properties_changed_bcast,
                                dbus_interface="org.freedesktop.DBus.Properties",
                                signal_name="PropertiesChanged",
                                arg0="org.bluez.Device1",
                                path_keyword="path")

        # Setup the scan filter for LE devices
        scan_filter = {
            "Transport": "le",  # Low Energy devices
            "UUIDs": ["00001852-0000-1000-8000-00805F9B34FB"]  # Add your UUID filters if necessary
        }

        adapter_bcast_interface.SetDiscoveryFilter(scan_filter)
        adapter_bcast_interface.StartDiscovery()
        print("Discovery started successfully.")

        # Run the GLib main loop and stop after 10 seconds
        mainloop = GLib.MainLoop()
        GLib.timeout_add_seconds(10, lambda: stop_discovery_bcast(adapter_bcast_interface, mainloop))
        mainloop.run()

    except dbus.exceptions.DBusException as e:
        if "org.bluez.Error.InProgress" in e.get_dbus_name():
            print("Discovery is already in progress.")
        elif "org.bluez.Error.Failed" in e.get_dbus_name():
            print("Failed to start discovery. Check adapter status.")
        else:
            print(f"DBus Exception: {e.get_dbus_name()} - {e.get_dbus_message()}")
    except Exception as e:
        print(f"Error in run_scanning: {str(e)}")

#############################BASS Service Discovery################################################

def service_discovery(selected_device_path):
    global bass_svc_path, brs_char_path, bascp_char_path, bus
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

def get_uuids_name(uuid_list):
    return [uuid_mapping.get(uuid, uuid) for uuid in uuid_list]

#############################Device Manager Flask Application######################################

@app.route('/device_manager')
def device_manager():
    
    for path, device in devices.items():
        device['RSSI'] = device.get('RSSI', '')
        device['connected'] = is_connected(path)
        device['paired'] = is_paired(path)
        device['leaudio'] = check_leaudio(path)
    
    return render_template('app_device_manager.html', devices=devices)


@app.route('/discover', methods=['POST'])
def start_discovery():
    print("Inside discover")
    global devices

    get_known_devices()  # Load known devices 
    discover_devices(10)  # Run discovery for 10 seconds
    # Filter out any devices that still might have "Unknown" address
    devices = {path: device for path, device in devices.items() if device.get('Address') and device.get('Name')}

    return redirect(url_for('device_manager'))

@app.route('/pair', methods=['POST'])
def pair_device():
    selected_device_path = request.form.get('selectedDevice')
    if not selected_device_path:
        return jsonify({'result': 'No device selected or operation failed'}), 400

    device_info = devices.get(selected_device_path, {})
    if not device_info:
        return jsonify({'result': 'Device not found'}), 404

    try:
        set_device_interface(selected_device_path, mode="Pair")
        pair_result = pair()
        return jsonify({'result': pair_result})
    except Exception as e:
        return jsonify({'result': f'Pairing failed: {str(e)}'}), 500

@app.route('/unpair', methods=['POST'])
def unpair_device():
    selected_device_path = request.form.get('selectedDevice')
    if not selected_device_path:
        return jsonify({'result': 'No device selected or operation failed'}), 400

    device_info = devices.get(selected_device_path, {})
    if not device_info:
        return jsonify({'result': 'Device not found'}), 404

    try:
        unpair_result = remove_device(selected_device_path)
        return jsonify({'result': unpair_result})
    except Exception as e:
        return jsonify({'result': f'Unpairing failed: {str(e)}'}), 500

@app.route('/connect', methods=['POST'])
def connect_device():
    selected_device_path = request.form.get('selectedDevice')
    if not selected_device_path:
        return jsonify({'result': 'No device selected or operation failed'}), 400

    device_info = devices.get(selected_device_path, {})
    if not device_info:
        return jsonify({'result': 'Device not found'}), 404

    try:
        set_device_interface(selected_device_path, mode="Connect")
        connect_result = connect()

        return jsonify({'result': connect_result})
    except Exception as e:
        return jsonify({'result': f'Connection failed: {str(e)}'}), 500

@app.route('/disconnect', methods=['POST'])
def disconnect_device():
    selected_device_path = request.form.get('selectedDevice')
    if not selected_device_path:
        return jsonify({'result': 'No device selected or operation failed'}), 400

    device_info = devices.get(selected_device_path, {})
    if not device_info:
        return jsonify({'result': 'Device not found'}), 404

    try:
        set_device_interface(selected_device_path, mode="Disconnect")
        disconnect_result = disconnect()
        return jsonify({'result': disconnect_result})
    except Exception as e:
        return jsonify({'result': f'Disconnection failed: {str(e)}'}), 500

@app.route('/get_device_info', methods=['POST'])
def get_device_info():
    selected_device_path = request.form.get('selectedDevice')
    if not selected_device_path:
        return jsonify({'error': 'No device selected or operation failed'}), 400

    device_info = devices.get(selected_device_path, None)
    if not device_info:
        return jsonify({'error': 'Device not found'}), 404

    # Assuming function translate_uuids exists to handle UUID conversion
    device_info['UUIDs'] = get_uuids_name(device_info.get('UUIDs', []))
    return jsonify({'device_info': device_info})

@app.route('/confirm_device_selection', methods=['POST'])
def confirm_device_selection():
    global selected_device  # Use the global variable
    selected_device_path = request.form.get('selectedDevice')
    if not selected_device_path:
        return redirect(url_for('device_manager'))  # Redirect back to Device Manager if no device selected

    device_info = devices.get(selected_device_path, {})
    if not device_info.get('leaudio', False):  # Check if LE Audio is supported
        return jsonify({'le_audio_supported': False})  # Respond with JSON indicating LE Audio is not supported

    # Update the selected device info
    selected_device = {
        'Name': device_info.get('Name', 'Unknown'),
        'Address': device_info.get('Address', 'Unknown'),
        'Address Type': device_info.get('AddressType', 'Unknown'),
        'Connected': 'Yes' if device_info.get('Connected') else 'No',
        'Paired': 'Yes' if device_info.get('Paired') else 'No',
        'DevicePath': selected_device_path
    }
    return jsonify({'le_audio_supported': True, 'redirect_url': url_for('index')})  # Respond with JSON and redirect URL


#################################Broadcast Scanner Flask Application#######################################################

@app.route('/discover_broadcast', methods=['POST'])
def discover_broadcast():
    global broadcasters
    broadcasters.clear()  # Clear the previous scan results
    run_scanning()  # Start the scanning process
    broadcasters = {path: broadcaster for path, broadcaster in broadcasters.items() if broadcaster.get('Address') and broadcaster.get('Name')}
    return redirect(url_for('broadcast_scanner'))

@app.route('/broadcast_info', methods=['POST'])
def broadcast_info():
    global selected_broadcaster_info, broadcasters
    selected_address = request.form.get('selectedDevice')
    if not selected_address:
        return jsonify({'error': 'No broadcaster selected or operation failed'}), 400
    
    selected_broadcaster = broadcasters.get(selected_address, {})
    if not selected_broadcaster:
        return jsonify({'error': 'Broadcaster not found'}), 404
    
    # Convert UUIDs to names
    if 'UUIDs' in selected_broadcaster:
        selected_broadcaster['UUIDs'] = get_uuids_name(selected_broadcaster['UUIDs'])

    # Store selected broadcaster information
    selected_broadcaster_info = {
        'Name': selected_broadcaster.get('Name', 'Unknown'),
        'Address': selected_broadcaster.get('Address', 'Unknown'),
        'Address Type': selected_broadcaster.get('AddressType', 'Unknown')
    }
    
    return jsonify({'selected_broadcaster': selected_broadcaster})

@app.route('/confirm_broadcast_selection', methods=['POST'])
def confirm_broadcast_selection():
    global selected_broadcaster, broadcasters
    selected_address = request.form.get('selectedDevice')
    if not selected_address:
        return jsonify({'error': 'No broadcaster selected or operation failed'}), 400
    
    selected_broadcaster = broadcasters.get(selected_address, {})
    return jsonify({'redirect_url': url_for('index')})

@app.route('/broadcast_scanner', methods=['GET', 'POST'])
def broadcast_scanner():
    global selected_broadcaster,broadcasters
    # Convert values to a list sorted by RSSI for displaying
    sorted_broadcasters = dict(broadcasters) # dict(sorted(broadcasters.items(), key=lambda x: x[1]["RSSI"], reverse=True))
    return render_template('app_broadcast_scanner.html', broadcasters=sorted_broadcasters, 
                           selected_broadcaster=selected_broadcaster)

################################Homepage Flask Application##################################################

@app.route('/service_discovery', methods=['POST'])
def service_discovery_route():
    global bass_svc_path, brs_char_path, bascp_char_path, selected_device

    # Get the path of the selected device
    selected_device_path = selected_device.get('DevicePath')

    # Reset paths to ensure fresh discovery
    bass_svc_path = None
    brs_char_path = None
    bascp_char_path = None
    
    # Perform service discovery for the selected device
    service_discovery(selected_device_path)

    # Send result back to the page
    if bass_svc_path and brs_char_path and bascp_char_path:
        return jsonify({
            'message': 'Service Discovery Completed Successfully',
            'bass_svc_path': bass_svc_path,
            'brs_char_path': brs_char_path,
            'bascp_char_path': bascp_char_path
        })
    else:
        return jsonify({
            'message': 'Service Discovery Failed: Characteristics Not Found'
        })


@app.route('/add_streaming', methods=['POST'])
def add_streaming():
    global decoded_state, selected_broadcaster
    # Ensure service discovery has completed and paths are valid
    if not bascp_char_path or not brs_char_path:
        return jsonify({'error': 'Service discovery not completed'}), 400
    
    if selected_broadcaster:
        address = selected_broadcaster.get('Address')
        address_type = selected_broadcaster.get('AddressType')
        # Send the address and address type to the service discovery code for the "start_stream" operation
        result = write_broadcast_control_point('add_stream', address, address_type)
        return jsonify({'result': result})
        # return jsonify({'result': result, 'broadcast_info': decoded_state})
    else:
        return jsonify({'error': 'No broadcaster selected'}), 400
    
@app.route('/start_streaming', methods=['POST'])
def start_streaming():
    global decoded_state, selected_broadcaster
    # Ensure service discovery has completed and paths are valid
    if not bascp_char_path or not brs_char_path:
        return jsonify({'error': 'Service discovery not completed'}), 400
    
    if selected_broadcaster:
        address = selected_broadcaster.get('Address')
        address_type = selected_broadcaster.get('AddressType')
        # Send the address and address type to the service discovery code for the "start_stream" operation
        result = write_broadcast_control_point('start_stream', address, address_type)
        return jsonify({'result': result})
    else:
        return jsonify({'error': 'No broadcaster selected'}), 400

@app.route('/pause_streaming', methods=['POST'])
def pause_streaming():
    global decoded_state, selected_broadcaster
    # Ensure service discovery has completed and paths are valid
    if not bascp_char_path or not brs_char_path:
        return jsonify({'error': 'Service discovery not completed'}), 400
    
    if selected_broadcaster:
        address = selected_broadcaster.get('Address')
        address_type = selected_broadcaster.get('AddressType')
        # Send the address and address type to the service discovery code for the "start_stream" operation
        result = write_broadcast_control_point('pause_stream', address, address_type)
        return jsonify({'result': result})
    else:
        return jsonify({'error': 'No broadcaster selected'}), 400
    
@app.route('/stop_streaming', methods=['POST'])
def stop_stream():
    global decoded_state, selected_broadcaster
    # Ensure service discovery has completed and paths are valid
    if not bascp_char_path or not brs_char_path:
        return jsonify({'error': 'Service discovery not completed'}), 400
    
    if selected_broadcaster:
        address = selected_broadcaster.get('Address')
        address_type = selected_broadcaster.get('AddressType')
        # Send the address and address type to the service discovery code for the "stop_stream" operation
        result = write_broadcast_control_point('stop_stream', address, address_type)
        return jsonify({'result': result})

    else:
        return jsonify({'error': 'No broadcaster selected'}), 400

@app.route('/set_broadcast_code', methods=['POST'])
def set_broadcast_code():
    global selected_broadcaster
    data = request.get_json()
    broadcast_code = data.get('code')

    if not broadcast_code or len(broadcast_code) != 32:
        return jsonify({'error': 'Invalid broadcast code provided.'}), 400

    if selected_broadcaster:
        # Perform the "set_code" operation
        result = write_broadcast_control_point('set_code', broadcast_code=broadcast_code)
        return jsonify({'result': result})
    else:
        return jsonify({'error': 'No broadcaster selected'}), 400
    
@app.route('/get_broadcast_state', methods=['GET'])
def get_broadcast_state():
    global decoded_state
    if decoded_state:
        return jsonify(decoded_state)
    return jsonify({'error': 'No broadcast state received yet.'})

@app.route('/')
def index():
    global bascp_char_path, brs_char_path, decoded_state
    return render_template('app_broadcast_assistant.html', 
                           selected_device=selected_device, 
                           selected_broadcaster=selected_broadcaster, 
                           brs_char_path=brs_char_path, 
                           bascp_char_path=bascp_char_path, 
                           broadcast_info=decoded_state)

def handle_dbus_signals():
    """Set up and handle DBus signals in a separate thread."""
    dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
    global bus

    bus.add_signal_receiver(
        broadcast_state_received,
        dbus_interface=bluetooth_constants.DBUS_PROPERTIES,
        signal_name="PropertiesChanged",
        path=brs_char_path,
        path_keyword="path"
    )
    GLib.MainLoop().run()

def run_flask_app():
    """Run the Flask app in a separate thread."""
    app.run(debug=True, use_reloader=False)

if __name__ == '__main__':
    # Thread for DBus signal handling
    dbus_thread = threading.Thread(target=handle_dbus_signals)
    dbus_thread.daemon = True
    dbus_thread.start()

    # Thread for Flask app
    flask_thread = threading.Thread(target=run_flask_app)
    flask_thread.daemon = True
    flask_thread.start()

    # Main thread will wait for these threads
    dbus_thread.join()
    flask_thread.join()
