from flask import Flask, render_template, request, redirect, url_for, jsonify
from bass_service_discovery import service_discovery, write_broadcast_control_point, broadcast_state_received

import dbus
import dbus.mainloop.glib
from gi.repository import GLib
import bluetooth_constants
import bluetooth_utils
import sys
import threading
import time
import subprocess
import json
import os

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

def fetch_broadcasters():
    # Compile the C code
    compile_cmd = ['cc', 'extended_scanning.c', '-lbluetooth', '-o', 'extended_scanning']
    try:
        subprocess.run(compile_cmd, check=True)  # Compile the C program
    except subprocess.CalledProcessError as e:
        print(f"Compilation failed: {e}")
        return "Error compiling C code", False

    # Run the C program
    run_cmd = ['sudo', './extended_scanning']
    try:
        subprocess.run(run_cmd, check=True)  # Run the compiled C program
    except subprocess.CalledProcessError as e:
        print(f"Execution failed: {e}")
        return "Error running C program", False

    # Load broadcasters information from the generated JSON file
    try:
        with open('broadcasters.json', 'r') as f:
            return json.load(f), True
    except FileNotFoundError:
        print("broadcasters.json not found")
        return "broadcasters.json not found", False
    except json.JSONDecodeError:
        print("Error decoding JSON data")
        return "Error decoding JSON data", False

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
    device_info['UUIDs'] = bluetooth_utils.get_uuids_name(device_info.get('UUIDs', []))
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
    # Fetch broadcasters using the C program
    broadcasters_data, success = fetch_broadcasters()
    if not success:
        return broadcasters_data, 500
    # Update the global broadcasters list with new data
    broadcasters = broadcasters_data
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
        selected_broadcaster['UUIDs'] = bluetooth_utils.get_uuids_name(selected_broadcaster['UUIDs'])

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
