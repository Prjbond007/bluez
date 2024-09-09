from flask import Flask, render_template, request, redirect, url_for, jsonify
import bass_service_discovery

import dbus
import dbus.mainloop.glib
from gi.repository import GLib
import bluetooth_constants
import bluetooth_utils
import sys

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

decoded_broadcast_info = None
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
        devices[path] = device_properties
        address = bluetooth_utils.dbus_to_python(device_properties['Address'])
        print("New Addr: ", address)
        device_info[address] = bluetooth_utils.dbus_to_python(device_properties)

def properties_changed(interface, changed, invalidated, path):
    global devices
    if interface != bluetooth_constants.DEVICE_INTERFACE:
        return
    if path in devices:
        devices[path] = dict(devices[path].items())
        devices[path].update(changed.items())
    else:
        devices[path] = changed

def stop_discovery():
    global adapter_interface, mainloop
    adapter_interface.StopDiscovery()
    mainloop.quit()
    print("Stop Device Discovery")
    bus = dbus.SystemBus()
    bus.remove_signal_receiver(interfaces_added,"InterfacesAdded")
    bus.remove_signal_receiver(properties_changed,"PropertiesChanged")
    return True

def get_known_devices():
    global devices

    object_manager = dbus.Interface(bus.get_object(bluetooth_constants.BLUEZ_SERVICE_NAME, "/"), bluetooth_constants.DBUS_OM_IFACE)
    managed_objects = object_manager.GetManagedObjects()

    # Construct the adapter path
    adapter_path_prefix = bluetooth_constants.BLUEZ_NAMESPACE + bluetooth_constants.ADAPTER_NAME

    for path, ifaces in managed_objects.items():
        # Check if the path starts with the adapter path prefix (e.g., /org/bluez/hci1)
        if path.startswith(adapter_path_prefix):
            for iface_name in ifaces:
                if iface_name == bluetooth_constants.DEVICE_INTERFACE:
                    device_properties = ifaces[bluetooth_constants.DEVICE_INTERFACE]
                    devices[path] = device_properties
    
def discover_devices(timeout=10):
    global adapter_interface, mainloop

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
    mainloop = GLib.MainLoop()
    GLib.timeout_add_seconds(timeout, stop_discovery)
    #timer_id = GLib.timeout_add(timeout, stop_discovery)
    adapter_interface.SetDiscoveryFilter(scan_filter)
    adapter_interface.StartDiscovery()
    print("Start Device Discovery")
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
        print("Disconnected OK")
        return bluetooth_constants.RESULT_OK
    except Exception as e:
        print("Failed to disconnect")
        print(e.get_dbus_name())
        print(e.get_dbus_message())
        if "UnknownObject" in e.get_dbus_name():
            print("Try scanning first to resolve this problem")
        return bluetooth_constants.RESULT_EXCEPTION

def pair():
    global device_interface
    try:
        device_interface.Pair()
        return("Pair OK")
    except dbus.DBusException as e:
        return("Failed to pair: ", e.get_dbus_name() + " Message: " + e.get_dbus_message())

def cancel_pairing():
    global device_interface
    try:
        device_interface.CancelPairing()
        return("Un-Pairing OK")
    except dbus.DBusException as e:
        return ("Failed to unpair: ", e.get_dbus_name() + " Message: " + e.get_dbus_message())

def remove_device(device_path):
    global adapter_interface
    device_proxy = bus.get_object(bluetooth_constants.BLUEZ_SERVICE_NAME, device_path)
    try:
        adapter_interface.RemoveDevice(device_proxy.object_path)
        return("Device removed OK")
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

def run_scanning():
    global adapter_interface
    global adapter_bcast_interface, mainloop

    adapter_bpath = bluetooth_constants.BLUEZ_NAMESPACE + "hci0"
    adapter_bobject = bus.get_object("org.bluez", adapter_bpath)
    adapter_bcast_interface = dbus.Interface(adapter_bobject, "org.bluez.Adapter1")
    
    bus.add_signal_receiver(interfaces_added_bcast,
                            dbus_interface="org.freedesktop.DBus.ObjectManager",
                            signal_name="InterfacesAdded")
    bus.add_signal_receiver(properties_changed_bcast,
                            dbus_interface="org.freedesktop.DBus.Properties",
                            signal_name="PropertiesChanged",
                            arg0="org.bluez.Device1",
                            path_keyword="path")

    scan_filter = {
        "Transport": "le",
        "UUIDs": ["00001852-0000-1000-8000-00805F9B34FB"]
    }

    adapter_bcast_interface.SetDiscoveryFilter(scan_filter)
    adapter_bcast_interface.StartDiscovery()

    mainloop = GLib.MainLoop()
    GLib.timeout_add_seconds(10, lambda: stop_discovery_bcast())
    mainloop.run()

def stop_discovery_bcast():
    global adapter_bcast_interface, mainloop
    adapter_bcast_interface.StopDiscovery()
    mainloop.quit()
    print("StopDiscovery")
    bus = dbus.SystemBus()
    bus.remove_signal_receiver(interfaces_added_bcast,"InterfacesAdded")
    bus.remove_signal_receiver(properties_changed_bcast,"PropertiesChanged")
    return True

#############################Device Manager Flask Application######################################

@app.route('/device_manager')
def device_manager():
    global adapter_interface
    # Load known devices if not already loaded
    adapter_path = bluetooth_constants.BLUEZ_NAMESPACE + bluetooth_constants.ADAPTER_NAME
    adapter_object = bus.get_object(bluetooth_constants.BLUEZ_SERVICE_NAME, adapter_path)
    adapter_interface = dbus.Interface(adapter_object, bluetooth_constants.ADAPTER_INTERFACE)

    for path, device in devices.items():
        device['Name'] = device.get('Name', 'Unknown')
        device['Address'] = device.get('Address', 'Unknown')
        device['RSSI'] = device.get('RSSI', 'Unknown')
        device['connected'] = is_connected(path)
        device['paired'] = is_paired(path)
        device['leaudio'] = check_leaudio(path)

    return render_template('app_device_manager.html', devices=devices)


@app.route('/discover', methods=['POST'])
def start_discovery():
    print("Inside discover")
    global devices

    get_known_devices()  # Load known devices only once
    discover_devices(10)  # Run discovery for 10 seconds
    # Filter out any devices that still might have "Unknown" name or address
    devices = {path: device for path, device in devices.items() if device.get('Name') and device.get('Address')}
     # Print all device paths
    print("List of All the Discovered Device Paths:")
    for path in devices:
        print(path)

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
    global selected_device_info
    selected_device_path = request.form.get('selectedDevice')
    if not selected_device_path:
        return jsonify({'result': 'No device selected or operation failed'}), 400

    device_info = devices.get(selected_device_path, {})
    if not device_info:
        return jsonify({'result': 'Device not found'}), 404

    # Store selected device information
    selected_device_info = {
        'Name': device_info.get('Name', 'Unknown'),
        'Address': device_info.get('Address', 'Unknown'),
        'Address Type': device_info.get('AddressType', 'Unknown'),
        'Connected': 'Yes' if device_info.get('Connected') else 'No',
        'Paired': 'Yes' if device_info.get('Paired') else 'No'
    }

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
    }
    return jsonify({'le_audio_supported': True, 'redirect_url': url_for('index')})  # Respond with JSON and redirect URL


#################################Broadcast Scanner Flask Application#######################################################

@app.route('/discover_broadcast', methods=['POST'])
def discover_broadcast():
    global broadcasters
    broadcasters.clear()  # Clear the previous scan results
    run_scanning()  # Start the scanning process
    return redirect(url_for('broadcast_scanner'))


@app.route('/broadcast_info', methods=['POST'])
def broadcast_info():
    global selected_broadcaster_info
    selected_address = request.form.get('selectedDevice')
    if not selected_address:
        return jsonify({'error': 'No broadcaster selected or operation failed'}), 400
    
    selected_broadcaster = broadcasters.get(selected_address, {})
    if not selected_broadcaster:
        return jsonify({'error': 'Broadcaster not found'}), 404

    # Store selected broadcaster information
    selected_broadcaster_info = {
        'Name': selected_broadcaster.get('Name', 'Unknown'),
        'Address': selected_broadcaster.get('Address', 'Unknown'),
        'Address Type': selected_broadcaster.get('AddressType', 'Unknown')
    }

    return jsonify({'selected_broadcaster': selected_broadcaster})

@app.route('/confirm_broadcast_selection', methods=['POST'])
def confirm_broadcast_selection():
    global selected_broadcaster
    selected_address = request.form.get('selectedDevice')
    if not selected_address:
        return jsonify({'error': 'No broadcaster selected or operation failed'}), 400
    
    selected_broadcaster = broadcasters.get(selected_address, {})
    return jsonify({'redirect_url': url_for('index')})

@app.route('/broadcast_scanner', methods=['GET', 'POST'])
def broadcast_scanner():
    global selected_broadcaster
    # Convert values to a list sorted by RSSI for displaying
    sorted_broadcasters = dict(sorted(broadcasters.items(), key=lambda x: x[1]["RSSI"], reverse=True))
    return render_template('broadcast_scanner_assistant.html', broadcasters=sorted_broadcasters, 
                           selected_broadcaster=selected_broadcaster)

################################Homepage Flask Application##################################################

@app.route('/service_discovery', methods=['POST'])
def service_discovery_route():
    global bascp_char_path, brs_char_path
    
    # Perform service discovery
    bass_service_discovery.service_discovery_completed()
    
    # Update paths after discovery
    bascp_char_path = bass_service_discovery.bascp_char_path
    brs_char_path = bass_service_discovery.brs_char_path

    # Send result back to the page
    if bascp_char_path and brs_char_path:
        return jsonify({
            'message': 'Service Discovery Completed Successfully',
            'bascp_char_path': bascp_char_path,
            'brs_char_path': brs_char_path
        })
    else:
        return jsonify({
            'message': 'Service Discovery Failed: Characteristics Not Found'
        })
    
@app.route('/start_streaming', methods=['POST'])
def start_streaming():
    global decoded_broadcast_info

    # Ensure service discovery has completed and paths are valid
    if not bascp_char_path or not brs_char_path:
        return jsonify({'error': 'Service discovery not completed'}), 400
    
    if selected_broadcaster:
        address = selected_broadcaster.get('Address')
        address_type = selected_broadcaster.get('AddressType')
        # Send the address and address type to the service discovery code for the "start_stream" operation
        result = bass_service_discovery.write_broadcast_control_point('start_stream', address, address_type)

        # Use the latest broadcast info if available
        if decoded_broadcast_info:
            broadcast_info = decoded_broadcast_info
        else:
            broadcast_info = "No stream data received yet"
        
        return jsonify({'result': result, 'broadcast_info': broadcast_info})
    else:
        return jsonify({'error': 'No broadcaster selected'}), 400

@app.route('/stop_streaming', methods=['POST'])
def stop_stream():
    global decoded_broadcast_info

    # Ensure service discovery has completed and paths are valid
    if not bascp_char_path or not brs_char_path:
        return jsonify({'error': 'Service discovery not completed'}), 400
    
    if selected_broadcaster:
        address = selected_broadcaster.get('Address')
        address_type = selected_broadcaster.get('AddressType')
        # Send the address and address type to the service discovery code for the "stop_stream" operation
        result = bass_service_discovery.write_broadcast_control_point('stop_stream', address, address_type)

        # Use the latest broadcast info if available
        if decoded_broadcast_info:
            broadcast_info = decoded_broadcast_info
        else:
            broadcast_info = "No stream data received yet"

        return jsonify({'result': result, 'broadcast_info': broadcast_info})
    else:
        return jsonify({'error': 'No broadcaster selected'}), 400

@app.route('/get_last_broadcast_state', methods=['GET'])
def get_last_broadcast_state():
    global decoded_broadcast_info
    if decoded_broadcast_info:
        return jsonify(decoded_broadcast_info)
    else:
        return jsonify({"error": "No broadcast state received yet."})
    
@app.route('/')
def index():
    global bascp_char_path, brs_char_path
    return render_template('index.html', selected_device=selected_device, selected_broadcaster=selected_broadcaster, brs_char_path=brs_char_path, bascp_char_path=bascp_char_path)

if __name__ == '__main__':
    bass_service_discovery.init_dbus()  # Initialize DBus in service discovery
    app.run(debug=True, use_reloader=False)
