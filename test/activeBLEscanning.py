import argparse
from gi.repository import GLib
from pydbus import SystemBus
import datetime

DEVICE_INTERFACE = 'org.bluez.Device1'

remove_list = set()

def stop_scan():
    """Stop device discovery and quit event loop"""
    adapter.StopDiscovery()
    mainloop.quit()

def on_iface_added(owner, path, iface, signal, interfaces_and_properties):
    """
    Event handler for D-Bus interface added.
    Test to see if it is a new Bluetooth device
    """
    iface_path, iface_props = interfaces_and_properties
    if DEVICE_INTERFACE in iface_props:
        on_device_found(iface_path, iface_props[DEVICE_INTERFACE])

def on_properties_changed(owner, path, iface, signal, interfaces_and_properties):
    """
    Event handler for D-Bus interface properties changed.
    Manufacturing data or Service Data change
    """
    iface_path, iface_props, leftover = interfaces_and_properties
    if DEVICE_INTERFACE in interfaces_and_properties:
        on_device_found(path, iface_props)

def on_device_found(device_path, device_props):
    """
    Handle new Bluetooth device being discover.
    If it is a beacon of type iBeacon, Eddystone, AltBeacon
    then process it
    """
    address = device_props.get('Address')
    
    address_type = device_props.get('AddressType')
    name = device_props.get('Name')
    alias = device_props.get('Alias')
    paired = device_props.get('Paired')
    trusted = device_props.get('Trusted')
    rssi = device_props.get('RSSI')
    service_data = device_props.get('ServiceData')
    manufacturer_data = device_props.get('ManufacturerData')
    
    if address == 'D7:6F:3F:5E:F4:BF' or "D7_6F_3F_5E_F4_BF" in device_path:
    
        print(str(datetime.datetime.now()) + " MAC: " + str(address) + 
              " RSSI:" + str(rssi) + " MData:" + str(manufacturer_data))
        adapter.RemoveDevice(device_path)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', '--duration', type=int, default=0,
                        help='Duration of scan [0 for continuous]')
    args = parser.parse_args()
    bus = SystemBus()
    #adapter = bus.get('org.bluez', '/org/bluez/hci0')
    adapter = bus.get('org.bluez', '/org/bluez/hci1')
    bus.subscribe(iface='org.freedesktop.DBus.ObjectManager',
                  signal='InterfacesAdded',
                  signal_fired=on_iface_added)
    
    # bus.subscribe(iface='org.freedesktop.DBus.Properties',
    #               signal='PropertiesChanged',
    #               signal_fired=on_properties_changed)

    mainloop = GLib.MainLoop()

    if args.duration > 0:
        GLib.timeout_add_seconds(args.duration, stop_scan)
    adapter.SetDiscoveryFilter({'DuplicateData': GLib.Variant.new_boolean(True), 
                                "Transport":GLib.Variant.new_string("le")})
    
    adapter.StartDiscovery()

    try:
        print('\n\tUse CTRL-C to stop discovery\n')
        mainloop.run()
    except KeyboardInterrupt:
        stop_scan()