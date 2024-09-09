#!/usr/bin/python3
#
# Connects to a specified device
# Run from the command line with a Bluetooth device address argument

import bluetooth_constants
import bluetooth_utils
import dbus
import sys
import time
sys.path.insert(0, '.')

bus = None
device_interface = None


def is_connected(device_proxy):
    global bus
    try:
        props_interface = dbus.Interface(device_proxy, bluetooth_constants.DBUS_PROPERTIES)
        connected = props_interface.Get(bluetooth_constants.DEVICE_INTERFACE, "Connected")
        return connected
    except dbus.exceptions.DBusException as e:
        return None


def is_paired(device_proxy):
    try:
        props_interface = dbus.Interface(device_proxy, bluetooth_constants.DBUS_PROPERTIES)
        paired = props_interface.Get(bluetooth_constants.DEVICE_INTERFACE, "Paired")
        return paired
    except dbus.exceptions.DBusException as e:
        return None
    
def connect():
    global bus
    global device_interface
    try:
        device_interface.Connect()
    except Exception as e:
        print("Failed to connect")
        print(e.get_dbus_name())
        print(e.get_dbus_message())
        if ("UnknownObject" in e.get_dbus_name()):
            print("Try scanning first to resolve this problem")
        return bluetooth_constants.RESULT_EXCEPTION
    else:
        print("Connected OK")
        return bluetooth_constants.RESULT_OK

def disconnect():
    global bus
    global device_interface
    try:
        device_interface.Disconnect()
    except Exception as e:
        print("Failed to disconnect")
        print(e.get_dbus_name())
        print(e.get_dbus_message())
        if ("UnknownObject" in e.get_dbus_name()):
            print("Try scanning first to resolve this problem")
        return bluetooth_constants.RESULT_EXCEPTION
    else:
        print("Disconnected OK")
        return bluetooth_constants.RESULT_OK
    
def pair():
    global bus
    global device_interface
    try:
        device_interface.Pair()
    except Exception as e:
        print("Failed to pair")
        print(e.get_dbus_name())
        print(e.get_dbus_message())
        if ("UnknownObject" in e.get_dbus_name()):
            print("Try scanning first to resolve this problem")
        return bluetooth_constants.RESULT_EXCEPTION
    else:
        print("Pairing OK")
        return bluetooth_constants.RESULT_OK

def unpair():
    global bus
    global device_interface
    try:
        device_interface.CancelPairing()
    except Exception as e:
        print("Failed to cancel pairing")
        print(e.get_dbus_name())
        print(e.get_dbus_message())
        if ("UnknownObject" in e.get_dbus_name()):
            print("Try scanning first to resolve this problem")
        return bluetooth_constants.RESULT_EXCEPTION
    else:
        print("Un-Pairing OK")
        return bluetooth_constants.RESULT_OK

def remove_device(device_proxy):
    global adapter_interface
    try:
        adapter_interface.RemoveDevice(device_proxy.object_path)
    except Exception as e:
        print("Failed to remove device")
        print(e.get_dbus_name())
        print(e.get_dbus_message())
        return bluetooth_constants.RESULT_EXCEPTION
    else:
        print("Device removed OK")
        return bluetooth_constants.RESULT_OK

def print_menu():
    print("\nMenu:")
    print("1. Connect")
    print("2. Disconnect")
    print("3. Pair")
    print("4. Unpair")
    print("5. Remove Device")
    print("6. Exit")
    
def handle_selection(selection, bdaddr):
    if selection == '1':
        print("Connecting to " + bdaddr)
        print(connect())
    elif selection == '2':
        print("Disconnecting from " + bdaddr)
        print(disconnect())
    elif selection == '3':
        print("Pairing with " + bdaddr)
        print(pair())
    elif selection == '4':
        print("Unpairing from " + bdaddr)
        print(unpair())
    elif selection == '5':
        print("Removing device " + bdaddr)
        print(remove_device(device_proxy))
    elif selection == '6':
        print("Exiting...")
        sys.exit(0)
    else:
        print("Invalid selection. Please choose a valid option.")

if len(sys.argv) != 2:
    print("usage: python3 connect_pair.py [bdaddr]")
    sys.exit(1)

bdaddr = sys.argv[1]
bus = dbus.SystemBus()
adapter_path = bluetooth_constants.BLUEZ_NAMESPACE + bluetooth_constants.ADAPTER_NAME
device_path = bluetooth_utils.device_address_to_path(bdaddr, adapter_path)
print(device_path)
device_proxy = bus.get_object(bluetooth_constants.BLUEZ_SERVICE_NAME, device_path)
device_interface = dbus.Interface(device_proxy, bluetooth_constants.DEVICE_INTERFACE)   

# Acquire the adapter interface so we can call its methods 
adapter_object = bus.get_object(bluetooth_constants.BLUEZ_SERVICE_NAME, adapter_path)
adapter_interface = dbus.Interface(adapter_object, bluetooth_constants.ADAPTER_INTERFACE)

while True:
    print("\nDevice Address:", bdaddr)
    print("Connected:", bool(is_connected(device_proxy)))
    print("Paired:", bool(is_paired(device_proxy)))
    
    print_menu()
    selection = input("Please select an option: ")
    handle_selection(selection, bdaddr)
