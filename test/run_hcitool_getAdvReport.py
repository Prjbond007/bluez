import os
import subprocess
import time
import signal

adv_reports = {}

def start_scanning():

    # Start Logging
    command = "sudo btmon >> adv_log.txt"
    process = subprocess.Popen(command, shell=True, preexec_fn=os.setsid)

    # Start LE passive scan
    command = "sudo hcitool -i hci1 lescan --passive"
    process = subprocess.Popen(command, shell=True, preexec_fn=os.setsid)
    # Let it run for 10 seconds
    time.sleep(10)

    # Stop scanning
    command = "sudo hcitool -i hci1 cmd 0x08 0x000c 00 01 "
    process = subprocess.Popen(command, shell=True, preexec_fn=os.setsid)
    # process.wait()
    # process.terminate()

    print("Scanning completed.")
    return

def stop_scanning():
    command = "sudo hcitool -i hci1 cmd 0x08 0x000c 00 01 "
    process = subprocess.Popen(command, shell=True, preexec_fn=os.setsid)
    process.wait()
    print("Scanning stoppped.")

def show_list_of_broadcasters():
    adv_reports = {}  # Initialize the dictionary to store advertising reports
    Broadcast_found = False
    report_start_index = None
    report_end_index = None
    address = None
    name = None
    num = 0
    with open('adv_log.txt', 'r') as file:
        lines = file.readlines()
    Broadcast_found = False  # Reset for the new report
    addresses_and_names = []

    for i, line in enumerate(lines):
        if 'LE Advertising Report (0x02)' in line:
            report_start_index = i  # Mark the start of a new report

        elif 'Broadcast Audio Announcement (0x1852)' in line:
            address_line = lines[i - 8].strip()
            name_line = lines[i + 2].strip()

            address = address_line.split(': ')[1][0:18]
            name = name_line.split(': ')[1]
            if (address, name) not in addresses_and_names:
                Broadcast_found = True
                num = num + 1
                print("New Broadcaster Found ", num, "\t")
                addresses_and_names.append((address, name))
                print("Address: ", address, "\t Name: ", name)

        elif 'RSSI' in line and Broadcast_found:
            report_end_index = i
            report_details = lines[report_start_index:report_end_index + 1]  
            # print(report_details)
            # Process and store the report details in the dictionary
            report_dict = {}
            for detail in report_details:
                if ':' in detail:
                    key, value = detail.strip().split(':', 1)
                    report_dict[key.strip()] = value.strip()
            Broadcast_found = False
'''
            if address and name:  # Ensure address and name are not None
                adv_reports[address] = report_dict
                print("Address: ", address, "Name: ", name)
                # Reset variables for the next report
                Broadcast_found = False
                address = None
                name = None
'''
    # Optionally, print or return the adv_reports dictionary

def get_advertisement_report():
    target_device = input("Select Broadcaster: ")
    with open('adv_log.txt', 'r') as file:
        lines = file.readlines()

    found = False
    for i, line in enumerate(lines):
        if target_device in line:
            print("Advertisement Report for", target_device)

def main_menu():
    while True:
        print("\n1. Start scanning for 10 sec")
        print("2. Stop scanning")
        print("3. Show List of Broadcasters")
        print("4. Get Advertisement Report")
        print("5. Exit")
        choice = input("Enter your choice: ")

        if choice == '1':
            start_scanning()
        if choice == '2':
            stop_scanning()
        elif choice == '3':
            show_list_of_broadcasters()
        elif choice == '4':
            get_advertisement_report()
        elif choice == '5':
            print("Exiting...")
            break
        else:
            print("Invalid choice. Please enter a number between 1 and 4.")

if __name__ == "__main__":
    main_menu()