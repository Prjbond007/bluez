import subprocess

def run_hcitool_command(command):
    process = subprocess.Popen(command.split(), stdout = subprocess.PIPE)
    output, error = process.communicate()

    if error:
        print(f'Error: {error}')
    else:
        return output

commands = [
    "sudo btmon",
    "sudo hcitool -i hci1 lescan --passive",             # Start LE passive scan
    "hcitool -i hci1 cmd 0x08 0x000c 00 01",            # Stop Scanning
    "hcitool -i hci1 cmd 0x08 0x000c 01 01",             # Start Scanning
    "hcitool -i hci1 cmd 0x08 0x0044 00 10 01 3C 18 9F E8 07 C0 00 00 0A 00 00" # Set Periodic Create Sync Parameters
    "hcitool -i hci1 cmd 0x08 0x000c 00 01",            # Stop Scanning
]

for cmd in commands:
    print(run_hcitool_command(cmd))