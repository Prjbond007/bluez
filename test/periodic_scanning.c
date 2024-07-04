// To compile this program, you need to install:
//   sudo apt-get install libbluetooth-dev
// Then you can compile it with:
//   cc periodic_scanning.c -lbluetooth -o periodic_scanning
// You can then run it with:
//   sudo ./periodic_scanning

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#define _GNU_SOURCE
#include <stdio.h>

#include <ctype.h>
#include <fcntl.h>
#include <unistd.h>

#include <string.h>
#include <getopt.h>
#include <sys/param.h>

#include <signal.h>

#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>
#include <time.h>

#define EIR_NAME_SHORT              0x08  /* shortened local name */
#define EIR_NAME_COMPLETE           0x09  /* complete local name */
#define OCF_LE_PA_CREATE_SYNC		0x2044
struct le_pa_create_sync {
	uint8_t  options;
	uint8_t  sid;
	uint8_t  addr_type;
	uint8_t  addr[6];
	uint16_t skip;
	uint16_t sync_timeout;
	uint8_t  sync_cte_type;
} __attribute__ ((packed));

#define EVT_EXT_LE_ADVERTISING_REPORT	0x0D
typedef struct {
	uint8_t 	subevent_Code;
	uint8_t     num_reports;
	uint8_t		evt_type;
	uint8_t		bdaddr_type;
	bdaddr_t	bdaddr;
	uint8_t		primary_PHY;
	uint8_t		secondary_PHY;
	uint8_t		advertising_SID;
	uint8_t		tx_power;
	uint8_t		rssi;
	uint8_t		periodic_advertising_interval;
	uint8_t		direct_address_type;
	uint8_t		direct_address;
	uint8_t		length;
	uint8_t		data[];
} __attribute__ ((packed)) le_extended_advertising_info;

struct hci_request ble_hci_request(uint16_t ocf, int clen, void * status, void * cparam)
{
	struct hci_request rq;
	memset(&rq, 0, sizeof(rq));
	rq.ogf = OGF_LE_CTL;
	rq.ocf = ocf;
	rq.cparam = cparam;
	rq.clen = clen;
	rq.rparam = status;
	rq.rlen = 1;
	return rq;
}

static void eir_parse_name(uint8_t *eir, size_t eir_len,
						char *buf, size_t buf_len)
{
	size_t offset;

	offset = 0;
	while (offset < eir_len) {
		uint8_t field_len = eir[0];
		size_t name_len;

		/* Check for the end of EIR */
		if (field_len == 0)
			break;

		if (offset + field_len > eir_len)
			goto failed;

		switch (eir[1]) {
		case EIR_NAME_SHORT:
		case EIR_NAME_COMPLETE:
			name_len = field_len - 1;
			if (name_len > buf_len)
				goto failed;

			memcpy(buf, &eir[2], name_len);
			return;
		}

		offset += field_len + 1;
		eir += field_len + 1;
	}

failed:
	snprintf(buf, buf_len, "(unknown)");
}

// Function to convert string address to byte array
void str_to_addr(const char *str, uint8_t *addr) {
    int values[6];
    if (6 == sscanf(str, "%x:%x:%x:%x:%x:%x", &values[5], &values[4], &values[3], &values[2], &values[1], &values[0])) {
        for (int i = 0; i < 6; ++i) {
            addr[i] = (uint8_t)values[i];
        }
    } else {
        printf("Address format error.\n");
    }
}

int main()
{
	int ret, status;
	int err;
	// Get HCI device.

	le_set_scan_enable_cp scan_cp;
	memset(&scan_cp, 0, sizeof(scan_cp));
	scan_cp.enable 		= 0x01;	// Enable flag.
	scan_cp.filter_dup 	= 0x00; // Filtering disabled.
	
	int device = hci_open_dev(0);
	if ( device < 0 ) {
		device = hci_open_dev(0);
		if (device >= 0) {
   		printf("Using hci0\n");
		}
	}
	else {
   		printf("Using hci1\n");
	}

	if ( device < 0 ) {
		perror("Failed to open HCI device.");
		return 0;
	}
	
	// Set BLE scan parameters.

	le_set_scan_parameters_cp scan_params_cp;
	memset(&scan_params_cp, 0, sizeof(scan_params_cp));
	scan_params_cp.type 			= 0x00; // passive scan
	scan_params_cp.interval 		= htobs(0x0010);
	scan_params_cp.window 			= htobs(0x0010);
	scan_params_cp.own_bdaddr_type 	= 0x00; // Public Device Address (default).
	scan_params_cp.filter 			= 0x00; // Accept all.

	struct hci_request scan_params_rq = ble_hci_request(OCF_LE_SET_SCAN_PARAMETERS, LE_SET_SCAN_PARAMETERS_CP_SIZE, &status, &scan_params_cp);

	ret = hci_send_req(device, &scan_params_rq, 1000);
	if ( ret < 0 ) {
		hci_close_dev(device);
		perror("Failed to set scan parameters data.");
		return 0;
	}

	// Set BLE events report mask.

	le_set_event_mask_cp event_mask_cp;
	memset(&event_mask_cp, 0, sizeof(le_set_event_mask_cp));
	int i = 0;
	for ( i = 0 ; i < 8 ; i++ ) event_mask_cp.mask[i] = 0xFF;

	struct hci_request set_mask_rq = ble_hci_request(OCF_LE_SET_EVENT_MASK, LE_SET_EVENT_MASK_CP_SIZE, &status, &event_mask_cp);
	ret = hci_send_req(device, &set_mask_rq, 1000);
	if ( ret < 0 ) {
		hci_close_dev(device);
		perror("Failed to set event mask.");
		return 0;
	}

	// Enable scanning.
	scan_cp.enable 		= 0x01;	// Enable flag.
	scan_cp.filter_dup 	= 0x00; // Filtering disabled.

	struct hci_request enable_adv_rq = ble_hci_request(OCF_LE_SET_SCAN_ENABLE, LE_SET_SCAN_ENABLE_CP_SIZE, &status, &scan_cp);

	ret = hci_send_req(device, &enable_adv_rq, 10);
	if ( ret < 0 ) {
		hci_close_dev(device);
		perror("Failed to enable scan.");
		return 0;
	}

	// Get Results.

	struct hci_filter nf;
	hci_filter_clear(&nf);
	hci_filter_set_ptype(HCI_EVENT_PKT, &nf);
	hci_filter_set_event(EVT_LE_META_EVENT, &nf);
	if ( setsockopt(device, SOL_HCI, HCI_FILTER, &nf, sizeof(nf)) < 0 ) {
		hci_close_dev(device);
		perror("Could not set socket options\n");
		return 0;
	}


	uint8_t buf[HCI_MAX_EVENT_SIZE];
	evt_le_meta_event * meta_event;
	le_extended_advertising_info * info;
	int len;

    int count = 0;
    unsigned now = (unsigned)time(NULL);
    unsigned last_detection_time = now;
    // Keep scanning until we see nothing for 10 secs or we have seen lots of advertisements.  Then exit.
    // We exit in this case because the scan may have failed or stopped. Higher level code can restart
	while ( last_detection_time - now < 10 && count < 1000 ) {
		len = read(device, buf, sizeof(buf));
		if ( len >= HCI_EVENT_HDR_SIZE ) {
			
		    count++;
            last_detection_time = (unsigned)time(NULL);
			meta_event = (evt_le_meta_event*)(buf+HCI_EVENT_HDR_SIZE+1);
			
			if ( meta_event->subevent == EVT_EXT_LE_ADVERTISING_REPORT ) {
				
			uint8_t reports_count = meta_event->data[0];
			void * offset = meta_event->data + 1;
			info = (le_extended_advertising_info *)offset;
			printf("Advertising SID: %d\n", info->advertising_SID);
			while ( reports_count-- ) {
				info = (le_extended_advertising_info *)offset;
				char name[30];
				char addr[18];
				ba2str(&(info->bdaddr), addr);
				eir_parse_name(info->data, info->length, name, sizeof(name) - 1);
				printf("LE Extended Advertising Report\n");
				printf("Address: %s\n", addr);
				printf("Name: %s\n", name);
				printf("Event Type: %d\n", info->evt_type);
				printf("BD Address Type: %d\n", info->bdaddr_type);
				printf("Primary PHY: %d\n", info->primary_PHY);
				printf("Secondary PHY: %d\n", info->secondary_PHY);
				printf("Advertising SID: %d\n", info->advertising_SID);
				printf("TX Power: %d\n", info->tx_power);
				printf("RSSI: %d\n", info->rssi);
				printf("Data Length: %d\n", info->length);
				printf("*******************************");
				/*
				printf("Data:");
				for (int i = 0; i < info->length; i++) {
					printf(" %02X", (unsigned char)info->data[i]);
				}
				printf("\n");*/
				// Adjust offset for the next report
				offset = (uint8_t *)offset + sizeof(le_extended_advertising_info) + info->length - 1;
				}
			
            }
		}
        now = (unsigned)time(NULL);
	}
	
    // Create sync
    struct le_pa_create_sync create_sync_cp;
    memset(&create_sync_cp, 0, sizeof(create_sync_cp));
    create_sync_cp.options = 0x00; // Use default options
    create_sync_cp.sid = 0x01; // Advertising SID
    create_sync_cp.addr_type = 0x01; // Public Device 
    const char *address_str = "C0:07:E8:9F:18:3C";
    str_to_addr(address_str, create_sync_cp.addr);
    create_sync_cp.skip = htobs(0x0000); // Number of advertising events that can be skipped after a successful receive
    create_sync_cp.sync_timeout = htobs(0x0258); // Synchronization timeout (6000 ms)
    create_sync_cp.sync_cte_type = 0x00; // Do not use Constant Tone Extension

    // Create an HCI request for LE Periodic Advertising Create Sync
    struct hci_request pa_create_sync_rq = ble_hci_request(OCF_LE_PA_CREATE_SYNC, sizeof(create_sync_cp), &status, &create_sync_cp);

    // Send the request
    ret = hci_send_req(device, &pa_create_sync_rq, 0);
    if (ret < 0) {
        hci_close_dev(device);
        perror("Failed to start LE Periodic Advertising Create Sync.");
        return 0;
    }
	
	// Disable scanning.
	memset(&scan_cp, 0, sizeof(scan_cp));
	scan_cp.enable = 0x00;	// Disable flag.

	struct hci_request disable_adv_rq = ble_hci_request(OCF_LE_SET_SCAN_ENABLE, LE_SET_SCAN_ENABLE_CP_SIZE, &status, &scan_cp);
	ret = hci_send_req(device, &disable_adv_rq, 10);
	if ( ret < 0 ) {
		hci_close_dev(device);
		perror("Failed to disable scan.");
		return 0;
	}

	hci_close_dev(device);

	return 0;
}