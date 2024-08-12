#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>
#include <time.h>
#include "util.h"
#define BT_HCI_LE_EXT_SCAN_PHY_1M   BIT(0)
#define HCI_EVENT_HDR_SIZE          2
#define EVT_EXT_LE_ADVERTISING_REPORT  0x0D
#define EIR_NAME_SHORT              0x08  /* shortened local name */
#define EIR_NAME_COMPLETE           0x09  /* complete local name */
#define BT_EIR_UUID16_ALL		0x03

typedef struct {
    char name[30];
    uint8_t addr_type;
    char baddr[18];
    uint8_t sid;
} broadcast_device_info;
broadcast_device_info broadcasters[1000];
int broadcaster_count = 0;

#define OCF_LE_PA_CREATE_SYNC		0x0044
typedef struct {
	uint8_t  options;
	uint8_t  sid;
	uint8_t  addr_type;
	uint8_t  addr[6];
	uint16_t skip;
	uint16_t sync_timeout;
	uint8_t  sync_cte_type;
} __attribute__ ((packed)) le_pa_create_sync;

typedef struct {
    uint8_t own_bdaddr_type;
    uint8_t filter;
    uint8_t scanning_phy;
    uint8_t type;
    uint16_t interval;
    uint16_t window;
} __attribute__ ((packed)) le_set_extended_scan_parameters_cp;

typedef struct {
    uint8_t enable;
    uint8_t filter_dup;
    uint16_t duration;
    uint16_t period;
} __attribute__ ((packed)) le_set_extended_scan_enable_cp;

#define BT_HCI_EVT_LE_EXT_ADV_REPORT	0x0d
struct bt_hci_evt_le_ext_adv_report {
	uint8_t  num_reports;
} __attribute__ ((packed));
typedef struct {
	uint16_t event_type;
	uint8_t  addr_type;
	bdaddr_t addr;
	uint8_t  primary_phy;
	uint8_t  secondary_phy;
	uint8_t  sid;
	uint8_t  tx_power;
	int8_t   rssi;
	uint16_t interval;
	uint8_t  direct_addr_type;
	uint8_t  direct_addr[6];
	uint8_t  data_len;
	uint8_t  data[0];
} __attribute__ ((packed)) le_ext_advertising_info;



struct hci_request ble_hci_request(uint16_t ocf, int clen, void *status, void *cparam) {
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

int open_hci_device() {
    int device = hci_open_dev(0);
    if (device < 0) {
        perror("Failed to open HCI device.");
    } else {
        printf("Using hci0\n");
    }
    return device;
}

int set_scan_parameters(int device) {
    int status;
    le_set_extended_scan_parameters_cp ext_scan_params_cp = {
        .own_bdaddr_type = 0x00,
        .filter = 0x00,
        .scanning_phy = BT_HCI_LE_EXT_SCAN_PHY_1M,
        .type = 0x01,
        .interval = htobs(0x0010),
        .window = htobs(0x0010)
    };
    struct hci_request scan_params_rq = ble_hci_request(0x0041, sizeof(ext_scan_params_cp), &status, &ext_scan_params_cp);
    int ret = hci_send_req(device, &scan_params_rq, 1000);
    if (ret < 0) {
        perror("Failed to set scan parameters data.");
    }
    return ret;
}

int set_event_mask(int device) {
    int status;
    uint8_t le_event_mask[8] = {0x1F, 0x1F, 0x1F, 0x1F, 0x1F, 0x1F, 0x1F, 0x1F};
    struct hci_request set_mask_rq = ble_hci_request(0x0001, sizeof(le_event_mask), &status, le_event_mask);
    int ret = hci_send_req(device, &set_mask_rq, 1000);
    if (ret < 0) {
        perror("Failed to set event mask.");
    }
    return ret;
}

int enable_scan(int device, uint8_t enable) {
    int status;
    le_set_extended_scan_enable_cp ext_scan_cp = {
        .enable = enable,
        .filter_dup = 0x00,
        .duration = htobs(0x0000),
        .period = htobs(0x0000)
    };
    struct hci_request enable_adv_rq = ble_hci_request(0x0042, sizeof(ext_scan_cp), &status, &ext_scan_cp);
    int ret = hci_send_req(device, &enable_adv_rq, 10);
    if (ret < 0) {
        perror("Failed to enable/disable scan.");
    }
    return ret;
}

void str2uint(const char *str, uint8_t addr[6]) {
    int values[6];
    if (sscanf(str, "%2x:%2x:%2x:%2x:%2x:%2x", 
               &values[5], &values[4], &values[3], 
               &values[2], &values[1], &values[0]) == 6) {
        for (int i = 0; i < 6; i++) {
            addr[i] = (uint8_t)values[i];
        }
    } else {
        // Handle error: invalid address format
        fprintf(stderr, "Invalid Bluetooth address format: %s\n", str);
    }
}

int pa_create_sync(int device){
    int status;
    le_pa_create_sync create_scan_cp = {
        .options = 0x00,
        .sid = broadcasters[0].sid,
        .addr_type = broadcasters[0].addr_type,
        .skip = htobs(0x0000),
        .sync_timeout = htobs(0x0258),
        .sync_cte_type = 0x00
    };
    str2uint(broadcasters[0].baddr, create_scan_cp.addr);
    
    struct hci_request scan_params_rq = ble_hci_request(0x0044, sizeof(create_scan_cp), &status, &create_scan_cp);
    int ret = hci_send_req(device, &scan_params_rq, 1000);
    if (ret < 0) {
        perror("Failed to set periodic create sync");
    }
    return ret;
}

static void print_uuid16_list(const char *label, const void *data,
                              uint8_t data_len)
{
    uint8_t count = data_len / sizeof(uint16_t);
    unsigned int i;

    printf("%s: %u entr%s", label, count, count == 1 ? "y" : "ies");

    for (i = 0; i < count; i++) {
        uint16_t uuid = get_le16(data + (i * 2));
        printf("UUID: 0x%4.4x\n", uuid);
        if (uuid == 0x1852){
            printf("Broadcast Audio Announcement Found\n");
        }
    }
}
int device_found = 0;
static void eir_parse_name(uint8_t *eir, size_t eir_len,
                           char *buf, size_t buf_len)
{
    size_t offset = 0;

    // Ensure buffer is cleared before use
    memset(buf, 0, buf_len);

    while (offset < eir_len) {
        uint8_t field_len = eir[offset];
        size_t name_len;

        // Check for the end of EIR
        if (field_len == 0)
            break;

        if (offset + field_len > eir_len)
            goto failed;

        switch (eir[offset + 1]) {
            case EIR_NAME_SHORT:
            case EIR_NAME_COMPLETE:
                name_len = field_len - 1; // Exclude the type byte

                // If the name length exceeds the buffer, truncate
                if (name_len >= buf_len)
                    name_len = buf_len - 1;

                memcpy(buf, &eir[offset + 2], name_len);
                buf[name_len] = '\0'; // Ensure null-terminated string
                return;

            case BT_EIR_UUID16_ALL:
                uint8_t count = (field_len - 1) / sizeof(uint16_t);
                unsigned int i;
                printf("%s: %u entr%s", "16-bit Service UUIDs (complete)", count, count == 1 ? "y" : "ies");

                for (i = 0; i < count; i++) {
                    uint16_t uuid = get_le16(&eir[offset + 2] + (i * 2));
                    printf("UUID: 0x%4.4x\n", uuid);
                    if (uuid == 0x1852){
                        printf("Broadcast Audio Announcement Found\n");
                        device_found = 1;
                    }
                }
                break;
        }

        offset += field_len + 1;
    }

failed:
    snprintf(buf, buf_len, "(unknown)");
}

void scan_for_advertisements(int device) {
    // Set up the HCI filter to capture LE Meta Events
    struct hci_filter nf;
    hci_filter_clear(&nf);
    hci_filter_set_ptype(HCI_EVENT_PKT, &nf);
    hci_filter_set_event(EVT_LE_META_EVENT, &nf);

    if (setsockopt(device, SOL_HCI, HCI_FILTER, &nf, sizeof(nf)) < 0) {
        hci_close_dev(device);
        perror("Could not set socket options\n");
        return;
    }

    uint8_t buf[HCI_MAX_EVENT_SIZE];
    int len;

    unsigned now = (unsigned)time(NULL);
    unsigned last_detection_time = now;
    int count = 0;
    char baddr[18];
    char name[30];
    
    
    // Keep scanning until we see nothing for 10 secs or we have seen lots of advertisements
    while (last_detection_time - now < 10 && count < 1000) {
        len = read(device, buf, sizeof(buf));
        if (len < HCI_EVENT_HDR_SIZE) continue;  // Skip if the read data is too short

        count++;
        last_detection_time = (unsigned)time(NULL);
        
        evt_le_meta_event *meta_event = (evt_le_meta_event*)(buf + HCI_EVENT_HDR_SIZE + 1);
        if (meta_event->subevent == EVT_EXT_LE_ADVERTISING_REPORT) {
            uint8_t reports_count = meta_event->data[0];
            uint8_t *offset = meta_event->data + 1;
            device_found = 0;
            while (reports_count--) {
                le_ext_advertising_info *info = (le_ext_advertising_info *)offset;
                
                ba2str(&(info->addr), baddr);
                // Print the contents of the info structure
                printf("LE Extended Advertising Info:\n");
                eir_parse_name(info->data, info->data_len, name, sizeof(name));
                
                printf("Name: %s\n", name);
                printf("Address Type: 0x%2.2x\n", info->addr_type);
                char addr[18];
                printf("BAddress: %s\n", baddr);
                printf("SID: 0x%02x\n", info->sid);
                printf("TX power: %d dBm\n", info->tx_power);
                printf("RSSI: %d dBm\n", info->rssi);
                if (device_found){
                    // Check if the address is already present
                    int is_duplicate = 0;
                    for (int i = 0; i < broadcaster_count; i++) {
                        if (strcmp(broadcasters[i].baddr, baddr) == 0) {
                            is_duplicate = 1;
                            break;
                        }
                    }
                    if (is_duplicate) {
                        continue; // Skip if the address is already present
                    }
                    printf("New Broadcaster Found\n");
                    // Save the broadcaster information
                    strncpy(broadcasters[broadcaster_count].name, name, sizeof(broadcasters[broadcaster_count].name));
                    strncpy(broadcasters[broadcaster_count].baddr, baddr, sizeof(broadcasters[broadcaster_count].baddr));
                    broadcasters[broadcaster_count].addr_type = info->addr_type;
                    broadcasters[broadcaster_count].sid = info->sid;
                    broadcaster_count++;
                }
                offset += sizeof(le_ext_advertising_info) + info->data_len - 1;
            }
        }

        now = (unsigned)time(NULL);
    }
}

int main() {
    int hci = 1;
    int device = hci_open_dev(hci);
    if (device < 0) {
        perror("Failed to open HCI device.");
    } 
    else {
        printf("Using hci %d\n", hci);
    }

    if (set_scan_parameters(device) < 0) {
        hci_close_dev(device);
        return 0;
    }

    if (set_event_mask(device) < 0) {
        hci_close_dev(device);
        return 0;
    }

    if (enable_scan(device, 0x01) < 0) {
        hci_close_dev(device);
        return 0;
    }

	struct hci_filter nf;
	hci_filter_clear(&nf);
	hci_filter_set_ptype(HCI_EVENT_PKT, &nf);
	hci_filter_set_event(EVT_LE_META_EVENT, &nf);
	if ( setsockopt(device, SOL_HCI, HCI_FILTER, &nf, sizeof(nf)) < 0 ) {
		hci_close_dev(device);
		perror("Could not set socket options\n");
		return 0;
	}

    scan_for_advertisements(device);

    
    // Print all the broadcaster information at the end
    printf("\nList of all new Broadcasters Found:\n");
    for (int i = 0; i < broadcaster_count; i++) {
        printf("Broadcaster %d:\n", i + 1);
        printf("Name: %s\n", broadcasters[i].name);
        printf("BAddress: %s\n", broadcasters[i].baddr);
        printf("Address Type: 0x%2.2x\n", broadcasters[i].addr_type);
        printf("SID: 0x%02x\n", broadcasters[i].sid);
    }

    pa_create_sync(device);
    /*
    if (pa_create_sync(device) < 0) {
        hci_close_dev(device);
        return 0;
    }    
    */
    enable_scan(device, 0x00);
    hci_close_dev(device);
    return 0;
}
