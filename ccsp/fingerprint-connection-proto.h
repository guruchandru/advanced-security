// This file is Confidential Information of CUJO LLC.
// Copyright (c) 2022 CUJO LLC. All rights reserved.

#ifndef CUJO_FINGERPRINT_CONNECTION_PROTO_H
#define CUJO_FINGERPRINT_CONNECTION_PROTO_H

#include <net/if.h>
#include <netinet/if_ether.h>
#include <pcap/pcap.h>
#include <stdbool.h>
#include <stdint.h>

// All structures here are packed as they represent on-the-wire protocol data.
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpacked"

enum cujo_fpc_tag_list {
	// v1.0

	// From CUJO agent.
	CUJO_FPC_HELLO, // Empty event, sent from CUJO agent after it connects via UNIX socket.
	// To CUJO agent.
	CUJO_FPC_PROTOCOL_VERSION, // Protocol version sent as an answer to HELLO.
	CUJO_FPC_WIFI_DATA_BATCH_EVENT,
	CUJO_FPC_WIFI_RADIO_UPDATE_EVENT,
	CUJO_FPC_WIFI_STATION_UPDATE_EVENT,

	// v2.0

	// Some overall operational notes about v2.0:
	//
	// For now it is assumed that the Cujo agent will only want to collect
	// for one (interface, MAC) combination at a time, so normally it should
	// never send L1_COLLECTION_START while a collection is ongoing.
	//
	// However, if the Wi-Fi data agent never sends L1_COLLECTION_DONE, the
	// Cujo agent will eventually time out and send L1_COLLECTION_START
	// regardless, in the hopes that this will "reset" the state of the
	// Wi-Fi data agent.
	//
	// In general, if the Wi-Fi data agent receives L1_COLLECTION_START
	// unexpectedly, it should assume that it is out of sync with the Cujo
	// agent and do its best to abort any ongoing collection in favour of
	// what the latest L1_COLLECTION_START message requested.

	// From CUJO agent.
	CUJO_FPC_L1_COLLECTION_START,
	// To CUJO agent.
	CUJO_FPC_TEMPERATURE_DATA_EVENT,
	CUJO_FPC_CFO_DATA_EVENT,
	CUJO_FPC_CSI_DATA_EVENT,
	CUJO_FPC_CSI_AND_CFO_DATA_EVENT,
	CUJO_FPC_L1_COLLECTION_DONE,
};

// Shared TLV structure used for all messages.
struct cujo_fpc_tlv {
	uint16_t tag; // enum cujo_fpc_tag_list
	uint16_t len;
	uint8_t data[];
};

///////////////////
// From CUJO agent.
///////////////////

// CUJO_FPC_HELLO is empty so there is no structure for it here.

// Mapped from enum cujo_fpc_wifi_mode, see below.
enum cujo_fpc_wifi_bandwidth {
	CUJO_FPC_WIFI_BW_20 = 0,
	CUJO_FPC_WIFI_BW_40 = 1,
	CUJO_FPC_WIFI_BW_80 = 2,
	CUJO_FPC_WIFI_BW_160 = 3,
	CUJO_FPC_WIFI_BW_80_80 = 4,
};

// Command structure for CUJO_FPC_L1_COLLECTION_START.
//
// Triggers collection of temperature, CFO, and CSI data for a given VAP and
// MAC. CUJO_FPC_TEMPERATURE_DATA_EVENT, CUJO_FPC_CFO_DATA_EVENT, and
// CUJO_FPC_CSI_DATA_EVENT or CUJO_FPC_CSI_AND_CFO_DATA_EVENT (up to a limit)
// should be sent to the CUJO agent until timeout, at which point
// CUJO_FPC_L1_COLLECTION_DONE should be sent.
//
// If the MAC disconnects, the collection should immediately be terminated with
// CUJO_FPC_L1_COLLECTION_DONE, which should be sent prior to any
// CUJO_FPC_WIFI_RADIO_UPDATE_EVENT indicating the disconnection.
struct cujo_fpc_l1_collection_start {
	uint32_t vap_index; // Per-device unique VAP index, might be if_index.
	struct ether_addr mac; // VAP MAC address for this capture.

	// Bandwidth for CFO and CSI capture, enum cujo_fpc_wifi_bandwidth.
	uint16_t bandwidth;

	// Max amount of time to send data for, in seconds.
	uint32_t timeout_secs;

	// Rate of CFO and CSI collection, in hertz. Does not have to match the
	// rate at which CUJO_FPC_CFO_DATA_EVENT and CUJO_FPC_CSI_DATA_EVENT are
	// sent, as multiple readings can be packed into each event.
	uint32_t l1_rate_hz;

	// Interval for CUJO_FPC_TEMPERATURE_DATA_EVENT sends, in seconds.
	uint32_t temperature_interval_secs;

	// Max number of CSI readings to send. Note, this does not limit the
	// number of CUJO_FPC_CSI_DATA_EVENT and CUJO_FPC_CSI_AND_CFO_DATA_EVENT
	// events, but the number of total readings across all such events,
	// combined across the two event types.
	//
	// Any readings beyond this limit are discarded by the CUJO agent.
	uint32_t max_csi_readings;
} __attribute__((packed));

/////////////////
// To CUJO agent.
/////////////////

// Data for CUJO_FPC_PROTOCOL_VERSION.
//
// List of known versions:
//
// - major=1, minor=0: corresponds to "v1.0" in enum cujo_fpc_tag_list
// - major=2, minor=0: corresponds to "v2.0" in enum cujo_fpc_tag_list
//
// If an unknown version is received, the CUJO agent will immediately close the
// receiving socket.
struct cujo_fpc_proto_version {
	uint8_t major;
	uint8_t minor;
};

enum cujo_fpc_event_type {
	CUJO_FPC_CONNECT = 0,
	CUJO_FPC_DISCONNECT = 1,
	CUJO_FPC_ONGOING = 2,
};

enum cujo_fpc_wifi_mode {
	CUJO_FPC_WIFI_MODE_AUTO = 0,
	CUJO_FPC_WIFI_MODE_11A = 1,
	CUJO_FPC_WIFI_MODE_11B = 2,
	CUJO_FPC_WIFI_MODE_11G = 3,
	CUJO_FPC_WIFI_MODE_11G_ONLY = 4,
	CUJO_FPC_WIFI_MODE_11NA_HT20 = 5,
	CUJO_FPC_WIFI_MODE_11NG_HT20 = 6,
	CUJO_FPC_WIFI_MODE_11NA_HT40 = 7,
	CUJO_FPC_WIFI_MODE_11NG_HT40PLUS = 8,
	CUJO_FPC_WIFI_MODE_11NG_HT40MINUS = 9,
	CUJO_FPC_WIFI_MODE_11NG_HT40 = 10,
	CUJO_FPC_WIFI_MODE_11AC_VHT20 = 11,
	CUJO_FPC_WIFI_MODE_11AC_VHT20_2G = 12,
	CUJO_FPC_WIFI_MODE_11AC_VHT40 = 13,
	CUJO_FPC_WIFI_MODE_11AC_VHT40PLUS_2G = 14,
	CUJO_FPC_WIFI_MODE_11AC_VHT40MINUS_2G = 15,
	CUJO_FPC_WIFI_MODE_11AC_VHT40_2G = 16,
	CUJO_FPC_WIFI_MODE_11AC_VHT80 = 17,
	CUJO_FPC_WIFI_MODE_11AC_VHT80_2G = 18,
	CUJO_FPC_WIFI_MODE_11AC_VHT160 = 19,
	CUJO_FPC_WIFI_MODE_11AC_VHT80_80 = 20,
	CUJO_FPC_WIFI_MODE_11AXA_HE20 = 21,
	CUJO_FPC_WIFI_MODE_11AXG_HE20 = 22,
	CUJO_FPC_WIFI_MODE_11AXA_HE40 = 23,
	CUJO_FPC_WIFI_MODE_11AXG_HE40PLUS = 24,
	CUJO_FPC_WIFI_MODE_11AXG_HE40MINUS = 25,
	CUJO_FPC_WIFI_MODE_11AXG_HE40 = 26,
	CUJO_FPC_WIFI_MODE_11AXA_HE80 = 27,
	CUJO_FPC_WIFI_MODE_11AXG_HE80 = 28,
	CUJO_FPC_WIFI_MODE_11AXA_HE160 = 29,
	CUJO_FPC_WIFI_MODE_11AXA_HE80_80 = 30,
};

enum cujo_fpc_wifi_freq {
	CUJO_FPC_WIFI_FREQ_2_4 = 0,
	CUJO_FPC_WIFI_FREQ_5 = 1,
	CUJO_FPC_WIFI_FREQ_6 = 2,
};

// When station associates to a VAP or disassociates from it this event will be
// sent via CUJO_WIFI_RADIO_UPDATE_EVENT. It contains information about the
// VAP and phy radio interface that it operates on.
#define CUJO_FPC_ESSID_MAX_SIZE 32
struct cujo_fpc_radio_event {
	enum cujo_fpc_event_type event_type;
	uint64_t timestamp_ms;
	char if_name[IF_NAMESIZE];
	uint32_t vap_index; // Per-device unique VAP index, might be if_index.
	enum cujo_fpc_wifi_freq freq_band;
	uint32_t channel;
	enum cujo_fpc_wifi_mode operating_mode;
	struct ether_addr bssid;
	uint8_t essid[CUJO_FPC_ESSID_MAX_SIZE];
	uint8_t essid_length;
	struct ether_addr station_mac; // Station MAC related to this event.
	// After this event is sent, one or multiple
	// CUJO_WIFI_STATION_UPDATE_EVENT events will be sent listing currently
	// connected stations. There can be one station event per VAP. The
	// following counter informs the receiver how many station update event
	// packets to expect.
	uint8_t station_update_event_count;
} __attribute__((packed));

struct cujo_fpc_assoc_station_info {
	struct ether_addr mac; // The MAC address of an associated device.
	char if_name[IF_NAMESIZE];
	enum cujo_fpc_wifi_mode operating_mode;
} __attribute__((packed));

// When station associates to a VAP or disassociates from it this event will be
// sent via CUJO_WIFI_STATION_UPDATE_EVENT. It contains information about all
// associated stations.
struct cujo_fpc_wifi_station_event {
	enum cujo_fpc_event_type event_type;
	uint64_t timestamp_ms;
	uint32_t vap_index; // Per-device unique VAP index, might be if_index.
	uint8_t essid[CUJO_FPC_ESSID_MAX_SIZE];
	uint8_t essid_length;
	uint32_t assoc_station_count;
	struct cujo_fpc_assoc_station_info assoc_station_info[];
} __attribute__((packed));

struct cujo_fpc_wifi_pcap {
	struct pcap_pkthdr header; // header->caplen specifies the length of data.
	uint8_t has_radiotap_header; // data contains radiotap header.
	uint8_t data[];
} __attribute__((packed));

// Packet captures on a particular VAP interface to be sent via
// CUJO_WIFI_DATA_BATCH_EVENT.
struct cujo_fpc_wifi_data_batch_event {
	uint64_t timestamp_ms;
	uint32_t vap_index; // Per-device unique VAP index, might be ifindex.
	struct ether_addr mac; // VAP MAC address for this capture.
	uint32_t wifi_captures_count;
	// This is uint8_t because struct cujo_fpc_wifi_pcap has variable length.
	uint8_t wifi_captures[];
} __attribute__((packed));

// Temperature data to be sent via CUJO_FPC_TEMPERATURE_DATA_EVENT.
//
// Contains raw temperature readings from platform-specific sensors. On any
// given platform this array should always have the same length, and the
// temperature data should always be ordered in the same way.
//
// The sensors to be read and the order in which their readings are
// delivered must be agreed ahead of time, so that the data can be
// interpreted in the cloud.
struct cujo_fpc_temperature_data_event {
	uint64_t timestamp_ms;
	uint32_t temperatures_count;
	int32_t temperatures[];
} __attribute__((packed));

#define CUJO_FPC_MAX_ANTENNAE 8

struct cujo_fpc_csi_metadata {
	uint8_t bw_mode; // Bandwidth and mode corresponding to cujo_fpc_wifi_mode
	uint8_t num_rx_antennae; // Number of antennas used to receive the frame
	uint8_t num_tx_streams; // Number of streams used to transmit the frame
	int32_t rssi[CUJO_FPC_MAX_ANTENNAE]; // RSSI on each antenna
	uint16_t router_bw; // Router BW [MHz] at the time of capture
	uint16_t station_bw; // Station BW [MHz] at the time of capture
	uint16_t tones_mask; // Valid tones in payload
	uint32_t num_subcarriers; // Number of subcarriers in the payload so that information can be used in conjunction with the number of streams to fully decode valid regions
	uint8_t decimation_factor; // The degree to which CSI matrix is decimated in terms of number of subcarriers present
	uint32_t channel; // Primary Channel of received frame
} __attribute__((packed));

struct cujo_fpc_cfo_reading {
	uint64_t timestamp_ms;
	int32_t cfo;
} __attribute__((packed));

// Carrier frequency offset (CFO) data sent via CUJO_FPC_CFO_DATA_EVENT.
struct cujo_fpc_cfo_data_event {
	uint32_t vap_index; // Per-device unique VAP index, might be ifindex.
	struct ether_addr mac; // VAP MAC address for this capture.
	uint32_t cfo_count;
	struct cujo_fpc_cfo_reading cfo[];
} __attribute__((packed));

struct cujo_fpc_csi_and_cfo_reading {
	uint64_t timestamp_ms;
	uint32_t data_len;
	struct cujo_fpc_csi_metadata csi_metadata;
	int32_t cfo;
	uint8_t data[];
} __attribute__((packed));

// Channel state information (CSI) data sent via CUJO_FPC_CSI_AND_CFO_DATA_EVENT.
//
// The data is treated as a raw byte stream without any interpretation.
struct cujo_fpc_csi_and_cfo_data_event {
	uint32_t vap_index; // Per-device unique VAP index, might be ifindex.
	struct ether_addr mac; // VAP MAC address for this capture.
	uint32_t csi_count; // Number of readings.
	// This is uint8_t because struct cujo_fpc_csi_and_cfo_reading has variable length.
	uint8_t csi[];
} __attribute__((packed));

struct cujo_fpc_csi_reading {
	uint64_t timestamp_ms;
	uint32_t data_len;
	struct cujo_fpc_csi_metadata csi_metadata;
	uint8_t data[];
} __attribute__((packed));

// Channel state information (CSI) data sent via CUJO_FPC_CSI_DATA_EVENT.
//
// The data is treated as a raw byte stream without any interpretation.
struct cujo_fpc_csi_data_event {
	uint32_t vap_index; // Per-device unique VAP index, might be ifindex.
	struct ether_addr mac; // VAP MAC address for this capture.
	uint32_t csi_count; // Number of readings.
	// This is uint8_t because struct cujo_fpc_csi_reading has variable length.
	uint8_t csi[];
} __attribute__((packed));

// To be sent after all data events related to the collection have been sent.
// Normally, this implies that the collection timeout given in
// CUJO_FPC_L1_COLLECTION_START has expired, but it could also be that the
// collection was prematurely terminated e.g. due to device disconnection.
struct cujo_fpc_l1_collection_done {
	uint32_t vap_index; // Per-device unique VAP index, might be ifindex.
	struct ether_addr mac; // VAP MAC address for this capture.
} __attribute__((packed));

#pragma GCC diagnostic pop

#endif /* CUJO_FINGERPRINT_CONNECTION_PROTO_H */
