#ifndef CUJOAGENT_DCL_API_H
#define CUJOAGENT_DCL_API_H

#include <endian.h>
#include <inttypes.h>
#include <libgen.h>
#include <limits.h>

#include <netinet/ether.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <sys/timerfd.h>
#include <sys/uio.h>
#include <sys/un.h>

/* Legacy ccsp_trace macros replaced by advsec_compat_types.h */
/* #include "ccsp_trace.h" */
#include "secure_wrapper.h"
#include "user_base.h"

#include <rbus.h>
#include "wifi_webconfig.h"

#include "fingerprint-connection-proto.h"

#define VERSION_MAJOR                   2
#define VERSION_MINOR                   0

#define RBUS_CONSUMER_NAME              "wifi-data-collection-consumer"

#ifdef NON_PRIVILEGED
#define CCSP_CUJOAGENT_SOCK_PATH        "/tmp/wifi.sock"
#else
#define CCSP_CUJOAGENT_SOCK_PATH        "/var/run/cujo/wifi.sock"
#endif

#define PRIVATE_BRIDGE                  "brlan0"
#if defined(INTEL_PUMA7) || defined(_SR213_PRODUCT_REQ_)
#define WIFI_WEBCONFIG_INIT_DATA_NAMESPACE WIFI_WEBCONFIG_INIT_DML_DATA
#else
#define WIFI_WEBCONFIG_INIT_DATA_NAMESPACE WIFI_WEBCONFIG_INIT_DATA
#endif

#define WIFI_RADIO_MIN_TEMPERATURE_INTERVAL 5000
#define WIFI_LEVL_MIN_SOUNDING_DURATION     1000

#define DEV_WIFI_EVENTS_RADIO_TEMPERATURE                                          \
  "Device.WiFi.Events.Radio.%d.Temperature"
#define DEV_WIFI_EVENTS_VAP_FRAMES_MGMT                                            \
  "Device.WiFi.Events.VAP.%d.Frames.Mgmt"

/* Defines moved from common to all wifi_base.h to non staged wifi_levl.h */
#ifndef WIFI_LEVL_CSI_DATAFIFO
/* Properties to setup the collection */
#define WIFI_LEVL_CLIENTMAC             "Device.WiFi.X_RDK_CSI_LEVL.clientMac"
#define WIFI_LEVL_NUMBEROFENTRIES       "Device.WiFi.X_RDK_CSI_LEVL.maxNumberCSIClients"
#define WIFI_LEVL_SOUNDING_DURATION     "Device.WiFi.X_RDK_CSI_LEVL.Duration"
/* Events to listen to */
#define WIFI_LEVL_CSI_DATAFIFO          "Device.WiFi.X_RDK_CSI_LEVL.datafifo"
#endif

#define WIFI_CSI_DATA_FIFO_PATH         "/tmp/csi_levl_pipe"

/* Assuming the following CSI payload format:
 * | LABEL + "\0" | TOTAL LENGTH | TIMESTAMP | CSI CLIENT COUNT |
 * (CSI CLIENT COUNT) x
 * | CSI CLIENT MAC | CSI CLIENT DATA LENGTH | CSI CLIENT DATA |
 */
#define WIFI_CSI_DATA_LABEL                     "CSI"
#define WIFI_CSI_DATA_LABEL_LENGTH              (sizeof(WIFI_CSI_DATA_LABEL) - 1)
#define WIFI_CSI_PAYLOAD_HEADER_SIZE                                           \
  (WIFI_CSI_DATA_LABEL_LENGTH + 1 + sizeof(unsigned int) + sizeof(time_t) +    \
   sizeof(unsigned int))
#define WIFI_CSI_CLIENT_HEADER_SIZE                                            \
  (sizeof(mac_address_t) + sizeof(unsigned int))

/* We can't control the rate at which the lower wifi layers collect the CSI.
 * The value, of course, is platform dependent, therefore, we would not want to
 * rely on any of the HAL defines, not to say that most likely we would be
 * encouraged not to do so. To make our assumptions on the interval visible, use
 * Platform default interval. */
#define DCL_CSI_INTERVAL_MS     MIN_CSI_INTERVAL

/* The agent has this parameter configurable, make sure it matches. */
#define DCL_MAX_CSI_CLIENTS     1

#define MSECS_PER_SEC           1000
#define USECS_PER_MSEC          1000
#define NSECS_PER_MSEC          1000000

#define EPOLL_TIMEOUT_MS        100
#define MAX_EPOLL_EVENTS        2
#define MAX_SOCK_RECV_BUFFER    1024

#define MAC_DOT_FMT             "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx"
#define MAX_MAC_STR_LEN         17

#define FCTL_FTYPE              0x000c
#define FCTL_STYPE              0x00f0

#define STYPE_ASSOC_REQ         0x0000
#define STYPE_ASSOC_RESP        0x0010
#define STYPE_REASSOC_REQ       0x0020
#define STYPE_REASSOC_RESP      0x0030
#define STYPE_PROBE_REQ         0x0040
#define STYPE_PROBE_RESP        0x0050
#define STYPE_BEACON            0x0080
#define STYPE_ATIM              0x0090
#define STYPE_DISASSOC          0x00A0
#define STYPE_AUTH              0x00B0
#define STYPE_DEAUTH            0x00C0
#define STYPE_ACTION            0x00D0

#define FC_GET_TYPE(fc)         (((fc) & (FCTL_FTYPE)) >> 2)
#define FC_GET_STYPE(fc)        (((fc) & (FCTL_STYPE)) >> 4)

#define EMPTY_RT_LEN            0x08

typedef enum {
  NOTIFY_NONE,
  NOTIFY_WEBCONFIG_INIT_READY,
  NOTIFY_RADIO_DATA_READY,
  NOTIFY_RADIO_DATA_SENT,
  NOTIFY_STATION_DATA_READY,
  NOTIFY_STATION_DATA_SENT,
  NOTIFY_BATCH_DATA_READY,
  NOTIFY_BATCH_DATA_SENT,
  NOTIFY_CSI_CFO_READY,
  NOTIFY_CSI_CFO_SENT,
  NOTIFY_TEMPERATURE_READY,
  NOTIFY_TEMPERATURE_SENT,
  NOTIFY_L1_COLLECTION_DONE_READY,
  NOTIFY_L1_COLLECTION_DONE_SENT,
  NOTIFY_SOCKET_THREAD_STOP,
  NOTIFY_SOCKET_THREAD_RETURN,
  NOTIFY_L1_COLLECTION_THREAD_STOP,
  NOTIFY_L1_COLLECTION_THREAD_RETURN,
  NOTIFY_FIFO_THREAD_STOP,
  NOTIFY_FIFO_THREAD_RETURN,
} cujoagent_notify_t;

/* Supported "to CUJO agent" event tags */
#define MAX_TO_CUJO_TLVS 6
typedef struct {
  enum cujo_fpc_tag_list event_tag;
  cujoagent_notify_t notify_ready;
  cujoagent_notify_t notify_sent;
} __attribute__((__packed__)) cujoagent_tlv_notify_lut_t;

typedef enum {
  consumer_event_type_webconfig,
  consumer_event_type_mgmt_frame,
  consumer_event_type_l1,
  consumer_event_type_temperature,
} cujoagent_consumer_event_type_t;

typedef enum {
  consumer_event_webconfig_init,
  consumer_event_webconfig_set_data,
  consumer_event_webconfig_get_data,
  consumer_event_probe_req,
  consumer_event_auth,
  consumer_event_assoc_req,
  consumer_event_reassoc_req,
  consumer_event_l1_csi_data,
  consumer_event_l1_done,
  consumer_event_radio_temperature,
} cujoagent_consumer_event_subtype_t;

typedef struct {
  cujoagent_consumer_event_type_t event_type;
  cujoagent_consumer_event_subtype_t event_subtype;
  void *msg;
  size_t mlen;
} __attribute__((__packed__)) cujoagent_wifi_consumer_event_t;

typedef struct {
  unsigned int radio_index;
  unsigned int temperature;
} __attribute__((__packed__)) cujoagent_radio_temperature_context_t;

typedef struct {
  unsigned int *temperature_data;
  size_t data_size;
  unsigned int collected_count;
} __attribute__((__packed__)) cujoagent_temperature_collection_context_t;

typedef struct {
  struct cujo_fpc_tlv *tlv;
  size_t size;
} __attribute__((__packed__)) cujoagent_tlv_context_t;

typedef struct consumer cujoagent_wifi_consumer_t;
typedef struct l1_collector cujoagent_l1_collector_t;

struct l1_collector {
  int notification;
  int notification_ack;
  int timer;
  struct cujo_fpc_l1_collection_start start;
  cujoagent_wifi_consumer_t *consumer;
};

struct consumer {
  pthread_mutex_t lock;
  pthread_cond_t cond;

  queue_t *queue;
  bool queue_wakeup;

  wifi_global_config_t config;
  wifi_hal_capability_t hal_cap;
  rdk_wifi_radio_t radios[MAX_NUM_RADIOS];

  webconfig_t webconfig;
  rbusHandle_t rbus_handle;
  unsigned int vap_subs_count;
  unsigned int *vap_subs_indexes;
  rbusEventSubscription_t *subscriptions;
  unsigned int subscriptions_count;
  rbusEventSubscription_t *raw_data_subscriptions;
  unsigned int raw_data_subscriptions_count;
  rbusEventSubscription_t *on_demand_subscriptions;
  unsigned int on_demand_subscriptions_count;

  int sock_fd;
  int fifo_fd;

  /* Short lived epoll and event fd's for:
   *   1) the consumer queue to notify the main thread that
   *      the initial webconfig processing has finished. */
  int misc_epoll;
  int misc_notification;

  /* Consumer epoll fd to wait for notifications:
   *   1) from the comms socket loop that the sending of the TLV has finished
   *   2) from the comms socket loop that it is going to return
   *   3) from the L1 collection thread that it is going to return
   *   4) from the fifo loop that it is going to return
   * Listens for eventfd's:
   *   1) comms_notification_ack
   *   2) collector->notification_ack
   *   3) fifo_notification_ack */
  int queue_epoll;

  /* Comms socket loop epoll fd to wait for notifications:
   *   1) from the consumer loop that the TLV data is ready for sending
   *   2) for the comms socket loop to return
   *   3) for the comms socket loop to send/receive the data to/from the agent
   * Listens for eventfd's:
   *   1) comms_notification
   * Listens for socket fd's:
   *   1) sock_fd */
  int comms_epoll;

  /* Comms socket loop eventfd for:
   *   1) the consumer queue to notify the comms socket loop
   *      that the TLV data is ready for sending
   *   2) notifying the comms socket loop to return */
  int comms_notification;

  /* Comms socket loop eventfd for:
   *   1) the comms socket loop to notify the consumer queue
   *      that the sending of the TLV has finished.
   *   2) notifying that the comms socket loop is going to return */
  int comms_notification_ack;

  /* Fifo loop epoll fd to wait for notifications:
   *   1) for the fifo loop to return
  *   2) for fifo loop to read CSI/CFO data from fifo pipe written by backend
   * Listens for eventfd's:
   *   1) fifo_notification
   * Listens for fifo fd's:
   *   1) fifo_fd */
  int fifo_epoll;

  /* Fifo loop eventfd for:
   *   1) notifying the fifo loop to return */
  int fifo_notification;

  /* Fifo eventfd for:
   *   1) notifying that the fifo loop is going to return */
  int fifo_notification_ack;

  pthread_mutex_t l1_lock;
  bool disable_l1_collection;
  cujoagent_l1_collector_t *l1_collections[DCL_MAX_CSI_CLIENTS];
  cujoagent_temperature_collection_context_t tcollect_ctx;

  bool comms_ready;
  cujoagent_tlv_context_t tlv_ctx;
  cujoagent_tlv_notify_lut_t tlv_notify_lut[MAX_TO_CUJO_TLVS];

  bool exit_consumer;
};

extern cujoagent_wifi_consumer_t *g_cujoagent_dcl;

int cujoagent_wifidatacollection_init(cujoagent_wifi_consumer_t *consumer);
int cujoagent_wifidatacollection_deinit(cujoagent_wifi_consumer_t *consumer, bool do_rbus_event_unsubscribe);
#endif
