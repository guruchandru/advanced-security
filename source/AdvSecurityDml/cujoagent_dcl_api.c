#include "cujoagent_dcl_api.h"

static int cujoagent_socket_init(cujoagent_wifi_consumer_t *consumer) {
  char *msg = NULL;

  char *socket_path = NULL;
  int cmd = 0;

  consumer->sock_fd = -1;
  int count = 0;
  struct sockaddr_un saddr = {.sun_family = AF_UNIX};
  size_t saddr_path_size = sizeof(saddr.sun_path);

  socket_path = strdup(CCSP_CUJOAGENT_SOCK_PATH);
  if (socket_path == NULL) {
    msg = "Socket path strdup failed";
    goto err;
  }

  cmd = v_secure_system("mkdir -p %s", dirname(socket_path));
  free(socket_path);

  if (cmd != 0) {
    msg = "Failed to create parent directory for the socket path";
    goto err;
  }

  consumer->sock_fd = socket(AF_UNIX, SOCK_DGRAM, 0);
  if (consumer->sock_fd == -1) {
    msg = "Failed to open unix socket";
    goto err;
  }

  if (remove(CCSP_CUJOAGENT_SOCK_PATH) == -1 && errno != ENOENT) {
    msg = "Failed to remove socket filepath";
    goto err;
  }

  count = snprintf(saddr.sun_path, saddr_path_size, "%s", CCSP_CUJOAGENT_SOCK_PATH);
  if (count < 0 || count >= (int)saddr_path_size) {
    msg = "Socket filepath doesn't fit into buffer";
    goto err;
  }

  if (bind(consumer->sock_fd, (struct sockaddr *)&saddr,
           sizeof(struct sockaddr_un)) == -1) {
    msg = "Failed to bind to the socket";
    goto err;
  }

  return 0;

err:
  CcspTraceError(("%s\n", msg));
  return -1;
}

static int cujoagent_notify_events_init(cujoagent_wifi_consumer_t *consumer) {

  int *epollfds[4] = {
      &consumer->misc_epoll,
      &consumer->queue_epoll,
      &consumer->comms_epoll,
      &consumer->fifo_epoll,
  };

  int *eventfds[5] = {
      &consumer->misc_notification,
      &consumer->comms_notification,
      &consumer->comms_notification_ack,
      &consumer->fifo_notification,
      &consumer->fifo_notification_ack,
  };

  for (unsigned int i = 0; i < sizeof(epollfds) / sizeof(epollfds[0]); i++) {
    *epollfds[i] = epoll_create1(EPOLL_CLOEXEC);
    if (*epollfds[i] == -1) {
      CcspTraceError(("Failed to create an epoll instance\n"));
      return -1;
    }
  }

  for (unsigned int i = 0; i < sizeof(eventfds) / sizeof(eventfds[0]); i++) {
    *eventfds[i] = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
    if (*eventfds[i] == -1) {
      CcspTraceError(("Failed to create eventfd\n"));
      return -1;
    }
  }

  return 0;
}

static int
cujoagent_set_consumer_epoll_lists(cujoagent_wifi_consumer_t *consumer) {
  struct epoll_event ev = {0};

  ev.events = EPOLLIN;
  ev.data.fd = consumer->sock_fd;
  if (epoll_ctl(consumer->comms_epoll, EPOLL_CTL_ADD, consumer->sock_fd, &ev)) {
    goto err;
  }

  ev.events = EPOLLIN | EPOLLET;
  ev.data.fd = consumer->comms_notification;
  if (epoll_ctl(consumer->comms_epoll, EPOLL_CTL_ADD,
                consumer->comms_notification, &ev)) {
    goto err;
  }

  ev.events = EPOLLIN | EPOLLET;
  ev.data.fd = consumer->fifo_fd;
  if (epoll_ctl(consumer->fifo_epoll, EPOLL_CTL_ADD, consumer->fifo_fd, &ev)) {
    goto err;
  }

  ev.events = EPOLLIN | EPOLLET;
  ev.data.fd = consumer->fifo_notification;
  if (epoll_ctl(consumer->fifo_epoll, EPOLL_CTL_ADD,
                consumer->fifo_notification, &ev)) {
    goto err;
  }

  ev.events = EPOLLIN | EPOLLET;
  ev.data.fd = consumer->comms_notification_ack;
  if (epoll_ctl(consumer->queue_epoll, EPOLL_CTL_ADD,
                consumer->comms_notification_ack, &ev)) {
    goto err;
  }

  ev.events = EPOLLIN | EPOLLET;
  ev.data.fd = consumer->fifo_notification_ack;
  if (epoll_ctl(consumer->queue_epoll, EPOLL_CTL_ADD,
                consumer->fifo_notification_ack, &ev)) {
    goto err;
  }

  return 0;

err:
  CcspTraceError(
      ("Failed to add the socket loop eventfd to an epoll interest list\n"));
  return -1;
}

/* Gets called internally by webconfig_set() */
static webconfig_error_t
cujoagent_webconfig_apply(__attribute__((unused)) webconfig_subdoc_t *doc,
                          __attribute__((unused)) webconfig_subdoc_data_t *data) {
  return webconfig_error_none;
}

static int cujoagent_consumer_init(cujoagent_wifi_consumer_t *consumer) {
  char *msg = NULL;
  memset(consumer, 0, sizeof(cujoagent_wifi_consumer_t));

  pthread_mutex_init(&consumer->lock, NULL);
  pthread_mutex_init(&consumer->l1_lock, NULL);
  pthread_cond_init(&consumer->cond, NULL);

  consumer->queue = queue_create();
  if (consumer->queue == NULL) {
    msg = "Failed to allocate a consumer queue";
    goto err;
  }
  consumer->queue_wakeup = false;

  cujoagent_tlv_notify_lut_t tlv_notify_lut_filler[MAX_TO_CUJO_TLVS] = {
      {CUJO_FPC_WIFI_RADIO_UPDATE_EVENT, NOTIFY_RADIO_DATA_READY, NOTIFY_RADIO_DATA_SENT},
      {CUJO_FPC_WIFI_STATION_UPDATE_EVENT, NOTIFY_STATION_DATA_READY, NOTIFY_STATION_DATA_SENT},
      {CUJO_FPC_WIFI_DATA_BATCH_EVENT, NOTIFY_BATCH_DATA_READY, NOTIFY_BATCH_DATA_SENT},
      {CUJO_FPC_CSI_AND_CFO_DATA_EVENT, NOTIFY_CSI_CFO_READY, NOTIFY_CSI_CFO_SENT},
      {CUJO_FPC_TEMPERATURE_DATA_EVENT, NOTIFY_TEMPERATURE_READY, NOTIFY_TEMPERATURE_SENT},
      {CUJO_FPC_L1_COLLECTION_DONE, NOTIFY_L1_COLLECTION_DONE_READY, NOTIFY_L1_COLLECTION_DONE_SENT},
  };
  memcpy(consumer->tlv_notify_lut, tlv_notify_lut_filler, sizeof(tlv_notify_lut_filler));

  consumer->webconfig.initializer = webconfig_initializer_dml;
  consumer->webconfig.apply_data = &cujoagent_webconfig_apply;
  if (webconfig_init(&consumer->webconfig) != 0) {
    msg = "Failed to initialize webconfig framework";
    goto err;
  }

  if (cujoagent_socket_init(consumer) != 0) {
    msg = "Failed to initialize a socket";
    goto err;
  }

  consumer->fifo_fd =
      open(WIFI_CSI_DATA_FIFO_PATH, O_CLOEXEC | O_RDONLY | O_NONBLOCK);
  if (consumer->fifo_fd == -1) {
    msg = "Failed to open fifo";
    goto err;
  }

  if (cujoagent_notify_events_init(consumer) != 0) {
    msg = "Failed to initialize notify events";
    goto err;
  }

  if (cujoagent_set_consumer_epoll_lists(consumer) != 0) {
    msg = "Failed to setup epoll interest lists";
    goto err;
  }

  consumer->disable_l1_collection = false;
  consumer->comms_ready = false;
  consumer->exit_consumer = false;
  return 0;

err:
  CcspTraceError(("%s\n", msg));
  return -1;
}

static void cujoagent_close_if_valid(int *fd) {
  if (*fd >= 0) {
    close(*fd);
    *fd = -1;
  }
}

static void cujoagent_close_event_fds(cujoagent_wifi_consumer_t *consumer) {
  cujoagent_close_if_valid(&consumer->misc_notification);
  cujoagent_close_if_valid(&consumer->comms_notification);
  cujoagent_close_if_valid(&consumer->comms_notification_ack);
  cujoagent_close_if_valid(&consumer->fifo_notification);
  cujoagent_close_if_valid(&consumer->fifo_notification_ack);

  cujoagent_close_if_valid(&consumer->misc_epoll);
  cujoagent_close_if_valid(&consumer->comms_epoll);
  cujoagent_close_if_valid(&consumer->fifo_epoll);
  cujoagent_close_if_valid(&consumer->queue_epoll);
}

static void cujoagent_consumer_deinit(cujoagent_wifi_consumer_t *consumer) {
  pthread_mutex_destroy(&consumer->lock);
  pthread_mutex_destroy(&consumer->l1_lock);
  pthread_cond_destroy(&consumer->cond);

  if (consumer->queue) {
    queue_destroy(consumer->queue);
  }

  /* Don't close rbus_handle - it's the global g_rbus_handle owned by advsec_rbus_handlers.c */
  /* The consumer just borrows the handle; it doesn't own it */

  free(consumer->vap_subs_indexes);

  if (consumer->subscriptions) {
    for (unsigned int i = 0; i < consumer->subscriptions_count; i++) {
      if (consumer->subscriptions[i].eventName) {
        free((char *)consumer->subscriptions[i].eventName);
      }
    }
    free(consumer->subscriptions);
  }

  if (consumer->raw_data_subscriptions) {
    for (unsigned int i = 0; i < consumer->raw_data_subscriptions_count; i++) {
      if (consumer->raw_data_subscriptions[i].eventName) {
        free((char *)consumer->raw_data_subscriptions[i].eventName);
      }
    }
    free(consumer->raw_data_subscriptions);
  }

  if (consumer->on_demand_subscriptions) {
    for (unsigned int i = 0; i < consumer->on_demand_subscriptions_count; i++) {
      if (consumer->on_demand_subscriptions[i].eventName) {
        free((char *)consumer->on_demand_subscriptions[i].eventName);
      }
    }
    free(consumer->on_demand_subscriptions);
  }

  free(consumer->tcollect_ctx.temperature_data);

  cujoagent_close_if_valid(&consumer->sock_fd);
  cujoagent_close_if_valid(&consumer->fifo_fd);
  cujoagent_close_event_fds(consumer);
}

static void cujoagent_update_consumer_wifi_structs(
    cujoagent_wifi_consumer_t *consumer,
    webconfig_subdoc_decoded_data_t *decoded_params) {
  if (!consumer || !decoded_params) {
    CcspTraceError(("Consumer or decoded params invalid\n"));
    return;
  }

  CcspTraceDebug(("Updating consumer config, hal_cap, radio structs\n"));
  consumer->hal_cap.wifi_prop.numRadios = decoded_params->num_radios;
  memcpy(&consumer->config, &decoded_params->config,
         sizeof(wifi_global_config_t));
  memcpy(&consumer->hal_cap, &decoded_params->hal_cap,
         sizeof(wifi_hal_capability_t));
  memcpy(&consumer->radios, &decoded_params->radios,
         decoded_params->num_radios * sizeof(rdk_wifi_radio_t));
}

static void cujoagent_update_decoded_wifi_structs(
    cujoagent_wifi_consumer_t *consumer,
    webconfig_subdoc_decoded_data_t *decoded_params) {
  if (!consumer || !decoded_params) {
    CcspTraceError(("Consumer or decoded params invalid\n"));
    return;
  }

  CcspTraceDebug(("Updating decoded config, hal_cap, radio structs\n"));
  decoded_params->num_radios = consumer->hal_cap.wifi_prop.numRadios;
  memcpy(&decoded_params->config, &consumer->config,
         sizeof(wifi_global_config_t));
  memcpy(&decoded_params->hal_cap, &consumer->hal_cap,
         sizeof(wifi_hal_capability_t));
  memcpy(&decoded_params->radios, &consumer->radios,
         decoded_params->num_radios * sizeof(rdk_wifi_radio_t));
}

static int cujoagent_write_event(int eventfd, cujoagent_notify_t notify) {
  size_t su = sizeof(uint64_t);
  uint64_t u = notify;
  CcspTraceDebug(
      ("Writing notify [%" PRIu64 "] to eventfd [%d]\n", u, eventfd));
  if (write(eventfd, &u, su) != (ssize_t)su) {
    CcspTraceError(("Failed to write eventfd value [%" PRIu64 "]\n", u));
    return -1;
  }
  return 0;
}

static int cujoagent_wait_for_event(int epoll_fd, cujoagent_notify_t notify,
                                    int timeout_ms) {
  struct epoll_event events[MAX_EPOLL_EVENTS] = {0};
  int nfds = -1;
  int efd = -1;
  uint32_t event = 0;
  uint64_t u = NOTIFY_NONE;
  int nbytes;

  CcspTraceDebug(("Epoll wait: epoll fd [%d] notify to expect [%d]\n",
                  epoll_fd, notify));

  nfds = epoll_wait(epoll_fd, events, MAX_EPOLL_EVENTS, timeout_ms);
  for (int i = 0; i < nfds; i++) {
    efd = events[i].data.fd;
    event = events[i].events;

    CcspTraceDebug(("Epoll event: epoll fd [%d] nfds [%d] event fd [%d] "
                    "event [0x%08" PRIx32 "] notify received [%d]\n",
                    epoll_fd, nfds, efd, event, notify));

    if (!(event & EPOLLIN)) {
      CcspTraceError(("Event [0x%08" PRIx32 "] "
                      "has bit [0x%08" PRIx32 "] not set\n",
                      event, EPOLLIN));
      return -1;
    }

    nbytes = read(efd, &u, sizeof(u));
    if (nbytes < 0) {
      CcspTraceError(("Failed to read event fd [%d]\n", efd));
      return -1;
    }
    else {
      CcspTraceDebug(("Read event fd %d bytes\n", nbytes));
    }

    if (u != notify) {
      CcspTraceError(("Eventfd notification mismatch: "
                      "[%" PRIu64 "] != [%d]\n",
                      u, notify));
      return -1;
    }
  }

  return nfds;
}

static int cujoagent_send_version_tlv(int sock_fd, struct sockaddr_un *paddr,
                                      socklen_t *addr_len) {
  struct cujo_fpc_proto_version ver = {.major = VERSION_MAJOR,
                                       .minor = VERSION_MINOR};
  size_t ver_size = sizeof(ver);
  size_t ver_tlv_size = sizeof(struct cujo_fpc_tlv) + ver_size;
  struct cujo_fpc_tlv *ver_tlv = calloc(1, ver_tlv_size);
  if (!ver_tlv) {
    CcspTraceError(("Failed to allocate a \"version\" tlv\n"));
    return -1;
  }

  ver_tlv->tag = CUJO_FPC_PROTOCOL_VERSION;
  ver_tlv->len = ver_size;
  memcpy(ver_tlv->data, &ver, ver_size);

  CcspTraceInfo(
      ("Sending \"version\" tlv: "
       "tag [%" PRIu16 "] len [%" PRIu16 "] size [%zu] major [%d] minor [%d]\n",
       ver_tlv->tag, ver_tlv->len, ver_tlv_size, ver.major, ver.minor));
  ssize_t mlen = sendto(sock_fd, ver_tlv, ver_tlv_size, 0,
                        (struct sockaddr *)paddr, *addr_len);
  free(ver_tlv);

  if (mlen == -1) {
    CcspTraceError(("Sending \"version\" tlv failed\n"));
    return -1;
  }

  return 0;
}

static int cujoagent_tlv_handshake(int sock_fd, struct sockaddr_un *paddr,
                                   socklen_t *addr_len, char *buf,
                                   size_t buf_size) {
  struct cujo_fpc_tlv received_tlv = {0};
  for (;;) {
    CcspTraceInfo(("Waiting for the agent \"hello\"\n"));
    if (recvfrom(sock_fd, buf, buf_size, 0,
                 (struct sockaddr *)paddr, addr_len) == -1) {
      CcspTraceError(("Reading from peer failed\n"));
      return -1;
    }
    memcpy(&received_tlv, buf, sizeof(received_tlv));

    CcspTraceDebug(("Received tlv: "
                    "tag [%" PRIu16 "] len [%" PRIu16 "]\n",
                    received_tlv.tag, received_tlv.len));

    if (received_tlv.tag != CUJO_FPC_HELLO) {
      CcspTraceWarning(("Not a \"hello\" tlv: "
                        "tag [%" PRIu16 "] len [%" PRIu16 "]\n",
                        received_tlv.tag, received_tlv.len));
      continue;
    }
    CcspTraceInfo(("Received the agent \"hello\"\n"));
    break;
  }

  if (cujoagent_send_version_tlv(sock_fd, paddr, addr_len) == -1) {
    return -1;
  }

  return 0;
}

static int
cujoagent_push_to_consumer_queue(cujoagent_wifi_consumer_t *consumer,
                                 void const *msg, size_t mlen,
                                 cujoagent_consumer_event_type_t type,
                                 cujoagent_consumer_event_subtype_t subtype) {
  cujoagent_wifi_consumer_event_t *data =
      calloc(1, sizeof(cujoagent_wifi_consumer_event_t));
  if (data == NULL) {
    CcspTraceError(("Failed to allocate consumer queue data\n"));
    return -1;
  }

  data->event_type = type;
  data->event_subtype = subtype;

  data->msg = calloc(1, mlen + 1);
  if (data->msg == NULL) {
    CcspTraceError(("Failed to allocate consumer queue data message\n"));
    free(data);
    return -1;
  }

  memcpy(data->msg, msg, mlen);
  data->mlen = mlen;

  pthread_mutex_lock(&consumer->lock);
  queue_push(consumer->queue, data);
  consumer->queue_wakeup = true;
  pthread_mutex_unlock(&consumer->lock);
  pthread_cond_signal(&consumer->cond);

  return 0;
}

static char *cujoagent_bytes_to_mac_str(mac_address_t mac, mac_addr_str_t key) {
  int count = snprintf(key, MAX_MAC_STR_LEN + 1, MAC_DOT_FMT,
                       mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
  if (count < 0 || count >= MAX_MAC_STR_LEN + 1) {
    CcspTraceError(("MAC string doesn't fit into buffer\n"));
    return NULL;
  }
  return (char *)key;
}

static int cujoagent_emit_event_tlv(enum cujo_fpc_tag_list tag, void *data,
                                    size_t data_len,
                                    cujoagent_wifi_consumer_t *consumer) {
  if (!data) {
    CcspTraceError(("Invalid data [%p]\n", (void *)data));
    return -1;
  }

  cujoagent_notify_t ready = NOTIFY_NONE;
  cujoagent_notify_t sent = NOTIFY_NONE;
  for (int i = 0; i < MAX_TO_CUJO_TLVS; i++) {
    if (tag == consumer->tlv_notify_lut[i].event_tag) {
      ready = consumer->tlv_notify_lut[i].notify_ready;
      sent = consumer->tlv_notify_lut[i].notify_sent;
      break;
    }
  }

  if ((ready == NOTIFY_NONE) || (sent == NOTIFY_NONE)) {
    CcspTraceError(("Unsupported event tag: [%u]\n", tag));
    return -1;
  }

  size_t tlv_size = sizeof(struct cujo_fpc_tlv) + data_len;
  CcspTraceDebug(("Preparing wifi tlv: tag [%u] len [%zu] size [%zu] "
                  "notify to be sent [%d] notify to expect [%d]\n",
                  tag, data_len, tlv_size, ready, sent));

  consumer->tlv_ctx.size = tlv_size;
  consumer->tlv_ctx.tlv = calloc(1, tlv_size);
  if (!consumer->tlv_ctx.tlv) {
    CcspTraceError(("Failed to allocate tlv for event tag [%d]\n", tag));
    return -1;
  }
  consumer->tlv_ctx.tlv->tag = tag;
  consumer->tlv_ctx.tlv->len = data_len;
  memcpy(consumer->tlv_ctx.tlv->data, data, data_len);

  if ((cujoagent_write_event(consumer->comms_notification, ready) == -1) ||
      (cujoagent_wait_for_event(consumer->queue_epoll, sent,
                                EPOLL_TIMEOUT_MS) <= 0)) {
    CcspTraceError(("Sending tlv [%d] failed or timed out\n",
                    consumer->tlv_ctx.tlv->tag));
    free(consumer->tlv_ctx.tlv);
    consumer->tlv_ctx.tlv = NULL;
    /* Assume that we either can't reliably notify the comms loop or the
     * comms loops failed to send the data. We are in the consumer queue
     * here, hence, already under the lock and it is expected to be safe
     * to set the comms_ready here. */
    consumer->comms_ready = false;
    return -1;
  }

  free(consumer->tlv_ctx.tlv);
  consumer->tlv_ctx.tlv = NULL;
  return 0;
}

static rbusError_t
cujoagent_set_csi_collection(cujoagent_wifi_consumer_t *consumer,
                             unsigned int duration,
                             mac_addr_str_t client_mac_str) {
  /* NOTE: Order matters here. Every property set triggers a push of levl dml
  * data (all fields) to the control queue, but only the client mac set
  * enables the csi engine. Therefore, first update the duration and only then
  * set the MAC for collection. */

  /* WIFI_LEVL_SOUNDING_DURATION: A duration for how long to collect the CSI
  * data. If zero, then is set to the platform default duration.
   * Note: not to confuse with CSI_DELAY_PERIOD, which is basically a sampling
   * rate and equals to 100ms. Therefore, for a default 2000ms sounding
   * duration and a 1sample/100ms rate we should be expecting 20 samples. */
  char const *name = WIFI_LEVL_SOUNDING_DURATION;
  CcspTraceDebug(("Setting sounding duration to [%u] ms\n", duration));
  rbusError_t err = rbus_setUInt(consumer->rbus_handle, name, duration);
  if (err) {
    CcspTraceError(("Failed to set [%s] over RBUS: [%d]\n", name, err));
    return err;
  }

  /* WIFI_LEVL_CLIENTMAC: Semicolon or no-semicolon MAC address to start the
   * CSI and CFO collection for. */
  name = WIFI_LEVL_CLIENTMAC;
  CcspTraceDebug(("Setting mac [%s] for CSI and CFO collection\n", client_mac_str));
  err = rbus_setStr(consumer->rbus_handle, name, client_mac_str);
  if (err) {
    CcspTraceError(("Failed to set [%s] over RBUS: [%d]\n", name, err));
  }

  return err;
}

/* XXX: Assuming we can have only one subscriber to temperatures, the following
 * routine can not be run in parallel, effectivelly making it a single-threaded
 * routine and limiting us to one L1 collection at a time. */
static void *cujoagent_l1_collector(void *arg) {
  cujoagent_l1_collector_t *collector = arg;
  cujoagent_wifi_consumer_t *consumer = collector->consumer;
  char *msg = NULL;

  struct epoll_event events[MAX_EPOLL_EVENTS] = {0};
  int nfds = -1;
  int efd = -1;
  uint32_t event = 0;
  uint64_t u = NOTIFY_NONE;
  cujoagent_notify_t notify = NOTIFY_NONE;

  struct cujo_fpc_l1_collection_start *l1_start_tlv = &collector->start;
  struct cujo_fpc_l1_collection_done done = {0};
  unsigned int expected_temperature_interval = 0;
  unsigned int expected_csi_duration = 0;
  unsigned int timeout_ms = 0;

  int collector_epoll = -1;
  struct epoll_event ev = {0};
  struct itimerspec ts = {0};
  int nbytes;

  mac_addr_str_t collect_mac_str = {0};
  cujoagent_bytes_to_mac_str(l1_start_tlv->mac.ether_addr_octet,
                             collect_mac_str);

  CcspTraceDebug(("Starting L1 collector for mac [%s]\n", collect_mac_str));

  expected_temperature_interval =
      l1_start_tlv->temperature_interval_secs * MSECS_PER_SEC;
  if (expected_temperature_interval < WIFI_RADIO_MIN_TEMPERATURE_INTERVAL) {
    CcspTraceDebug(
        ("Collecting the temperatures at requested interval [%u] is "
         "not possible. Setting the interval to the minimum supported [%u]\n",
         l1_start_tlv->temperature_interval_secs,
         WIFI_RADIO_MIN_TEMPERATURE_INTERVAL / MSECS_PER_SEC));
    expected_temperature_interval = WIFI_RADIO_MIN_TEMPERATURE_INTERVAL;
  }

  timeout_ms = l1_start_tlv->timeout_secs * MSECS_PER_SEC;
  expected_csi_duration = l1_start_tlv->max_csi_readings * DCL_CSI_INTERVAL_MS;
  if (expected_csi_duration > timeout_ms) {
    CcspTraceDebug((
        "Expected CSI collection duration [%u] is greater than the L1 "
        "collection timeout [%u]. Setting the duration to match the timeout.\n",
        expected_csi_duration, timeout_ms));
    expected_csi_duration = timeout_ms;
  }
  if (expected_csi_duration < WIFI_LEVL_MIN_SOUNDING_DURATION) {
    CcspTraceDebug(
        ("Expected CSI collection duration [%u] is less than the minimum "
         "supported [%u]. Setting the duration to the minimum supported.\n",
         expected_csi_duration, WIFI_LEVL_MIN_SOUNDING_DURATION));
    expected_csi_duration = WIFI_LEVL_MIN_SOUNDING_DURATION;
  }

  done.vap_index = l1_start_tlv->vap_index;
  done.mac = l1_start_tlv->mac;

  collector_epoll = epoll_create1(EPOLL_CLOEXEC);
  if (collector_epoll == -1) {
    msg = "Failed to create an L1 collector epoll instance";
    goto err;
  }

  ev.events = EPOLLIN | EPOLLET;
  ev.data.fd = collector->notification;
  if (epoll_ctl(collector_epoll, EPOLL_CTL_ADD, collector->notification, &ev)) {
    msg = "Failed to add L1 collector stop eventfd to an epoll interest list";
    goto err;
  }

  ev.events = EPOLLIN | EPOLLET;
  ev.data.fd = collector->timer;
  if (epoll_ctl(collector_epoll, EPOLL_CTL_ADD, collector->timer, &ev)) {
    msg = "Failed to add L1 collector timerfd to an epoll interest list";
    goto err;
  }

  /* XXX: Parameters must match when unsubscribing. Since the way we gather
   * temperatures is a major limiting factor of collecting for one MAC only, we
   * assume it is safe to modify the interval without any locks, because we are
   * running one L1 collector thread at a time. */
  for (unsigned int i = 0; i < consumer->on_demand_subscriptions_count; i++) {
    consumer->on_demand_subscriptions[i].interval =
        expected_temperature_interval;
  }

  /* Start getting radios temperatures over RBUS */
  if (rbusEvent_SubscribeEx(consumer->rbus_handle,
                            consumer->on_demand_subscriptions,
                            consumer->on_demand_subscriptions_count,
                            0) != RBUS_ERROR_SUCCESS) {
    msg = "Failed to subscribe to on-demand event(s)";
    goto err;
  }

  /* Start getting CSI and CFO over RBUS */
  if (cujoagent_set_csi_collection(consumer, expected_csi_duration,
                                   collect_mac_str) != RBUS_ERROR_SUCCESS) {
    msg = "Failed to enable CSI and CFO collection";
    goto err;
  }

  ts.it_value.tv_sec = timeout_ms / MSECS_PER_SEC;
  ts.it_value.tv_nsec = (timeout_ms % MSECS_PER_SEC) * NSECS_PER_MSEC;
  ts.it_interval.tv_sec = 0;
  ts.it_interval.tv_nsec = 0;

  if (timerfd_settime(collector->timer, 0, &ts, NULL) != 0) {
    msg = "Failed to set the timer for L1 collector thread timer";
    goto err;
  }

  CcspTraceDebug(("Epoll wait: epoll fd [%d] "
                  "expecting event on eventfd [%d] or timerfd [%d]\n",
                  collector_epoll, collector->notification, collector->timer));

  nfds = epoll_wait(collector_epoll, events, MAX_EPOLL_EVENTS,
                    timeout_ms + EPOLL_TIMEOUT_MS);
  if (nfds == -1) {
    msg = "L1 collector epoll wait error";
    goto err;
  }

  if (nfds == 0) {
    CcspTraceWarning(("No fd's became ready during the requested "
                      "L1 collection timeout [%u] for mac [%s]\n",
                      timeout_ms, collect_mac_str));
  }

  for (int i = 0; i < nfds; i++) {
    efd = events[i].data.fd;
    event = events[i].events;
    notify = NOTIFY_NONE;

    CcspTraceDebug(("Epoll event: epoll fd [%d] nfds [%d] event fd [%d] "
                    "event [0x%08" PRIx32 "]\n",
                    collector_epoll, nfds, efd, event));

    if (!(event & EPOLLIN)) {
      CcspTraceError(("Event [0x%08" PRIx32 "] "
                      "has bit [0x%08" PRIx32 "] not set\n",
                      event, EPOLLIN));
      continue;
    }

    nbytes = read(efd, &u, sizeof(u));
    if (nbytes < 0) {
      CcspTraceError(("Failed to read event fd [%d]\n", efd));
      continue;
    }
    else {
      CcspTraceDebug(("Read event fd %d bytes\n", nbytes));
    }

    if (efd == collector->timer) {
      CcspTraceDebug(("L1 collection timer for mac [%s] has expired\n",
                      collect_mac_str));
      /* We're sending DONE in all cases except L1 collector thread return.
       * Therefore, simply break to follow the code to avoid more conditions
       * to check. */
      break;
    } else if (efd == collector->notification) {
      if (u == NOTIFY_L1_COLLECTION_THREAD_STOP) {
        notify = NOTIFY_L1_COLLECTION_THREAD_RETURN;
      }

      CcspTraceDebug(("Eventfd notification: "
                      "notify received [%" PRIu64 "] "
                      "notify to be sent [%d]\n",
                      u, notify));

      if (notify == NOTIFY_NONE) {
        CcspTraceError(("Unsupported eventfd notification: "
                        "notify received [%" PRIu64 "] "
                        "notify to be sent [%d]\n",
                        u, notify));
        continue;
      }

      if (notify == NOTIFY_L1_COLLECTION_THREAD_RETURN) {
        cujoagent_write_event(collector->notification_ack, notify);
        goto out;
      }
    }
  }

err:
  if (msg) {
    CcspTraceError(("%s\n", msg));
  }

  /* XXX: Beware of the consumer lock acquired to push to the consumer queue.
   * Obey the lock order: consumer lock first, then the collector lock.
   * Otherwise use relevant lock to protect relevant data. */
  cujoagent_push_to_consumer_queue(consumer,
                                   &done,
                                   sizeof(done),
                                   consumer_event_type_l1,
                                   consumer_event_l1_done);
out:
  for (unsigned int i = 0; i < consumer->on_demand_subscriptions_count; i++) {
    if (rbusEvent_IsSubscriptionExist(consumer->rbus_handle, NULL,
                                      &consumer->on_demand_subscriptions[i])) {
      rbusEvent_UnsubscribeEx(consumer->rbus_handle,
                              &consumer->on_demand_subscriptions[i], 1);
    }
  }

  pthread_mutex_lock(&consumer->l1_lock);
  if (epoll_ctl(consumer->queue_epoll, EPOLL_CTL_DEL,
                collector->notification_ack, NULL)) {
    CcspTraceError(("Failed to remove L1 collector stop_ack eventfd from the "
                    "consumer epoll interest list\n"));
  }
  cujoagent_close_if_valid(&collector->notification_ack);
  cujoagent_close_if_valid(&collector->notification);
  cujoagent_close_if_valid(&collector->timer);
  cujoagent_close_if_valid(&collector_epoll);
  for (int i = 0; i < DCL_MAX_CSI_CLIENTS; i++) {
    if (consumer->l1_collections[i] == collector) {
      consumer->l1_collections[i] = NULL;
      break;
    }
  }
  pthread_mutex_unlock(&consumer->l1_lock);
  free(collector);

  CcspTraceDebug(("Returning from L1 collector thread routine for mac [%s]\n",
                  collect_mac_str));
  return NULL;
}

static int
cujoagent_start_l1_collection(struct cujo_fpc_l1_collection_start *l1_start_tlv,
                              cujoagent_wifi_consumer_t *consumer) {
  if (!l1_start_tlv) {
    CcspTraceError(
        ("Invalid L1 collection start tlv [%p]\n", (void *)l1_start_tlv));
    return -1;
  }

  struct epoll_event ev = {0};
  mac_addr_str_t collect_mac_str = {0};
  cujoagent_l1_collector_t *collector = NULL;

  pthread_mutex_lock(&consumer->l1_lock);
  cujoagent_bytes_to_mac_str(l1_start_tlv->mac.ether_addr_octet,
                             collect_mac_str);

  if (consumer->disable_l1_collection) {
    CcspTraceWarning(("L1 collection is disabled\n"));
    goto err;
  }

  for (int i = 0; i < DCL_MAX_CSI_CLIENTS; i++) {
    if (consumer->l1_collections[i] != NULL &&
        memcmp(consumer->l1_collections[i]->start.mac.ether_addr_octet,
               l1_start_tlv->mac.ether_addr_octet, ETH_ALEN) == 0) {
      CcspTraceWarning(("L1 collection for mac [%s] already in progress\n",
                        collect_mac_str));
      goto err;
    }
  }

  int slot = -1;
  for (int i = 0; i < DCL_MAX_CSI_CLIENTS; i++) {
    if (consumer->l1_collections[i] == NULL) {
      slot = i;
      break;
    }
  }

  if (slot == -1) {
    CcspTraceWarning(("No slots available for new L1 collection\n"));
    goto err;
  }

  collector = calloc(1, sizeof(*collector));
  if (!collector) {
    CcspTraceError(("Failed to allocate L1 collector\n"));
    goto err;
  }

  memcpy(&collector->start, l1_start_tlv, sizeof(*l1_start_tlv));
  collector->consumer = consumer;

  /* Initialize fd's to -1 to avoid accidentally closing stdin on error paths */
  collector->notification = -1;
  collector->notification_ack = -1;
  collector->timer = -1;

  collector->notification = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
  if (collector->notification == -1) {
    CcspTraceError(("Failed to create stop eventfd for L1 collector\n"));
    goto err;
  }

  collector->notification_ack = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
  if (collector->notification_ack == -1) {
    CcspTraceError(("Failed to create stop_ack eventfd for L1 collector\n"));
    goto err;
  }

  collector->timer = timerfd_create(CLOCK_MONOTONIC, 0);
  if (collector->timer == -1) {
    CcspTraceError(("Failed to create timerfd for L1 collector\n"));
    goto err;
  }

  ev.events = EPOLLIN | EPOLLET;
  ev.data.fd = collector->notification_ack;
  if (epoll_ctl(consumer->queue_epoll, EPOLL_CTL_ADD,
                collector->notification_ack, &ev)) {
    CcspTraceError(("Failed to add L1 collector stop_ack eventfd to the "
                    "consumer epoll interest list\n"));
    goto err;
  }

  consumer->l1_collections[slot] = collector;
  pthread_mutex_unlock(&consumer->l1_lock);

  pthread_attr_t attr;
  pthread_attr_init(&attr);
  pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
  pthread_t thr = 0;
  if (pthread_create(&thr, &attr, &cujoagent_l1_collector, collector) != 0) {
    CcspTraceError(("Failed to start L1 collector thread for mac [%s]\n",
                    collect_mac_str));
    if (epoll_ctl(consumer->queue_epoll, EPOLL_CTL_DEL,
                  collector->notification_ack, NULL)) {
      CcspTraceError(("Failed to remove L1 collector stop_ack eventfd from the "
                      "consumer epoll interest list\n"));
    }
    consumer->l1_collections[slot] = NULL;
    pthread_attr_destroy(&attr);
    if (collector) {
      cujoagent_close_if_valid(&collector->notification_ack);
      cujoagent_close_if_valid(&collector->notification);
      cujoagent_close_if_valid(&collector->timer);
      free(collector);
    }
    return -1;
  }
  pthread_attr_destroy(&attr);

  return 0;

err:
  if (collector) {
    cujoagent_close_if_valid(&collector->notification_ack);
    cujoagent_close_if_valid(&collector->notification);
    cujoagent_close_if_valid(&collector->timer);
    free(collector);
  }
  pthread_mutex_unlock(&consumer->l1_lock);
  return -1;
}

static void *cujoagent_socket_loop(void *arg) {
  cujoagent_wifi_consumer_t *consumer = arg;
  char *msg = NULL;

  char buf[MAX_SOCK_RECV_BUFFER] = {0};
  struct sockaddr_un paddr = {0};
  socklen_t addr_len = sizeof(struct sockaddr_un);

  struct sockaddr_un daddr = {0};
  socklen_t daddr_len = 0;

  struct epoll_event events[MAX_EPOLL_EVENTS] = {0};
  int nfds = 0;
  int efd = 0;
  uint32_t event = 0;
  uint64_t u = NOTIFY_NONE;
  cujoagent_notify_t notify = NOTIFY_NONE;
  struct cujo_fpc_tlv received_tlv = {0};

  struct cujo_fpc_l1_collection_start *l1_start_tlv = NULL;
  mac_addr_str_t collect_mac_str = {0};
  int nbytes;

  /* Blocking call, get a hello first and only then proceed further */
  if (cujoagent_tlv_handshake(consumer->sock_fd, &paddr, &addr_len,
                              buf, sizeof(buf)) != 0) {
    msg = "\"hello<->version\" handshake failed";
    goto err;
  }

  /* Save the address on where CUJO_FPC_HELLO has happened, so that receives
   * with other tags do not overwrite the address destined to the agent. */
  daddr = paddr;
  daddr_len = addr_len;

  pthread_mutex_lock(&consumer->lock);
  consumer->comms_ready = true;
  pthread_mutex_unlock(&consumer->lock);

  for (;;) {
    /* Block until event, timeout -1 */
    CcspTraceDebug(("Epoll wait: epoll fd [%d] "
                    "expecting event on socket fd [%d] or eventfd [%d]\n",
                    consumer->comms_epoll, consumer->sock_fd,
                    consumer->comms_notification));
    nfds = epoll_wait(consumer->comms_epoll, events, MAX_EPOLL_EVENTS, -1);
    for (int i = 0; i < nfds; i++) {
      efd = events[i].data.fd;
      event = events[i].events;
      notify = NOTIFY_NONE;

      CcspTraceDebug(("Epoll event: epoll fd [%d] nfds [%d] event fd [%d] "
                      "event [0x%08" PRIx32 "]\n",
                      consumer->comms_epoll, nfds, efd, event));

      if (!(event & EPOLLIN)) {
        continue;
      }

      if (efd == consumer->comms_notification) {
        nbytes = read(efd, &u, sizeof(u));
        if (nbytes == -1) {
          CcspTraceError(("Failed to read eventfd [%d]\n", efd));
          continue;
        }
       else {
         CcspTraceDebug(("Read eventfd %d bytes\n", nbytes));
       }

        for (int j = 0; j < MAX_TO_CUJO_TLVS; j++) {
          if (u == consumer->tlv_notify_lut[j].notify_ready) {
            notify = consumer->tlv_notify_lut[j].notify_sent;
            break;
          }
        }

        if (u == NOTIFY_SOCKET_THREAD_STOP) {
          notify = NOTIFY_SOCKET_THREAD_RETURN;
        }

        CcspTraceDebug(("Eventfd notification: "
                        "notify received [%" PRIu64 "] "
                        "notify to be sent [%d]\n",
                        u, notify));

        if (notify == NOTIFY_NONE) {
          CcspTraceError(("Unsupported eventfd notification: "
                          "notify received [%" PRIu64 "] "
                          "notify to be sent [%d]\n",
                          u, notify));
          continue;
        }

        if (notify == NOTIFY_SOCKET_THREAD_RETURN) {
          cujoagent_write_event(consumer->comms_notification_ack, notify);
          goto out;
        }

        /* It would not be a great idea to access the freed memory, so make
         * sure we see it in the logs if that race is ever going to happen. */
        if (!consumer->tlv_ctx.tlv) {
          CcspTraceError(("Invalid wifi tlv: [%p] "
                          "notify received [%" PRIu64 "] "
                          "notify to be sent [%d]\n",
                          (void *)consumer->tlv_ctx.tlv, u, notify));
          continue;
        }

        /* The agent handles the following types of mishaps just fine, but
         * let's make it clear that it happened at where the data is gathered,
         * rather than blindly sending an invalid tlv and hoping that the agent
         * will take care of it. */
        if (consumer->tlv_ctx.size !=
            (consumer->tlv_ctx.tlv->len + sizeof(struct cujo_fpc_tlv))) {
          CcspTraceError(
              ("Invalid wifi tlv data: tag [%u] len [%u] size [%zu] "
               "notify received [%" PRIu64 "] notify to be sent [%d]\n",
               consumer->tlv_ctx.tlv->tag, consumer->tlv_ctx.tlv->len,
               consumer->tlv_ctx.size, u, notify));
          continue;
        }

        CcspTraceDebug(("Sending wifi tlv: tag [%u] len [%u] size [%zu]\n",
                        consumer->tlv_ctx.tlv->tag, consumer->tlv_ctx.tlv->len,
                        consumer->tlv_ctx.size));
        if (sendto(consumer->sock_fd, consumer->tlv_ctx.tlv,
                   consumer->tlv_ctx.size, 0, (const struct sockaddr *)&daddr,
                   daddr_len) == -1) {
          CcspTraceError(("Sending wifi tlv failed. Is the agent running?\n"));
          continue;
        }
        cujoagent_write_event(consumer->comms_notification_ack, notify);
      } else if (efd == consumer->sock_fd) {
        addr_len = sizeof(struct sockaddr_un);
        if (recvfrom(consumer->sock_fd, buf, sizeof(buf), 0,
                     (struct sockaddr *)&paddr, &addr_len) == -1) {
          CcspTraceError(("Reading from peer failed\n"));
          continue;
        }
        memcpy(&received_tlv, buf, sizeof(received_tlv));
        CcspTraceDebug(("Received tlv: "
                        "tag [%" PRIu16 "] len [%" PRIu16 "]\n",
                        received_tlv.tag, received_tlv.len));

        switch (received_tlv.tag) {
        case CUJO_FPC_HELLO:
          if (cujoagent_send_version_tlv(consumer->sock_fd, &paddr,
                                         &addr_len) == -1) {
            CcspTraceError(("\"hello<->version\" handshake failed\n"));
            continue;
          }
          daddr = paddr;
          daddr_len = addr_len;

          /* Acquiring consumer mutex in the epoll_wait loop is a recipe for a
           * deadlock if the consumer queue is waiting for an eventfd
           * notification from the comms loop for the successful TLV send. But
           * it's a "hello" we expect here and comms_ready checks are before
           * any TLV sending, so it should be fine to wait here for the queue
           * to bail out on data gathering because the agent is considered not
           * ready to receive TLVs anyway. */
          pthread_mutex_lock(&consumer->lock);
          consumer->comms_ready = true;
          pthread_mutex_unlock(&consumer->lock);
          break;
        case CUJO_FPC_L1_COLLECTION_START:
          l1_start_tlv = (struct cujo_fpc_l1_collection_start *)(buf + sizeof(received_tlv));
          cujoagent_bytes_to_mac_str(l1_start_tlv->mac.ether_addr_octet, collect_mac_str);
          CcspTraceDebug((
              "CUJO_FPC_L1_COLLECTION_START: "
              "vap_index [%u] mac [%s] bandwidth [%" PRIu16 "] "
              "timeout_secs [%u] l1_rate_hz [%u] "
              "temperature_interval_secs [%u] max_csi_readings [%u]\n",
              l1_start_tlv->vap_index,
              collect_mac_str,
              l1_start_tlv->bandwidth,
              l1_start_tlv->timeout_secs,
              l1_start_tlv->l1_rate_hz,
              l1_start_tlv->temperature_interval_secs,
              l1_start_tlv->max_csi_readings));
          if (cujoagent_start_l1_collection(l1_start_tlv, consumer) != 0) {
            CcspTraceWarning(
                ("L1 collector could not be started for mac [%s]\n",
                 collect_mac_str));
          }
          break;
        default:
          CcspTraceWarning(("Unsupported tlv received: "
                            "tag [%" PRIu16 "] len [%" PRIu16 "]\n",
                            received_tlv.tag, received_tlv.len));
          break;
        }
      }
    }
  }

err:
  CcspTraceError(("%s\n", msg));
out:
  CcspTraceDebug(("Returning from socket loop thread routine\n"));
  return NULL;
}

static void *cujoagent_fifo_loop(void *arg) {
  cujoagent_wifi_consumer_t *consumer = arg;
  char *msg = NULL;

  struct epoll_event events[MAX_EPOLL_EVENTS] = {0};
  int nfds = -1;
  int efd = -1;
  uint32_t event = 0;
  uint64_t u = NOTIFY_NONE;
  cujoagent_notify_t notify = NOTIFY_NONE;

  char *fifo_buf = NULL;
  size_t fifo_payload_size = WIFI_CSI_PAYLOAD_HEADER_SIZE +
                             WIFI_CSI_CLIENT_HEADER_SIZE +
                             sizeof(wifi_csi_data_t);
  ssize_t fifo_read = 0;

  char csi_label[WIFI_CSI_DATA_LABEL_LENGTH + 1] = {0};
  size_t csi_label_len = sizeof(csi_label);
  size_t csi_expected_len = 0;
  unsigned int csi_data_len = 0;
  int nbytes;

  fifo_buf = calloc(1, fifo_payload_size);
  if (fifo_buf == NULL) {
    msg = "Failed to allocate fifo buffer";
    goto err;
  }

  for (;;) {
    CcspTraceDebug(("Epoll wait: epoll fd [%d] "
                    "expecting event on eventfd [%d] or fifo fd [%d]\n",
                    consumer->fifo_epoll, consumer->fifo_notification,
                    consumer->fifo_fd));
    nfds = epoll_wait(consumer->fifo_epoll, events, MAX_EPOLL_EVENTS, -1);
    if (nfds == -1) {
      msg = "Epoll wait error";
      goto err;
    }

    for (int i = 0; i < nfds; i++) {
      efd = events[i].data.fd;
      event = events[i].events;
      notify = NOTIFY_NONE;

      CcspTraceDebug(("Epoll event: epoll fd [%d] nfds [%d] event fd [%d] "
                      "event [0x%08" PRIx32 "]\n",
                      consumer->fifo_epoll, nfds, efd, event));

      if (!(event & EPOLLIN)) {
        CcspTraceError(("Event [0x%08" PRIx32 "] "
                        "has bit [0x%08" PRIx32 "] not set\n",
                        event, EPOLLIN));
        continue;
      }

      if (efd == consumer->fifo_fd) {
        CcspTraceDebug(
            ("Reading csi data from fifo fd [%d]\n", consumer->fifo_fd));
        for (;;) {
          fifo_read = read(consumer->fifo_fd, fifo_buf, fifo_payload_size);
          if (fifo_read == -1) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
              break; // no more data to read
            } else {
              CcspTraceError(("Failed to read csi data from fifo fd [%d]\n",
                              consumer->fifo_fd));
              break;
            }
          } else if (fifo_read == 0) {
            break; // end of file
          } else {
            /* There's no distinct data type defined for the CSI payload.
             * However, the format is known:
             * | LABEL + "\0" | TOTAL LENGTH | TIMESTAMP | CSI CLIENT COUNT |
             * (CSI CLIENT COUNT) x
             * | CSI CLIENT MAC | CSI CLIENT DATA LENGTH | CSI CLIENT DATA |
             */

            memcpy(csi_label, fifo_buf, WIFI_CSI_DATA_LABEL_LENGTH);
            if (strncmp(csi_label, WIFI_CSI_DATA_LABEL,
                        WIFI_CSI_DATA_LABEL_LENGTH) != 0) {
              CcspTraceError(
                  ("CSI label changed: received [%s] expected [%s]\n",
                   csi_label, WIFI_CSI_DATA_LABEL));
              break;
            }

            /* TOTAL LENGTH: length of the afterwards following payload.
             * Doesn't account for the label length and the size of itself. */
            memcpy(&csi_data_len, fifo_buf + csi_label_len, sizeof(unsigned int));
            csi_expected_len = csi_label_len + csi_data_len + sizeof(csi_data_len);
            if (fifo_read != (ssize_t)csi_expected_len) {
              CcspTraceError(("Invalid payload read from fifo fd [%d]: "
                              "read [%zd] expected [%zd]\n",
                              consumer->fifo_fd, fifo_read, csi_expected_len));
              break;
            }
            cujoagent_push_to_consumer_queue(consumer,
					     fifo_buf,
					     fifo_payload_size,
					     consumer_event_type_l1,
					     consumer_event_l1_csi_data);
          }
        }
      } else if (efd == consumer->fifo_notification) {
        nbytes = read(efd, &u, sizeof(u));
        if (nbytes < 0) {
          CcspTraceError(("Failed to read event fd [%d]\n", efd));
          continue;
        }
       else {
         CcspTraceDebug(("Read event fd %d bytes\n", nbytes));
       }

        if (u == NOTIFY_FIFO_THREAD_STOP) {
          notify = NOTIFY_FIFO_THREAD_RETURN;
        }

        CcspTraceDebug(("Eventfd notification: "
                        "notify received [%" PRIu64 "] "
                        "notify to be sent [%d]\n",
                        u, notify));

        if (notify == NOTIFY_NONE) {
          CcspTraceError(("Unsupported eventfd notification: "
                          "notify received [%" PRIu64 "] "
                          "notify to be sent [%d]\n",
                          u, notify));
          continue;
        }

        if (notify == NOTIFY_FIFO_THREAD_RETURN) {
          cujoagent_write_event(consumer->fifo_notification_ack, notify);
          goto out;
        }
      }
    }
  }

err:
  if (msg) {
    CcspTraceError(("%s\n", msg));
  }

out:
  free(fifo_buf);
  CcspTraceDebug(("Returning from fifo thread routine\n"));
  return NULL;
}

static int cujoagent_spawn_loop(void *(*start_routine)(void *),
                                cujoagent_wifi_consumer_t *consumer) {
  pthread_attr_t attr;
  pthread_attr_init(&attr);
  pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
  pthread_t thr = 0;

  int err = pthread_create(&thr, &attr, start_routine, consumer);
  if (err) {
    CcspTraceError(("Failed to start loop thread\n"));
  }

  pthread_attr_destroy(&attr);
  return err;
}

static uint64_t cujoagent_timestamp(void) {
  struct timespec ts = {0};
  if (clock_gettime(CLOCK_REALTIME, &ts) != 0) {
    CcspTraceError(("Getting current time failed\n"));
    return 1;
  }

  return (uint64_t)ts.tv_sec * MSECS_PER_SEC +
         (uint64_t)ts.tv_nsec / NSECS_PER_MSEC;
}

static size_t cujoagent_copy_to(char *dst, size_t dst_len, char *src) {
  size_t src_len = strlen(src);
  if (src_len >= dst_len) {
    CcspTraceDebug(("Src buffer doesn't fit into dst buffer\n"));
  }

  size_t min_len = (src_len > dst_len - 1) ? dst_len - 1 : src_len;
  memset(dst, 0, dst_len);
  memcpy(dst, src, min_len);
  return min_len;
}

static wifi_interface_name_idex_map_t *
cujoagent_iface_property(wifi_platform_property_t *wifi_prop,
                         unsigned int vap_index) {
  /* We're copying the relevant structs from a (hopefully) successful
   * webconfig_decode(), so we assume that wifi_prop is valid and we don't need
   * to validate the actual values there. Therefore, just a basic check here.*/
  if (!wifi_prop) {
    CcspTraceError(("Wifi property is invalid\n"));
    return NULL;
  }

  wifi_interface_name_idex_map_t *iface_map = NULL;
  for (int i = 0; i < (int)wifi_prop->numRadios * MAX_NUM_VAP_PER_RADIO; i++) {
    if (wifi_prop->interface_map[i].index == vap_index) {
      iface_map = &wifi_prop->interface_map[i];
      break;
    }
  }

  return iface_map;
}

static int
cujoagent_vap_array_index(wifi_platform_property_t *wifi_prop,
                          wifi_interface_name_idex_map_t *iface_map) {
  /* We're copying the relevant structs from a (hopefully) successful
   * webconfig_decode(), so we assume that wifi_prop is valid and we don't need
   * to validate the actual values there. Therefore, just a basic check here.*/
  if (!wifi_prop || !iface_map) {
    CcspTraceError(("Wifi or iface map property is invalid\n"));
    return -1;
  }

  int vap_array_index = -1;
  for (int i = 0; i < (int)wifi_prop->numRadios * MAX_NUM_VAP_PER_RADIO; i++) {
    if (wifi_prop->interface_map[i].rdk_radio_index ==
        iface_map->rdk_radio_index) {
      vap_array_index++;
    }
    if (wifi_prop->interface_map[i].index == iface_map->index) {
      break;
    }
  }

  return vap_array_index;
}

static wifi_vap_info_t *
cujoagent_vap_index_to_vap_info(cujoagent_wifi_consumer_t *consumer,
                                unsigned int vap_index) {
  wifi_hal_capability_t *hal_cap = &consumer->hal_cap;
  wifi_platform_property_t *wifi_prop = &hal_cap->wifi_prop;

  wifi_interface_name_idex_map_t *iface_map = NULL;
  rdk_wifi_radio_t *radio = NULL;
  int vap_array_index = -1;

  iface_map = cujoagent_iface_property(wifi_prop, vap_index);
  if (!iface_map) {
    CcspTraceError(
        ("Couldn't find interface map for vap index [%u]\n", vap_index));
    return NULL;
  }

  radio = &consumer->radios[iface_map->rdk_radio_index];
  vap_array_index = cujoagent_vap_array_index(wifi_prop, iface_map);
  if (vap_array_index == -1) {
    CcspTraceError(("Couldn't find vap array index for iface map index [%u]\n",
                    iface_map->index));
    return NULL;
  }

  return &radio->vaps.vap_map.vap_array[vap_array_index];
}

static int cujoagent_event_type(client_state_t client_state) {
  int event_type = -1;
  switch (client_state) {
  case client_state_connected:
    event_type = CUJO_FPC_CONNECT;
    break;
  case client_state_disconnected:
    event_type = CUJO_FPC_DISCONNECT;
    break;
  default:
    break;
  }
  return event_type;
}

static void cujoagent_new_station_event(
    struct cujo_fpc_wifi_station_event **event,
    size_t *station_update_event_size,
    assoc_dev_data_t *diff_assoc_dev_data,
    wifi_vap_info_t *vap_info,
    cujoagent_wifi_consumer_t *consumer) {
  unsigned int client_count = 0;
  unsigned int assoc_dev_count = 0;
  size_t ssid_len = 0;
  hash_map_t *assoc_dev_map = NULL;
  assoc_dev_data_t *assoc_dev_data = NULL;
  wifi_interface_name_idex_map_t *iface_map = NULL;

  /* Count clients across _all_ VAPs of interest */
  *station_update_event_size = sizeof(struct cujo_fpc_wifi_station_event);
  for (unsigned int i = 0; i < consumer->hal_cap.wifi_prop.numRadios; i++) {
    for (unsigned int j = 0; j < consumer->vap_subs_count; j++) {
      assoc_dev_map = consumer->radios[i]
                          .vaps.rdk_vap_array[consumer->vap_subs_indexes[j]]
                          .associated_devices_map;
      if (assoc_dev_map) {
        assoc_dev_count = hash_map_count(assoc_dev_map);
        *station_update_event_size +=
            assoc_dev_count * sizeof(struct cujo_fpc_assoc_station_info);
        client_count += assoc_dev_count;
      }
    }
  }

  *event = calloc(1, *station_update_event_size);
  if (*event == NULL) {
    CcspTraceError(("Failed to allocate station update event\n"));
    return;
  }

  /* Populate the station update event with the list of _all_ connected clients */
  for (unsigned int i = 0, offset = 0; i < consumer->hal_cap.wifi_prop.numRadios; i++) {
    for (unsigned int j = 0; j < consumer->vap_subs_count; j++) {
      assoc_dev_map = consumer->radios[i]
                          .vaps.rdk_vap_array[consumer->vap_subs_indexes[j]]
                          .associated_devices_map;
      if (assoc_dev_map) {
        /* We need the if_name of the VAP each client is connected to, not the
         * if_name of the VAP where the particular (dis)connect event happened.
         * Therefore, get the iface_map here rather than passing it as an
         * argument from the diff map we are processing the particular station
         * event for. */
        iface_map = cujoagent_iface_property(
            &consumer->hal_cap.wifi_prop,
            consumer->radios[i]
                .vaps.rdk_vap_array[consumer->vap_subs_indexes[j]]
                .vap_index);
        if (!iface_map) {
          CcspTraceError(("Couldn't find interface map for vap index [%u]\n",
                          consumer->radios[i]
                              .vaps.rdk_vap_array[consumer->vap_subs_indexes[j]]
                              .vap_index));
          break;
        }

        assoc_dev_count = hash_map_count(assoc_dev_map);
        assoc_dev_data = hash_map_get_first(assoc_dev_map);
        for (unsigned int k = 0; assoc_dev_data; k++) {
          memcpy((*event)->assoc_station_info[offset + k].mac.ether_addr_octet,
                 assoc_dev_data->dev_stats.cli_MACAddress,
                 ETH_ALEN);
          cujoagent_copy_to((*event)->assoc_station_info[offset + k].if_name,
                            IF_NAMESIZE,
                            iface_map->interface_name);
          /* FIXME: Hard-coding AUTO */
          (*event)->assoc_station_info[offset + k].operating_mode =
              CUJO_FPC_WIFI_MODE_AUTO;
          assoc_dev_data = hash_map_get_next(assoc_dev_map, assoc_dev_data);
        }
        offset += assoc_dev_count;
      }
    }
  }

  (*event)->assoc_station_count = client_count;
  (*event)->event_type = cujoagent_event_type(diff_assoc_dev_data->client_state);
  (*event)->timestamp_ms = cujoagent_timestamp();
  (*event)->vap_index = vap_info->vap_index;
  ssid_len = cujoagent_copy_to((char *)(*event)->essid,
                               sizeof((*event)->essid),
                               vap_info->u.sta_info.ssid);
  (*event)->essid_length = ssid_len;
}

static int cujoagent_freq_band(wifi_freq_bands_t oper_band) {
  int band = -1;
  switch (oper_band) {
  case WIFI_FREQUENCY_2_4_BAND:
    band = CUJO_FPC_WIFI_FREQ_2_4;
    break;
  case WIFI_FREQUENCY_5_BAND:
  case WIFI_FREQUENCY_5L_BAND:
  case WIFI_FREQUENCY_5H_BAND:
    band = CUJO_FPC_WIFI_FREQ_5;
    break;
  case WIFI_FREQUENCY_6_BAND:
  case WIFI_FREQUENCY_60_BAND:
    band = CUJO_FPC_WIFI_FREQ_6;
    break;
  default:
    break;
  }
  return band;
}

static void cujoagent_new_radio_event(struct cujo_fpc_radio_event *event,
                                      assoc_dev_data_t *diff_assoc_dev_data,
                                      wifi_interface_name_idex_map_t *iface_map,
                                      rdk_wifi_radio_t *radio,
                                      wifi_vap_info_t *vap_info) {
  event->event_type = cujoagent_event_type(diff_assoc_dev_data->client_state);
  event->timestamp_ms = cujoagent_timestamp();
  cujoagent_copy_to(event->if_name,
                    sizeof(event->if_name),
                    iface_map->interface_name);
  event->vap_index = vap_info->vap_index;
  event->freq_band = cujoagent_freq_band(radio->oper.band);
  event->channel = radio->oper.channel;

  /* FIXME: Needs proper translation from radio_oper fields and bitmasks. And
   * even then that will be the radio's operating mode, not the station's.
   * Probably not worth the hassle, hard-coding to auto for now. */
  event->operating_mode = CUJO_FPC_WIFI_MODE_AUTO;

  memcpy(event->bssid.ether_addr_octet, vap_info->u.bss_info.bssid, ETH_ALEN);
  size_t ssid_len = cujoagent_copy_to((char *)event->essid,
                                      sizeof(event->essid),
                                      vap_info->u.sta_info.ssid);
  event->essid_length = ssid_len;
  memcpy(event->station_mac.ether_addr_octet,
         diff_assoc_dev_data->dev_stats.cli_MACAddress,
         ETH_ALEN);
}

static void
cujoagent_print_events(struct cujo_fpc_radio_event *radio_event,
                       struct cujo_fpc_wifi_station_event *station_event,
                       struct cujo_fpc_wifi_data_batch_event *batch_event,
                       struct cujo_fpc_csi_and_cfo_data_event *csi_cfo_event,
                       struct cujo_fpc_temperature_data_event *temperature_event) {
  char da[MAX_MAC_STR_LEN + 1] = {0};
  char sa[MAX_MAC_STR_LEN + 1] = {0};
  char bssid[MAX_MAC_STR_LEN + 1] = {0};

  if (radio_event) {
    CcspTraceDebug(
        ("CUJO_WIFI_RADIO_UPDATE_EVENT: "
         "event_type [%d] timestamp_ms [%" PRIu64 "] "
         "if_name [%s] vap_index [%u] freq_band [%d] channel [%u] "
         "operating_mode [%d] bssid [%s] essid [%s] "
         "essid length [%d] mac [%s] station_update_event_count [%d]\n",
         radio_event->event_type, radio_event->timestamp_ms,
         radio_event->if_name, radio_event->vap_index, radio_event->freq_band,
         radio_event->channel, radio_event->operating_mode,
         ether_ntoa_r(&radio_event->bssid, bssid), radio_event->essid,
         radio_event->essid_length, ether_ntoa_r(&radio_event->station_mac, sa),
         radio_event->station_update_event_count));
  }

  if (station_event) {
    CcspTraceDebug(("CUJO_WIFI_STATION_UPDATE_EVENT: "
                    "event_type [%d] timestamp_ms [%" PRIu64 "] "
                    "vap_index [%u] assoc_station_count [%u]\n",
                    station_event->event_type, station_event->timestamp_ms,
                    station_event->vap_index,
                    station_event->assoc_station_count));

    for (unsigned int i = 0; i < station_event->assoc_station_count; i++) {
      CcspTraceDebug(
          ("CUJO_WIFI_STATION_UPDATE_EVENT: "
           "station [%u]: mac [%s] if_name [%s] operating_mode [%d]\n",
           i, ether_ntoa_r(&station_event->assoc_station_info[i].mac, sa),
           station_event->assoc_station_info[i].if_name,
           station_event->assoc_station_info[i].operating_mode));
    }
  }

  if (batch_event) {
    CcspTraceDebug(("CUJO_WIFI_DATA_BATCH_EVENT: "
                    "timestamp_ms [%" PRIu64 "] "
                    "vap_index [%u] mac [%s] wifi_captures_count [%u]\n",
                    batch_event->timestamp_ms, batch_event->vap_index,
                    ether_ntoa_r(&batch_event->mac, sa),
                    batch_event->wifi_captures_count));

    struct cujo_fpc_wifi_pcap *pcap = NULL;
    uint64_t pcap_ts = 0;

    uint8_t version = 0;
    uint16_t hdrlen = 0;
    uint16_t fc = 0, duration = 0;
    uint16_t addr1 = 0, addr2 = 0, addr3 = 0;

    for (unsigned int i = 0, offset = 0; i < batch_event->wifi_captures_count; i++) {
      pcap = (struct cujo_fpc_wifi_pcap *)(batch_event->wifi_captures + offset);
      if (pcap->has_radiotap_header){
        version = pcap->data[0];
        hdrlen = le16toh(*(uint16_t *)&pcap->data[2]);
        CcspTraceDebug(("CUJO_WIFI_DATA_BATCH_EVENT: "
                        "radiotap [%u]: version [%" PRIu8 "] len [%" PRIu16 "]\n",
                        i, version, hdrlen));
      }

      pcap_ts = (uint64_t)pcap->header.ts.tv_sec * MSECS_PER_SEC +
                (uint64_t)pcap->header.ts.tv_usec / USECS_PER_MSEC;
      CcspTraceDebug(("CUJO_WIFI_DATA_BATCH_EVENT: "
                      "pcap_pkthdr [%u]: timestamp_ms [%" PRIu64 "] "
                      "caplen [%" PRIu32 "] len [%" PRIu32 "]\n",
                      i, pcap_ts, pcap->header.caplen, pcap->header.len));

      fc = le16toh(*(uint16_t *)&pcap->data[hdrlen]);
      duration = le16toh(*(uint16_t *)&pcap->data[hdrlen + sizeof fc]);
      addr1 = hdrlen + sizeof fc + sizeof duration;
      addr2 = addr1 + sizeof(struct ether_addr);
      addr3 = addr2 + sizeof(struct ether_addr);
      CcspTraceDebug(
          ("CUJO_WIFI_DATA_BATCH_EVENT: "
           "ieee frame [%u]: fc [0x%04x] da[%s] sa[%s] bssid[%s]\n",
           i, fc, ether_ntoa_r((struct ether_addr *)&pcap->data[addr1], da),
           ether_ntoa_r((struct ether_addr *)&pcap->data[addr2], sa),
           ether_ntoa_r((struct ether_addr *)&pcap->data[addr3], bssid)));

      offset += sizeof(struct cujo_fpc_wifi_pcap) + pcap->header.caplen;
    }
  }

  if (csi_cfo_event) {
    CcspTraceDebug(("CUJO_FPC_CSI_AND_CFO_DATA_EVENT: "
                    "vap_index [%u] mac [%s] csi_count [%u]\n",
                    csi_cfo_event->vap_index,
                    ether_ntoa_r(&csi_cfo_event->mac, sa),
                    csi_cfo_event->csi_count));

    struct cujo_fpc_csi_and_cfo_reading *csi_cfo_reading = NULL;
    for (unsigned int i = 0, offset = 0; i < csi_cfo_event->csi_count; i++) {
      csi_cfo_reading =
          (struct cujo_fpc_csi_and_cfo_reading *)(csi_cfo_event->csi + offset);

      CcspTraceDebug(("CUJO_FPC_CSI_AND_CFO_READING[%u]: "
                      "timestamp_ms [%" PRIu64 "] data_len [%u] "
                      "cfo [%" PRIi32 "]\n",
                      i,
                      csi_cfo_reading->timestamp_ms,
                      csi_cfo_reading->data_len,
                      csi_cfo_reading->cfo));

      CcspTraceDebug(("CUJO_FPC_CSI_AND_CFO_READING[%u]: csi_metadata: "
                      "bw_mode [%" PRIu8 "] num_rx_antennae [%" PRIu8 "] "
                      "num_tx_streams [%" PRIu8 "] RSSI[0] [%" PRIi32 "] "
                      "router_bw [%" PRIu16 "] station_bw [%" PRIu16 "] "
                      "tones_mask [0x%hx] num_subcarriers [%" PRIu32 "] "
                      "decimation_factor [%" PRIu8 "] channel [%" PRIu32 "]\n",
                      i,
                      csi_cfo_reading->csi_metadata.bw_mode,
                      csi_cfo_reading->csi_metadata.num_rx_antennae,
                      csi_cfo_reading->csi_metadata.num_tx_streams,
                      csi_cfo_reading->csi_metadata.rssi[0],
                      csi_cfo_reading->csi_metadata.router_bw,
                      csi_cfo_reading->csi_metadata.station_bw,
                      csi_cfo_reading->csi_metadata.tones_mask,
                      csi_cfo_reading->csi_metadata.num_subcarriers,
                      csi_cfo_reading->csi_metadata.decimation_factor,
                      csi_cfo_reading->csi_metadata.channel));

      offset += sizeof(struct cujo_fpc_csi_and_cfo_reading) +
                csi_cfo_reading->data_len;
    }
  }

  if (temperature_event) {
    CcspTraceDebug(("CUJO_FPC_TEMPERATURE_DATA_EVENT: "
                    "timestamp_ms [%" PRIu64 "] "
                    "temperatures_count [%" PRIu32 "]\n",
                    temperature_event->timestamp_ms,
                    temperature_event->temperatures_count));
    for (unsigned int i = 0; i < temperature_event->temperatures_count; i++) {
      CcspTraceDebug(("CUJO_FPC_TEMPERATURE_READING[%u]: [%" PRIi32 "]\n",
                      i, temperature_event->temperatures[i]));
    }
  }
}

static void cujoagent_free_decoded_macfilter_entries(
    webconfig_subdoc_decoded_data_t *decoded_params) {
  if (!decoded_params) {
    CcspTraceError(("Decoded params invalid\n"));
    return;
  }

  unsigned int i = 0, j = 0;
  hash_map_t *acl_map = NULL;
  acl_entry_t *temp_acl_entry = NULL, *acl_entry = NULL;
  mac_addr_str_t mac_str = {0};

  for (i = 0; i < decoded_params->hal_cap.wifi_prop.numRadios; i++) {
    for (j = 0; j < decoded_params->radios[i].vaps.num_vaps; j++) {
      acl_map = decoded_params->radios[i].vaps.rdk_vap_array[j].acl_map;
      if (acl_map) {
        CcspTraceDebug(("Processing decoded [%p] ACL map\n", (void *)acl_map));
        acl_entry = hash_map_get_first(acl_map);
        while (acl_entry) {
          CcspTraceDebug(
              ("Processing decoded [%p] ACL entry\n", (void *)acl_entry));
          cujoagent_bytes_to_mac_str(acl_entry->mac, mac_str);
          acl_entry = hash_map_get_next(acl_map, acl_entry);
          temp_acl_entry = hash_map_remove(acl_map, mac_str);
          if (temp_acl_entry) {
            CcspTraceDebug(("Freeing [%p] mac [%s] from decoded ACL map [%p]\n",
                            (void *)temp_acl_entry, mac_str, (void *)acl_map));
            free(temp_acl_entry);
          }
        }
        CcspTraceDebug(("Destroying [%p] decoded ACL map\n", (void *)acl_map));
        hash_map_destroy(acl_map);
        decoded_params->radios[i].vaps.rdk_vap_array[j].acl_map = NULL;
      }
    }
  }
}

static void
cujoagent_add_device_to_associated_device_map(mac_address_t mac,
                                              hash_map_t *assoc_dev_map,
                                              assoc_dev_data_t *assoc_dev_data) {
  if (!assoc_dev_map || !assoc_dev_data) {
    CcspTraceError(("Associated device map [%p] or client data [%p] invalid\n",
                    (void *)assoc_dev_map, (void *)assoc_dev_data));
    return;
  }

  mac_addr_str_t mac_str = {0};
  cujoagent_bytes_to_mac_str(mac, mac_str);
  assoc_dev_data_t *temp_assoc_dev_data = NULL;

  temp_assoc_dev_data = hash_map_get(assoc_dev_map, mac_str);
  if (!temp_assoc_dev_data) {
    temp_assoc_dev_data = malloc(sizeof(assoc_dev_data_t));
    if (temp_assoc_dev_data == NULL) {
      CcspTraceError(("Failed to allocate a mac [%s]\n", mac_str));
      return;
    }
    *temp_assoc_dev_data = *assoc_dev_data;
    CcspTraceDebug(("Adding [%p] mac [%s] to assoc map [%p]\n",
                    (void *)temp_assoc_dev_data, mac_str,
                    (void *)assoc_dev_map));
    hash_map_put(assoc_dev_map, strdup(mac_str), temp_assoc_dev_data);
  } else {
    CcspTraceDebug(("The mac [%s] is already present [%p] "
                    "in assoc map [%p], updating it\n",
                    mac_str, (void *)temp_assoc_dev_data,
                    (void *)assoc_dev_map));
    *temp_assoc_dev_data = *assoc_dev_data;
  }
}

static void
cujoagent_remove_device_from_associated_devices_map(mac_address_t mac,
                                                    hash_map_t *assoc_dev_map) {
  if (!assoc_dev_map) {
    CcspTraceError(("Associated device map invalid [%p]\n",
                    (void *)assoc_dev_map));
    return;
  }

  mac_addr_str_t mac_str = {0};
  cujoagent_bytes_to_mac_str(mac, mac_str);

  assoc_dev_data_t *assoc_dev_data = hash_map_remove(assoc_dev_map, mac_str);
  if (assoc_dev_data) {
    CcspTraceDebug(("Freeing [%p] mac [%s] from assoc device map [%p]\n",
                    (void *)assoc_dev_data, mac_str, (void *)assoc_dev_map));
    free(assoc_dev_data);
  } else {
    CcspTraceDebug(("The mac [%s] is not in assoc map [%p]\n",
                    mac_str, (void *)assoc_dev_map));
  }
}

static void
cujoagent_update_associated_devices_map(hash_map_t *assoc_dev_map,
                                        assoc_dev_data_t *assoc_dev_data) {
  if (!assoc_dev_map || !assoc_dev_data) {
    CcspTraceError(("Associated device map [%p] or client data [%p] invalid\n",
                    (void *)assoc_dev_map, (void *)assoc_dev_data));
    return;
  }

  if (assoc_dev_data->client_state == client_state_disconnected) {
    cujoagent_remove_device_from_associated_devices_map(
        assoc_dev_data->dev_stats.cli_MACAddress,
        assoc_dev_map);
  } else if (assoc_dev_data->client_state == client_state_connected) {
    cujoagent_add_device_to_associated_device_map(
        assoc_dev_data->dev_stats.cli_MACAddress,
        assoc_dev_map,
        assoc_dev_data);
  }
}

static void
cujoagent_free_all_associated_devices_maps(rdk_wifi_radio_t *radios,
                                           unsigned int num_radios) {
  if (!radios) {
    CcspTraceError(("Radios invalid\n"));
    return;
  }

  hash_map_t *assoc_dev_map = NULL;
  assoc_dev_data_t *assoc_dev_data = NULL;
  assoc_dev_data_t *temp_assoc_dev_data = NULL;
  mac_addr_str_t mac_str = {0};

  for (unsigned int i = 0; i < num_radios; i++) {
    for (unsigned int j = 0; j < radios[i].vaps.num_vaps; j++) {
      /* Full associated device map */
      assoc_dev_map = radios[i].vaps.rdk_vap_array[j].associated_devices_map;
      if (assoc_dev_map) {
        CcspTraceDebug(("Processing [%p] full associated device map\n",
                        (void *)assoc_dev_map));
        assoc_dev_data = hash_map_get_first(assoc_dev_map);
        while (assoc_dev_data) {
          CcspTraceDebug(("Processing [%p] full associated device data\n",
                          (void *)assoc_dev_data));
          cujoagent_bytes_to_mac_str(assoc_dev_data->dev_stats.cli_MACAddress,
                                     mac_str);
          assoc_dev_data = hash_map_get_next(assoc_dev_map, assoc_dev_data);
          temp_assoc_dev_data = hash_map_remove(assoc_dev_map, mac_str);
          if (temp_assoc_dev_data) {
            CcspTraceDebug(
                ("Freeing [%p] mac [%s] from full associated device map [%p]\n",
                 (void *)temp_assoc_dev_data, mac_str, (void *)assoc_dev_map));
            free(temp_assoc_dev_data);
          }
        }
        CcspTraceDebug(("Destroying [%p] full associated device map\n",
                        (void *)assoc_dev_map));
        hash_map_destroy(assoc_dev_map);
        radios[i].vaps.rdk_vap_array[j].associated_devices_map = NULL;
      }

      /* Diff associated device map */
      assoc_dev_map =
          radios[i].vaps.rdk_vap_array[j].associated_devices_diff_map;
      if (assoc_dev_map) {
        CcspTraceDebug(("Processing [%p] diff associated device map\n",
                        (void *)assoc_dev_map));
        assoc_dev_data = hash_map_get_first(assoc_dev_map);
        while (assoc_dev_data) {
          CcspTraceDebug(("Processing [%p] diff associated device data\n",
                          (void *)assoc_dev_data));
          cujoagent_bytes_to_mac_str(assoc_dev_data->dev_stats.cli_MACAddress,
                                     mac_str);
          assoc_dev_data = hash_map_get_next(assoc_dev_map, assoc_dev_data);
          temp_assoc_dev_data = hash_map_remove(assoc_dev_map, mac_str);
          if (temp_assoc_dev_data) {
            CcspTraceDebug(
                ("Freeing [%p] mac [%s] from diff associated device map [%p]\n",
                 (void *)temp_assoc_dev_data, mac_str, (void *)assoc_dev_map));
            free(temp_assoc_dev_data);
          }
        }
        CcspTraceDebug(("Destroying [%p] diff associated device map\n",
                        (void *)assoc_dev_map));
        hash_map_destroy(assoc_dev_map);
        radios[i].vaps.rdk_vap_array[j].associated_devices_diff_map = NULL;
      }
    }
  }
}

static void
cujoagent_process_client_state(client_state_t client_state,
                               webconfig_subdoc_decoded_data_t *decoded_params,
                               cujoagent_wifi_consumer_t *consumer) {
  int vap_array_index = 0;
  wifi_interface_name_idex_map_t *iface_map = NULL;
  rdk_wifi_radio_t *radio = NULL;
  wifi_vap_info_t *vap_info = NULL;

  hash_map_t *assoc_dev_map = NULL;
  hash_map_t *assoc_dev_diff_map = NULL;
  assoc_dev_data_t *diff_assoc_dev_data = NULL;
  mac_addr_str_t mac_in_diff_map = {0};

  struct cujo_fpc_wifi_station_event *station_update_event = NULL;
  size_t station_update_event_size = 0;
  struct cujo_fpc_radio_event radio_update_event = {0};
  size_t radio_update_event_size = sizeof radio_update_event;

  bool should_send_done = false;
  cujoagent_l1_collector_t *collector = NULL;
  struct cujo_fpc_l1_collection_done done = {0};

  for (unsigned int i = 0; i < consumer->hal_cap.wifi_prop.numRadios; i++) {
    for (unsigned int j = 0; j < consumer->vap_subs_count; j++) {
      vap_array_index = consumer->vap_subs_indexes[j];
      iface_map =
          cujoagent_iface_property(&decoded_params->hal_cap.wifi_prop,
                                   decoded_params->radios[i]
                                       .vaps.rdk_vap_array[vap_array_index]
                                       .vap_index);
      if (!iface_map) {
        CcspTraceError(("Couldn't find interface map for vap index [%u]\n",
                        decoded_params->radios[i]
                            .vaps.rdk_vap_array[vap_array_index]
                            .vap_index));
        continue;
      }
      radio = &decoded_params->radios[iface_map->rdk_radio_index];
      vap_info = &radio->vaps.vap_map.vap_array[vap_array_index];

      assoc_dev_diff_map = decoded_params->radios[i]
                               .vaps.rdk_vap_array[vap_array_index]
                               .associated_devices_diff_map;
      if (assoc_dev_diff_map) {
        /* It might be the very first connect to the VAP,
         * create consumer's full map for those cases. */
        if (consumer->radios[i]
                .vaps.rdk_vap_array[vap_array_index]
                .associated_devices_map == NULL) {
          consumer->radios[i]
              .vaps.rdk_vap_array[vap_array_index]
              .associated_devices_map = hash_map_create();
          CcspTraceDebug(("New associated_devices_map created [%p]\n",
                          (void *)consumer->radios[i]
                              .vaps.rdk_vap_array[vap_array_index]
                              .associated_devices_map));
        }
        assoc_dev_map = consumer->radios[i]
                            .vaps.rdk_vap_array[vap_array_index]
                            .associated_devices_map;

        diff_assoc_dev_data = hash_map_get_first(assoc_dev_diff_map);
        while (diff_assoc_dev_data) {
          if (diff_assoc_dev_data->client_state == client_state) {
            cujoagent_bytes_to_mac_str(
                diff_assoc_dev_data->dev_stats.cli_MACAddress,
                mac_in_diff_map);

            /* NOTE: we can continue to processing next device in list only
             * after we update the consumer maintained full map. */
            CcspTraceDebug(("Updating the full map [%p] with the mac [%s] "
                            "from diff map [%p]\n",
                            (void *)assoc_dev_map,
                            mac_in_diff_map,
                            (void *)assoc_dev_diff_map));
            cujoagent_update_associated_devices_map(assoc_dev_map,
                                                    diff_assoc_dev_data);

            CcspTraceDebug(("Processing mac [%s] in client state [%d] "
                            "on diff map [%p] for vap index [%u]\n",
                            mac_in_diff_map,
                            diff_assoc_dev_data->client_state,
                            assoc_dev_diff_map,
                            decoded_params->radios[i]
                                .vaps.rdk_vap_array[vap_array_index]
                                .vap_index));

            /* For disconnects, DONE must be sent _before_ the radio|station
             * update event. Therefore, stop the L1 collection for the
             * disconnecting MAC first (stopping it will skip pushing the DONE
             * to the consumer queue) and then send DONE ahead of the sending of
             * radio|station update events. */
            if (client_state == client_state_disconnected) {
              should_send_done = false;

              /* XXX: Obey the lock order: consumer lock first (we are in the
               * consumer thread already), then the collector lock. */
              pthread_mutex_lock(&consumer->l1_lock);
              for (int k = 0; k < DCL_MAX_CSI_CLIENTS; k++) {
                if (consumer->l1_collections[k] == NULL ||
                    memcmp(
                        consumer->l1_collections[k]->start.mac.ether_addr_octet,
                        diff_assoc_dev_data->dev_stats.cli_MACAddress,
                        ETH_ALEN) != 0) {
                  continue;
                }
                should_send_done = true;
                collector = consumer->l1_collections[k];

                CcspTraceDebug(("Stopping L1 collector for mac [%s]\n", mac_in_diff_map));
                if ((cujoagent_write_event(collector->notification,
                                           NOTIFY_L1_COLLECTION_THREAD_STOP) == -1) ||
                    (cujoagent_wait_for_event(consumer->queue_epoll,
                                              NOTIFY_L1_COLLECTION_THREAD_RETURN,
                                              EPOLL_TIMEOUT_MS) <= 0)) {
                  CcspTraceWarning(("Failed to notify L1 collector thread for "
                                    "mac [%s] to stop\n",
                                    mac_in_diff_map));
                }
              }
              pthread_mutex_unlock(&consumer->l1_lock);

              if (should_send_done) {
                if (!consumer->comms_ready) {
                  CcspTraceWarning(
                      ("Not yet ready to send DONE tlv data for mac [%s] "
                       "in state [%d]\n",
                       mac_in_diff_map, diff_assoc_dev_data->client_state));
                  diff_assoc_dev_data = hash_map_get_next(assoc_dev_diff_map,
                                                          diff_assoc_dev_data);
                  continue;
                }

                done.vap_index = decoded_params->radios[i]
                                     .vaps.rdk_vap_array[vap_array_index]
                                     .vap_index;
                memcpy(done.mac.ether_addr_octet,
                       diff_assoc_dev_data->dev_stats.cli_MACAddress,
                       ETH_ALEN);
                if (cujoagent_emit_event_tlv(CUJO_FPC_L1_COLLECTION_DONE,
                                             &done,
                                             sizeof(done),
                                             consumer) != 0) {
                  diff_assoc_dev_data = hash_map_get_next(assoc_dev_diff_map,
                                                          diff_assoc_dev_data);
                  continue;
                }
                CcspTraceDebug(("CUJO_FPC_L1_COLLECTION_DONE: "
                                "vap_index [%u] mac [%s]\n",
                                done.vap_index, mac_in_diff_map));
              } // should send done
            } // separate case for disconnects

            if (!consumer->comms_ready) {
              CcspTraceWarning(("Not yet ready to send radio and station tlv "
                                "data for mac [%s] in state [%d]\n",
                                mac_in_diff_map,
                                diff_assoc_dev_data->client_state));
              diff_assoc_dev_data = hash_map_get_next(assoc_dev_diff_map,
                                                      diff_assoc_dev_data);
              continue;
            }

            cujoagent_new_station_event(&station_update_event,
                                        &station_update_event_size,
                                        diff_assoc_dev_data,
                                        vap_info,
                                        consumer);
            if (cujoagent_emit_event_tlv(CUJO_FPC_WIFI_STATION_UPDATE_EVENT,
                                         station_update_event,
                                         station_update_event_size,
                                         consumer) != 0) {
              free(station_update_event);
              station_update_event = NULL;
              diff_assoc_dev_data = hash_map_get_next(assoc_dev_diff_map,
                                                      diff_assoc_dev_data);
              continue;
            }

            cujoagent_new_radio_event(&radio_update_event,
                                      diff_assoc_dev_data,
                                      iface_map,
                                      radio,
                                      vap_info);
            /* Sending radio update event for every station update event */
            radio_update_event.station_update_event_count = 1;
            if (cujoagent_emit_event_tlv(CUJO_FPC_WIFI_RADIO_UPDATE_EVENT,
                                         &radio_update_event,
                                         radio_update_event_size,
                                         consumer) != 0) {
              free(station_update_event);
              station_update_event = NULL;
              diff_assoc_dev_data = hash_map_get_next(assoc_dev_diff_map,
                                                      diff_assoc_dev_data);
              continue;
            }

            cujoagent_print_events(&radio_update_event,
                                   station_update_event,
                                   NULL, NULL, NULL);

            free(station_update_event);
            station_update_event = NULL;
          } // process only the desired client state
          diff_assoc_dev_data = hash_map_get_next(assoc_dev_diff_map,
                                                  diff_assoc_dev_data);
        } // devices in diff map
      } // diff map exists
    } // vaps of interest
  } // radios
}

static void
cujoagent_process_webconfig_event(cujoagent_wifi_consumer_t *consumer,
                                  char const *s,
                                  __attribute__((unused)) size_t slen,
                                  cujoagent_consumer_event_subtype_t subtype) {
  webconfig_subdoc_data_t *data = calloc(1, sizeof(webconfig_subdoc_data_t));
  if (data == NULL) {
    CcspTraceError(("Failed to allocate memory for webconfig subdoc data\n"));
    return;
  }
  webconfig_subdoc_decoded_data_t *decoded_params = &data->u.decoded;

  /* Depending on the subdoc type the relevant structures have to be populated
   * for a successful webconfig_decode(). */
  cujoagent_update_decoded_wifi_structs(consumer, decoded_params);

  webconfig_error_t err = webconfig_decode(&consumer->webconfig, data, s);
  if (err) {
    CcspTraceError(("Webconfig decode failed with [%d]\n", err));
    free(data);
    return;
  }

  webconfig_subdoc_type_t subdoc_type = data->type;
  CcspTraceDebug(("Processing webconfig subdoc type [%d]\n", subdoc_type));
  switch (subtype) {
  case consumer_event_webconfig_init:
    /* A special case where we need to notify the main thread that decoding
     * initial webconfig data is finished and consumer structures are updated,
     * so the subscription to the RBUS can continue. */

    /* De-allocate ACL maps, we do not consume ACL data in any way. */
    cujoagent_free_decoded_macfilter_entries(decoded_params);

    /* Update the consumer, so that the relevant data is updated for the
     * next callbacks. */
    cujoagent_update_consumer_wifi_structs(consumer, decoded_params);
    cujoagent_write_event(consumer->misc_notification,
                          NOTIFY_WEBCONFIG_INIT_READY);
    break; // consumer_event_webconfig_init
  case consumer_event_webconfig_set_data:
    switch (subdoc_type) {
    case webconfig_subdoc_type_associated_clients:
      if (decoded_params->assoclist_notifier_type == assoclist_notifier_full) {
        cujoagent_free_all_associated_devices_maps(
            consumer->radios, consumer->hal_cap.wifi_prop.numRadios);
      }
      break; // webconfig_subdoc_type_associated_clients
    default:
      break;
    }

    /* De-allocate ACL maps, we do not consume ACL data in any way. */
    cujoagent_free_decoded_macfilter_entries(decoded_params);

    /* Update the consumer, so that the relevant data is updated for the
     * next callbacks. */
    cujoagent_update_consumer_wifi_structs(consumer, decoded_params);

    break; // consumer_event_webconfig_set_data
  case consumer_event_webconfig_get_data:
    switch (subdoc_type) {
    case webconfig_subdoc_type_associated_clients:
      /* Just update the consumer maintained full connected client list.
       * There's no client state at this point, therefore, we can't send
       * CUJO_FPC_{DIS}CONNECT events. */
      if (decoded_params->assoclist_notifier_type == assoclist_notifier_full) {
        cujoagent_free_all_associated_devices_maps(
            consumer->radios, consumer->hal_cap.wifi_prop.numRadios);
        cujoagent_update_consumer_wifi_structs(consumer, decoded_params);
      }

      /* Process the diff assoc list and send appropriate CUJO_FPC_{DIS}CONNECT
       * events based on the client state in that list. */
      if (decoded_params->assoclist_notifier_type == assoclist_notifier_diff) {
        /* Process disconnects first for cases stations jump between bands */
        cujoagent_process_client_state(client_state_disconnected,
                                       decoded_params, consumer);
        cujoagent_process_client_state(client_state_connected,
                                       decoded_params, consumer);
        cujoagent_free_all_associated_devices_maps(decoded_params->radios,
                                                   decoded_params->num_radios);
      }
      break; // webconfig_subdoc_type_associated_clients
    default:
      break;
    }
    break; // consumer_event_webconfig_get_data
  default:
    break; // default
  }

  webconfig_data_free(data);
  free(data);
}

static void cujoagent_new_wifi_pcap(struct cujo_fpc_wifi_pcap *pcap,
                                    size_t data_size, frame_data_t *rdk_mgmt) {
  /* FIXME: timestamp is not yet available in the RBUS payload */
  struct timeval tv = {0};
  gettimeofday(&tv, NULL);
  memcpy(&pcap->header.ts, &tv, sizeof(pcap->header.ts));

  /* Assuming no partial packet captures */
  pcap->header.caplen = data_size;
  pcap->header.len = data_size;

  /* FIXME: Fake empty radiotap header */
  uint8_t rt[EMPTY_RT_LEN] = {0x00, 0x00, EMPTY_RT_LEN, 0x00, 0x00, 0x00, 0x00, 0x00};
  pcap->has_radiotap_header = 1;

  memcpy(pcap->data, &rt, EMPTY_RT_LEN);
  memcpy(pcap->data + EMPTY_RT_LEN, rdk_mgmt->data, rdk_mgmt->frame.len);
}

static int cujoagent_new_data_batch_event(
    struct cujo_fpc_wifi_data_batch_event *event,
    struct cujo_fpc_wifi_pcap *pcap, size_t pcap_size,
    cujoagent_wifi_consumer_t *consumer, frame_data_t *rdk_mgmt) {
  wifi_vap_info_t *vap_info =
      cujoagent_vap_index_to_vap_info(consumer, rdk_mgmt->frame.ap_index);
  if (!vap_info) {
    CcspTraceError(("Couldn't find vap info for vap index [%u]\n",
                    rdk_mgmt->frame.ap_index));
    return -1;
  }

  /* An event for each received frame. */
  event->wifi_captures_count = 1;
  event->timestamp_ms = cujoagent_timestamp();
  event->vap_index = rdk_mgmt->frame.ap_index;
  memcpy(event->mac.ether_addr_octet, vap_info->u.bss_info.bssid, ETH_ALEN);
  memcpy(event->wifi_captures, pcap, pcap_size);
  return 0;
}

static void
cujoagent_process_mgmt_frame_event(cujoagent_wifi_consumer_t *consumer,
                                   frame_data_t *rdk_mgmt,
                                   __attribute__((unused)) size_t rdk_mgmt_len,
                                   cujoagent_consumer_event_subtype_t subtype) {
  mac_addr_str_t sta_mac = {0};
  cujoagent_bytes_to_mac_str(rdk_mgmt->frame.sta_mac, sta_mac);

  /* We don't need to update any data maintained in the consumer from the frame
   * event payload, therefore it's fine to bail out here. Arguably, we could do
   * that as early as at the RBUS notification callback, but we are already
   * under a mutex lock here and that should help to avoid any potential races
   * in contrast of acquiring the lock at RBUS notification callback while
   * something else is being processed in the queue. */
  if (!consumer->comms_ready) {
    CcspTraceWarning((
        "Not yet ready to send tlv data for rdk frame type [%d] sta_mac [%s]\n",
        rdk_mgmt->frame.type, sta_mac));
    return;
  }

  /* FIXME: Fake empty radiotap header */
  size_t data_size = rdk_mgmt->frame.len + EMPTY_RT_LEN;
  size_t pcap_size = sizeof(struct cujo_fpc_wifi_pcap) + data_size;
  struct cujo_fpc_wifi_pcap *pcap = calloc(1, pcap_size);
  if (pcap == NULL) {
    CcspTraceError(
        ("Failed to allocate wifi pcap for frame type [%d] sta_mac [%s]\n",
         rdk_mgmt->frame.type, sta_mac));
    return;
  }

  size_t data_batch_event_size =
      sizeof(struct cujo_fpc_wifi_data_batch_event) + pcap_size;
  struct cujo_fpc_wifi_data_batch_event *data_batch_event =
      calloc(1, data_batch_event_size);
  if (data_batch_event == NULL) {
    CcspTraceError(("Failed to allocate data batch event\n"));
    free(pcap);
    return;
  }

  cujoagent_new_wifi_pcap(pcap, data_size, rdk_mgmt);

  switch (subtype) {
  case consumer_event_probe_req:
  case consumer_event_auth:
  case consumer_event_assoc_req:
  case consumer_event_reassoc_req:
    if (cujoagent_new_data_batch_event(data_batch_event, pcap, pcap_size,
                                       consumer, rdk_mgmt) != 0) {
      CcspTraceError(("Gathering data for wifi data batch event "
                      "frame type [%d] sta_mac [%s] failed\n",
                      rdk_mgmt->frame.type, sta_mac));
      free(pcap);
      free(data_batch_event);
      return;
    }
    break;
  default:
    break;
  }

  if (cujoagent_emit_event_tlv(CUJO_FPC_WIFI_DATA_BATCH_EVENT,
                               data_batch_event,
                               data_batch_event_size,
                               consumer) != 0) {
    free(pcap);
    free(data_batch_event);
    return;
  }

  cujoagent_print_events(NULL, NULL, data_batch_event, NULL, NULL);

  free(pcap);
  free(data_batch_event);
}

static void
cujoagent_new_csi_and_cfo_event(struct cujo_fpc_csi_and_cfo_data_event *event,
                                unsigned int vap_index, char *csi_data) {
  if (!event || !csi_data) {
    CcspTraceError(("Invalid event [%p] or csi data [%p]\n", (void *)event,
                    (void *)csi_data));
    return;
  }

  wifi_csi_data_t *csi_client_data = NULL;
  struct cujo_fpc_csi_and_cfo_reading csi_cfo_reading = {0};
  size_t csi_cfo_reading_size = sizeof(csi_cfo_reading);

  event->vap_index = vap_index;
  memcpy(event->mac.ether_addr_octet, csi_data + WIFI_CSI_PAYLOAD_HEADER_SIZE,
         ETH_ALEN);

  /* An event for each received CSI payload */
  event->csi_count = 1;

  csi_client_data =
      (wifi_csi_data_t *)(csi_data + WIFI_CSI_PAYLOAD_HEADER_SIZE +
                          WIFI_CSI_CLIENT_HEADER_SIZE);

  csi_cfo_reading.timestamp_ms = csi_client_data->frame_info.time_stamp;
  csi_cfo_reading.data_len = sizeof(wifi_csi_matrix_t);
  csi_cfo_reading.csi_metadata.bw_mode = csi_client_data->frame_info.bw_mode;
  csi_cfo_reading.csi_metadata.num_rx_antennae = csi_client_data->frame_info.Nr;
  /* Current BCM implementation supports only 1 stream */
  csi_cfo_reading.csi_metadata.num_tx_streams = csi_client_data->frame_info.Nc;

  /* Despite the fact that the RDK data type has RSSI in the frame info as
   * INT, the driver has it at int8 and it's a two's complement. Practically,
   * the signal won't even be near 0dB, so assume negative values. */
  for (int i = 0; i < csi_client_data->frame_info.Nr; i++) {
    csi_cfo_reading.csi_metadata.rssi[i] =
        csi_client_data->frame_info.nr_rssi[i] - (1 << 8);
  }

  csi_cfo_reading.csi_metadata.router_bw = csi_client_data->frame_info.phy_bw;
  csi_cfo_reading.csi_metadata.station_bw = csi_client_data->frame_info.cap_bw;
  /* Not applied to BCM's CSI format, 0xffff for that matter */
  csi_cfo_reading.csi_metadata.tones_mask = csi_client_data->frame_info.valid_mask;
  csi_cfo_reading.csi_metadata.num_subcarriers = csi_client_data->frame_info.num_sc;
  /* Current BCM implementation supports only 0 */
  csi_cfo_reading.csi_metadata.decimation_factor = csi_client_data->frame_info.decimation;
  csi_cfo_reading.csi_metadata.channel = csi_client_data->frame_info.channel;
  csi_cfo_reading.cfo = csi_client_data->frame_info.cfo;

  memcpy(event->csi, &csi_cfo_reading, csi_cfo_reading_size);
  memcpy(event->csi + csi_cfo_reading_size, csi_client_data->csi_matrix,
         sizeof(wifi_csi_matrix_t));
}

static int cujoagent_vap_index_from_mac(cujoagent_wifi_consumer_t *consumer,
                                        mac_addr_str_t mac_str) {
  wifi_platform_property_t *wifi_prop = &consumer->hal_cap.wifi_prop;
  rdk_wifi_radio_t *radios = consumer->radios;

  if (!wifi_prop || !radios) {
    CcspTraceError(("Wifi property [%p] or radios [%p] are invalid\n",
                    (void *)wifi_prop, (void *)radios));
    return -1;
  }

  int vap_index = -1;
  hash_map_t *assoc_dev_map = NULL;
  assoc_dev_data_t *assoc_dev_data = NULL;
  for (unsigned int i = 0; i < wifi_prop->numRadios; i++) {
    for (unsigned int j = 0; j < radios[i].vaps.num_vaps; j++) {
      assoc_dev_map = radios[i].vaps.rdk_vap_array[j].associated_devices_map;
      if (assoc_dev_map) {
        assoc_dev_data = hash_map_get(assoc_dev_map, mac_str);
        if (assoc_dev_data) {
          vap_index = radios[i].vaps.rdk_vap_array[j].vap_index;
        }
      }
    }
  }

  return vap_index;
}

static void
cujoagent_process_l1_event(cujoagent_wifi_consumer_t *consumer, char *msg,
                           __attribute__((unused)) size_t mlen,
                           cujoagent_consumer_event_subtype_t subtype) {
  int vap_index = -1;
  mac_address_t csi_data_client_mac = {0};
  mac_addr_str_t collect_mac_str = {0};
  struct cujo_fpc_l1_collection_done *done = NULL;

  struct cujo_fpc_csi_and_cfo_data_event *csi_cfo_event = NULL;
  size_t csi_cfo_event_size = sizeof(struct cujo_fpc_csi_and_cfo_data_event) +
                              sizeof(struct cujo_fpc_csi_and_cfo_reading) +
                              sizeof(wifi_csi_matrix_t);

  switch(subtype){
  case consumer_event_l1_csi_data:
    /* Assuming the CSI payload has a reading only for one MAC */
    memcpy(&csi_data_client_mac,
           msg + WIFI_CSI_PAYLOAD_HEADER_SIZE,
           sizeof(csi_data_client_mac));
    break; // consumer_event_l1_csi_data
  case consumer_event_l1_done:
    done = (struct cujo_fpc_l1_collection_done *)msg;
    memcpy(&csi_data_client_mac, done->mac.ether_addr_octet,
           sizeof(csi_data_client_mac));
    break; // consumer_event_l1_done
  default:
    break; // default
  }
  cujoagent_bytes_to_mac_str(csi_data_client_mac, collect_mac_str);

  switch (subtype) {
  case consumer_event_l1_csi_data:
    CcspTraceDebug(("Processing csi data sample for mac [%s]\n",
                    collect_mac_str));

    if (!consumer->comms_ready) {
      CcspTraceWarning(("Not yet ready to send L1 tlv data for mac [%s]\n",
                        collect_mac_str));
      return;
    }

    vap_index = cujoagent_vap_index_from_mac(consumer, collect_mac_str);
    if (vap_index == -1) {
      CcspTraceWarning(("Couldn't find mac [%s] on any of the associated "
                        "devices maps, ignoring the csi data sample\n",
                        collect_mac_str));
      return;
    }

    csi_cfo_event = calloc(1, csi_cfo_event_size);
    if (csi_cfo_event == NULL) {
      CcspTraceError(("Failed to allocate csi and cfo event for mac [%s]\n",
                      collect_mac_str));
      return;
    }

    cujoagent_new_csi_and_cfo_event(csi_cfo_event, vap_index, msg);
    if (cujoagent_emit_event_tlv(CUJO_FPC_CSI_AND_CFO_DATA_EVENT,
                                 csi_cfo_event,
                                 csi_cfo_event_size,
                                 consumer) != 0) {
      free(csi_cfo_event);
      return;
    }

    cujoagent_print_events(NULL, NULL, NULL, csi_cfo_event, NULL);
    free(csi_cfo_event);
    break; // consumer_event_l1_csi_data
  case consumer_event_l1_done:
    CcspTraceDebug(
        ("Processing L1 done event for mac [%s]\n", collect_mac_str));

    /* Zero-out only the data of the temperature collection context. Note that
     * the tcollect_ctx.data_size is still valid as it is initialised on the
     * subscriptions to RBUS and so do reflect the radio count, which is not
     * going to change at runtime. */
    memset(consumer->tcollect_ctx.temperature_data, 0,
           consumer->tcollect_ctx.data_size);
    consumer->tcollect_ctx.collected_count = 0;

    if (!consumer->comms_ready) {
      CcspTraceWarning(("Not yet ready to send DONE tlv data for mac [%s]\n",
                        collect_mac_str));
      return;
    }

    if (cujoagent_emit_event_tlv(CUJO_FPC_L1_COLLECTION_DONE,
                                 done,
                                 sizeof *done,
                                 consumer) == 0) {
      CcspTraceDebug(("CUJO_FPC_L1_COLLECTION_DONE: "
                      "vap_index [%u] mac [%s]\n",
                      done->vap_index,
                      collect_mac_str));
    }
    break; // consumer_event_l1_done
  default:
    break; // default
  }
}

static void cujoagent_new_temperature_event(
    struct cujo_fpc_temperature_data_event *event,
    cujoagent_temperature_collection_context_t *event_ctx) {
  event->timestamp_ms = cujoagent_timestamp();
  event->temperatures_count =
      event_ctx->data_size / sizeof *event_ctx->temperature_data;
  memcpy(event->temperatures, event_ctx->temperature_data,
         event_ctx->data_size);
}

static void cujoagent_process_temperature_event(
    cujoagent_wifi_consumer_t *consumer, char *msg,
    __attribute__((unused)) size_t mlen,
    cujoagent_consumer_event_subtype_t subtype) {
  cujoagent_radio_temperature_context_t *radio_temperatures_ctx = NULL;
  unsigned int max_temperature_readings =
      consumer->tcollect_ctx.data_size /
      sizeof *consumer->tcollect_ctx.temperature_data;

  switch(subtype){
  case consumer_event_radio_temperature:
    /* It is assumed that the RBUS notifications for the radio temperatures are
     * complete, meaning that if there will be more than one notification for
     * the same radio index, or e.g. a notification for the radio index higher
     * than the expected radio count -- the resulting temperature array data
     * will be corrupt. */
    radio_temperatures_ctx = (cujoagent_radio_temperature_context_t *)msg;
    if (radio_temperatures_ctx->radio_index >= max_temperature_readings) {
      CcspTraceError(
          ("Radio index [%u] is out of expected radio count [%u] range\n",
           radio_temperatures_ctx->radio_index, max_temperature_readings));
      return;
    }
    CcspTraceDebug(("Processing radio index [%u] temperature reading [%u]\n",
                    radio_temperatures_ctx->radio_index,
                    radio_temperatures_ctx->temperature));
    consumer->tcollect_ctx
        .temperature_data[radio_temperatures_ctx->radio_index] =
        radio_temperatures_ctx->temperature;
    consumer->tcollect_ctx.collected_count++;
    break; // consumer_event_radio_temperature
  default:
    break; // default
  }

  int err = -1;
  struct cujo_fpc_temperature_data_event *temperature_data_event = NULL;
  size_t temperature_data_event_size =
      sizeof(struct cujo_fpc_temperature_data_event) +
      consumer->tcollect_ctx.data_size;

  /* The temperature data event consists of _all_ available sensors readings,
   * but we're handling a single sample here, so count the processed ones and
   * send the TLV only when the expected number of readings reached.
   *
   * We do depend on the RBUS notifications though. Therefore, if e.g. there's
   * no notification for one of the expected radio temperatures during
   * timeout_ms of the timer, then the TLV send will never happen. */
  if (consumer->tcollect_ctx.collected_count == max_temperature_readings) {
    if (!consumer->comms_ready) {
      CcspTraceWarning(("Not yet ready to send temperatures tlv data\n"));
      /* Regardless of the available comms, zero-out only the data of the
       * temperature collection context. Note that the tcollect_ctx.data_size
       * is still valid as it is initialised on the subscriptions to RBUS and
       * so do reflect the radio count, which is not going to change at
       * runtime. */
      memset(consumer->tcollect_ctx.temperature_data, 0,
             consumer->tcollect_ctx.data_size);
      consumer->tcollect_ctx.collected_count = 0;
      return;
    }

    temperature_data_event = calloc(1, temperature_data_event_size);
    if (temperature_data_event == NULL){
      CcspTraceError(("Failed to allocate temperature date event\n"));
      return;
    }

    cujoagent_new_temperature_event(temperature_data_event,
                                    &consumer->tcollect_ctx);
    err = cujoagent_emit_event_tlv(CUJO_FPC_TEMPERATURE_DATA_EVENT,
                                   temperature_data_event,
                                   temperature_data_event_size,
                                   consumer);
    /* Regardless of the TLV send success, zero-out only the data of the
     * temperature collection context. Note that the tcollect_ctx.data_size is
     * still valid as it is initialised on the subscriptions to RBUS and so do
     * reflect the radio count, which is not going to change at runtime. */
    memset(consumer->tcollect_ctx.temperature_data, 0,
           consumer->tcollect_ctx.data_size);
    consumer->tcollect_ctx.collected_count = 0;
    if (err) {
      free(temperature_data_event);
      return;
    }

    cujoagent_print_events(NULL, NULL, NULL, NULL, temperature_data_event);
    free(temperature_data_event);
  }
}

static void *cujoagent_consumer_queue_loop(void *arg) {
  cujoagent_wifi_consumer_event_t *queue_data = NULL;
  cujoagent_wifi_consumer_t *consumer = arg;

  pthread_mutex_lock(&consumer->lock);
  for (;;) {
    while (!consumer->queue_wakeup) {
      pthread_cond_wait(&consumer->cond, &consumer->lock);
    }

    if (consumer->exit_consumer) {
      break;
    }

    while (queue_count(consumer->queue)) {
      queue_data = queue_pop(consumer->queue);
      if (queue_data == NULL) {
        continue;
      }

      switch (queue_data->event_type) {
      case consumer_event_type_webconfig:
        cujoagent_process_webconfig_event(consumer, queue_data->msg,
                                          queue_data->mlen,
                                          queue_data->event_subtype);
        break;
      case consumer_event_type_mgmt_frame:
        cujoagent_process_mgmt_frame_event(consumer, queue_data->msg,
                                           queue_data->mlen,
                                           queue_data->event_subtype);
        break;
      case consumer_event_type_l1:
        cujoagent_process_l1_event(consumer, queue_data->msg,
                                   queue_data->mlen,
                                   queue_data->event_subtype);
        break;
      case consumer_event_type_temperature:
        cujoagent_process_temperature_event(consumer, queue_data->msg,
                                            queue_data->mlen,
                                            queue_data->event_subtype);
        break;
      default:
        break;
      }

      /* Free data allocated at every push to queue */
      if (queue_data->msg) {
        free(queue_data->msg);
      }
      free(queue_data);
    }

    consumer->queue_wakeup = false;
  }
  pthread_mutex_unlock(&consumer->lock);

  CcspTraceDebug(("Returning from consumer thread routine\n"));
  return NULL;
}

static rbusError_t
cujoagent_webconfig_init_get(cujoagent_wifi_consumer_t *consumer) {
  struct epoll_event ev = {.events = EPOLLIN | EPOLLET,
                           .data.fd = consumer->misc_notification};
  if (epoll_ctl(consumer->misc_epoll, EPOLL_CTL_ADD,
                consumer->misc_notification, &ev)) {
    CcspTraceError(
        ("Failed to add a webconfig init eventfd to epoll interest list\n"));
    return RBUS_ERROR_BUS_ERROR;
  }

  char *s = NULL;
  char const *name = WIFI_WEBCONFIG_INIT_DATA_NAMESPACE;

  rbusError_t err = rbus_getStr(consumer->rbus_handle, name, &s);
  if (err) {
    CcspTraceError(("Failed to get [%s] over RBUS: [%d]\n", name, err));
    return err;
  }

  cujoagent_push_to_consumer_queue(consumer, s, strlen(s),
                                   consumer_event_type_webconfig,
                                   consumer_event_webconfig_init);

  /* rbus_getStr() return is strdup()'ed, free it */
  free(s);

  /* Wait until the WIFI_WEBCONFIG_INIT_DATA_NAMESPACE is processed in the
   * consumer queue thread (or time out). Otherwise, the subscribing code won't
   * get any vap indexes for subscription to the appropriate connect/disconnect
   * events only. */
  if (cujoagent_wait_for_event(consumer->misc_epoll,
                               NOTIFY_WEBCONFIG_INIT_READY,
                               EPOLL_TIMEOUT_MS) <= 0) {
    CcspTraceError(("Processing webconfig init failed or timed out\n"));
    return RBUS_ERROR_BUS_ERROR;
  }

  if (epoll_ctl(consumer->misc_epoll, EPOLL_CTL_DEL,
                consumer->misc_notification, NULL)) {
    CcspTraceError(("Failed to remove a webconfig init eventfd from epoll "
                    "interest list\n"));
    return RBUS_ERROR_BUS_ERROR;
  }

  cujoagent_close_if_valid(&consumer->misc_notification);
  cujoagent_close_if_valid(&consumer->misc_epoll);

  return RBUS_ERROR_SUCCESS;
}

static rbusError_t
cujoagent_set_l1_max_clients(cujoagent_wifi_consumer_t *consumer) {
  /* WIFI_LEVL_NUMBEROFENTRIES: The number of maximum simultaneous CSI
   * collections (aka the maximum number of MACs to allow for sounding).
  * If zero, then is set to the platform default. Otherwise,
   * can not be greater than MAX_LEVL_CSI_CLIENTS, i.e. 5 clients max. */
  char const *name = WIFI_LEVL_NUMBEROFENTRIES;
  unsigned int value = DCL_MAX_CSI_CLIENTS;

  CcspTraceDebug(("Setting max csi clients to [%u]\n", value));
  rbusError_t err = rbus_setUInt(consumer->rbus_handle, name, value);
  if (err) {
    CcspTraceError(("Failed to set [%s] over RBUS: [%d]\n", name, err));
    return err;
  }

  return RBUS_ERROR_SUCCESS;
}

static rbusError_t
cujoagent_assoc_list_init_get(cujoagent_wifi_consumer_t *consumer) {
  char *s = NULL;
  char const *name = WIFI_WEBCONFIG_GET_ASSOC;

  rbusError_t err = rbus_getStr(consumer->rbus_handle, name, &s);
  if (err) {
    CcspTraceError(("Failed to get [%s] over RBUS: [%d]\n", name, err));
    return err;
  }

  cujoagent_push_to_consumer_queue(consumer, s, strlen(s),
                                   consumer_event_type_webconfig,
                                   consumer_event_webconfig_set_data);

  /* rbus_getStr() return is strdup()'ed, free it */
  free(s);
  return RBUS_ERROR_SUCCESS;
}

static void cujoagent_webconfig_handler(__attribute__((unused))
                                        rbusHandle_t handle,
                                        rbusEvent_t const *event,
                                        rbusEventSubscription_t *subscription) {
  if (!event || !subscription) {
    CcspTraceError(
        ("Invalid event [%p] or subscription [%p] for [%s] handler\n",
         (void *)event, (void *)subscription, WIFI_WEBCONFIG_DOC_DATA_NORTH));
    return;
  }

  if (!event->data || !subscription->userData) {
    CcspTraceError(
        ("Invalid event data [%p] or subscription data [%p] for [%s] handler\n",
         (void *)event->data, (void *)subscription->userData, event->name));
    return;
  }

  rbusValue_t value = rbusObject_GetValue(event->data, subscription->eventName);
  if (!value) {
    CcspTraceError(("Failed to get [%s] value\n", subscription->eventName));
    return;
  }

  int slen = 0;
  char const *s = rbusValue_GetString(value, &slen);
  if (s == NULL) {
    CcspTraceError(
        ("Failed to get string for [%s]\n", subscription->eventName));
    return;
  }

  /* The WIFI_WEBCONFIG_GET_ASSOC case. Practically should happen way more
   * often than any wifi config changes. Pushing to the "get" case of the queue,
   * because event based notification payload is a partial _diff_ type of the
   * assoclist. */
  cujoagent_consumer_event_subtype_t subtype = consumer_event_webconfig_get_data;

  if (strcmp(subscription->eventName, WIFI_WEBCONFIG_DOC_DATA_NORTH) == 0) {
    subtype = consumer_event_webconfig_set_data;
  }

  cujoagent_push_to_consumer_queue(subscription->userData, s, slen,
                                   consumer_event_type_webconfig, subtype);
}

static void
cujoagent_frame_events_handler(__attribute__((unused)) rbusHandle_t handle,
                               rbusEvent_t const *event,
                               rbusEventSubscription_t *subscription) {
  if (!event || !subscription) {
    CcspTraceError(
        ("Invalid event [%p] or subscription [%p] for [%s] handler\n",
         (void *)event, (void *)subscription, DEV_WIFI_EVENTS_VAP_FRAMES_MGMT));
    return;
  }

  if (!event->data || !subscription->userData) {
    CcspTraceError(
        ("Invalid event data [%p] or subscription data [%p] for [%s] handler\n",
         (void *)event->data, (void *)subscription->userData, event->name));
    return;
  }

  rbusValue_t value = rbusObject_GetValue(event->data, subscription->eventName);
  if (!value) {
    CcspTraceError(("Failed to get [%s] value\n", subscription->eventName));
    return;
  }

  int len = 0;
  uint8_t const *data = rbusValue_GetBytes(value, &len);
  if (!data || (len > (int)sizeof(frame_data_t))) {
    CcspTraceError(("Invalid event [%s] data\n", subscription->eventName));
    return;
  }

  frame_data_t *rdk_mgmt = (frame_data_t *)data;
  uint16_t fc = le16toh(*(uint16_t*)&rdk_mgmt->data[0]);
  uint16_t subtype = fc & FCTL_STYPE;

  CcspTraceDebug(("Subscription [%s] rbus payload: rdk frame type [%d], "
                  "ieee80211 frame fc [0x%04x] "
                  "type [%" PRIu16 "] subtype [%" PRIu16 "]\n",
                  subscription->eventName, rdk_mgmt->frame.type, fc,
                  FC_GET_TYPE(fc), FC_GET_STYPE(fc)));

  /* Action No Ack frames, i.e. frame control B7..B4 == 1110 */
  int event_subtype = WIFI_MGMT_FRAME_TYPE_INVALID;
  switch (rdk_mgmt->frame.type) {
  case WIFI_MGMT_FRAME_TYPE_PROBE_REQ:
    if (subtype == STYPE_PROBE_REQ) {
      event_subtype = consumer_event_probe_req;
    }
    break;
  case WIFI_MGMT_FRAME_TYPE_AUTH:
    if (subtype == STYPE_AUTH) {
      event_subtype = consumer_event_auth;
    }
    break;
  case WIFI_MGMT_FRAME_TYPE_ASSOC_REQ:
    if (subtype == STYPE_ASSOC_REQ) {
      event_subtype = consumer_event_assoc_req;
    }
    break;
  case WIFI_MGMT_FRAME_TYPE_REASSOC_REQ:
    if (subtype == STYPE_REASSOC_REQ) {
      event_subtype = consumer_event_reassoc_req;
    }
    break;
  default:
    break;
  }

  if (event_subtype == WIFI_MGMT_FRAME_TYPE_INVALID) {
    CcspTraceError(("Unsupported or invalid mgmt frame: rdk frame type [%d], "
                    "ieee80211 subtype [%" PRIu16 "]\n",
                    rdk_mgmt->frame.type, FC_GET_STYPE(fc)));
    return;
  }

  cujoagent_push_to_consumer_queue(subscription->userData, data, len,
                                   consumer_event_type_mgmt_frame,
                                   event_subtype);
}

static void
cujoagent_unsupported_handler(__attribute__((unused)) rbusHandle_t handle,
                              rbusEventRawData_t const *event,
                              rbusEventSubscription_t *subscription) {
  if (!event || !subscription) {
    CcspTraceError(
        ("Invalid event [%p] or subscription [%p] for [%s] handler\n",
         (void *)event, (void *)subscription, WIFI_LEVL_CSI_DATAFIFO));
    return;
  }

  if (!event->rawData || !subscription->userData) {
    CcspTraceError(
        ("Invalid event data [%p] or subscription data [%p] for [%s] handler\n",
         (void *)event->rawData, (void *)subscription->userData, event->name));
    return;
  }

  /* XXX: We can't pass NULL into subscriptions rbusEventSubscription_t type for
   * rbusEventHandler_t type callback function -- RBUS will return
   * RBUS_ERROR_INVALID_INPUT and not only we'll error out for _all_
  * subscriptions, but also the RBUS system won't count us as CSI data consumers.
  * Therefore, a no-op handler as a workaround for RBUS, with actual data read from FIFO. There should not be any notifications for the CSI data over RBUS. */
  CcspTraceWarning(("Handler for [%s] is called. We should not be here.\n",
                    subscription->eventName));
}

static void
cujoagent_radio_temperature_handler(__attribute__((unused)) rbusHandle_t handle,
                                    rbusEvent_t const *event,
                                    rbusEventSubscription_t *subscription) {
  if (!event || !subscription) {
    CcspTraceError(
        ("Invalid event [%p] or subscription [%p] for [%s] handler\n",
         (void *)event, (void *)subscription, DEV_WIFI_EVENTS_RADIO_TEMPERATURE));
    return;
  }

  if (!event->data || !subscription->userData) {
    CcspTraceError(
        ("Invalid event data [%p] or subscription data [%p] for [%s] handler\n",
         (void *)event->data, (void *)subscription->userData, event->name));
    return;
  }

  unsigned int event_radio_idx = 1;
  if (sscanf(subscription->eventName, DEV_WIFI_EVENTS_RADIO_TEMPERATURE,
             &event_radio_idx) != 1) {
    CcspTraceError(
      ("Failed to read radio index from [%s]\n", subscription->eventName));
    return;
  }

  /* The above is the radio index as it is in an event name used for
   * subscription. The actual radio index matching with the interface is:
   * event_radio_idx - 1. Therefore, having it as zero is clearly a sign that
   * something is amiss with the rbus notification. */
  if (event_radio_idx == 0) {
    CcspTraceError(("Event [%s] radio index [%u] is invalid\n",
                    subscription->eventName, event_radio_idx));
    return;
  }

  rbusValue_t value = rbusObject_GetValue(event->data, subscription->eventName);
  if (!value) {
    CcspTraceError(("Failed to get [%s] value\n", subscription->eventName));
    return;
  }

  cujoagent_radio_temperature_context_t ctx = {
      .radio_index = event_radio_idx - 1,
      .temperature = rbusValue_GetUInt32(value),
  };
  cujoagent_push_to_consumer_queue(subscription->userData, &ctx, sizeof(ctx),
                                   consumer_event_type_temperature,
                                   consumer_event_radio_temperature);
}

static int cujoagent_fill_subscription(rbusEventSubscription_t *consumer_subs,
                                       unsigned int subs_count,
                                       unsigned int idx,
                                       char const *filler_name,
                                       rbusEventSubscription_t *filler_sub) {
  if (idx >= subs_count) {
    CcspTraceError(("Subscription index [%u] out of range for the "
                    "subscriptions count [%u]\n",
                    idx, subs_count));
    return -1;
  }

  rbusEventSubscription_t *sub = &consumer_subs[idx];
  *sub = *filler_sub;
  sub->eventName = strdup(filler_name);
  if (sub->eventName == NULL) {
    CcspTraceError(("Failed to allocate the consumer subscription name\n"));
    return -1;
  }

  return 0;
}

static rbusError_t
cujoagent_rbus_subscribe(cujoagent_wifi_consumer_t *consumer) {
  /* WIFI_WEBCONFIG_DOC_DATA_SOUTH:
  *    _to_ backend. Mentioned for the reference. Changes to subdocs coming from e.g. ovsdb or dml.
  *
  * WIFI_WEBCONFIG_DOC_DATA_NORTH:
  *    _from_ backend. Basically any of the webconfig_subdoc_type_t subdocs.
   *
   * WIFI_WEBCONFIG_GET_ASSOC:
   *    "AddAssociatedClients" for connected clients.
   *    "RemoveWiFiAssociatedClients" for disconnected clients.
   *
   * DEV_WIFI_EVENTS_VAP_FRAMES_MGMT:
   *    RDK metadata + IEEE802 mgmt frame.
   *
   * DEV_WIFI_EVENTS_RADIO_TEMPERATURE:
   *    Periodic per-radio temperature.
   *    Interval subscriptions only.
   *    When not required _must_ be unsubscribed.
   *    Minimum interval allowed -- 5000 ms.
   */

  rbusEventSubscription_t filler_subs[] = {
      /* event name, filter, interval, duration, handler, user data, handle, async handler, publish on subscribe */
      {WIFI_WEBCONFIG_DOC_DATA_NORTH, NULL, 0, 0, cujoagent_webconfig_handler, consumer, NULL, NULL, false},
      {WIFI_WEBCONFIG_GET_ASSOC, NULL, 0, 0, cujoagent_webconfig_handler, consumer, NULL, NULL, false},
      {WIFI_LEVL_CSI_DATAFIFO, NULL, 0, 0, cujoagent_unsupported_handler, consumer, NULL, NULL, false},
      {DEV_WIFI_EVENTS_VAP_FRAMES_MGMT, NULL, 0, 0, cujoagent_frame_events_handler, consumer, NULL, NULL, false},
      {DEV_WIFI_EVENTS_RADIO_TEMPERATURE, NULL, WIFI_RADIO_MIN_TEMPERATURE_INTERVAL, 0, cujoagent_radio_temperature_handler, consumer, NULL, NULL, false},
  };
  size_t filler_subs_count = sizeof(filler_subs) / sizeof(*filler_subs);

  wifi_platform_property_t *wifi_prop = &consumer->hal_cap.wifi_prop;
  if (!wifi_prop) {
    CcspTraceError(("Wifi property is invalid\n"));
    return RBUS_ERROR_BUS_ERROR;
  }

  if (wifi_prop->numRadios == 0) {
    CcspTraceError(("Wifi property number of radios is zero!"));
    return RBUS_ERROR_BUS_ERROR;
  }

  consumer->vap_subs_count = 0;
  for (unsigned int i = 0; i < wifi_prop->numRadios * MAX_NUM_VAP_PER_RADIO; i++) {
    if (strcmp(wifi_prop->interface_map[i].bridge_name, PRIVATE_BRIDGE) == 0) {
      consumer->vap_subs_count++;
      unsigned int *tmp = reallocarray(consumer->vap_subs_indexes,
                                       consumer->vap_subs_count,
                                       sizeof *consumer->vap_subs_indexes);
      if (tmp == NULL) {
        CcspTraceError(("Failed to reallocate vaps indexes\n"));
        free(consumer->vap_subs_indexes);
        return RBUS_ERROR_BUS_ERROR;
      }
      consumer->vap_subs_indexes = tmp;
      consumer->vap_subs_indexes[consumer->vap_subs_count - 1] = wifi_prop->interface_map[i].index;
    }
  }

  if (consumer->vap_subs_count == 0) {
    CcspTraceError(("No vap indexes found for bridge [%s]: wifi property "
                    "number of radios [%u] max vaps per radio [%d]\n",
                    PRIVATE_BRIDGE, wifi_prop->numRadios,
                    MAX_NUM_VAP_PER_RADIO));
    return RBUS_ERROR_BUS_ERROR;
  }

  consumer->subscriptions_count = 0;
  consumer->raw_data_subscriptions_count = 0;
  consumer->on_demand_subscriptions_count = 0;
  for (unsigned int i = 0; i < filler_subs_count; i++) {
    switch (i) {
    case 0: // WIFI_WEBCONFIG_DOC_DATA_NORTH
    case 1: // WIFI_WEBCONFIG_GET_ASSOC
      consumer->subscriptions_count++;
      break;
    case 2: // WIFI_LEVL_CSI_DATAFIFO
      consumer->raw_data_subscriptions_count++;
      break;
    case 3: // DEV_WIFI_EVENTS_VAP_FRAMES_MGMT
      consumer->subscriptions_count += consumer->vap_subs_count;
      break;
    case 4: // DEV_WIFI_EVENTS_RADIO_TEMPERATURE
      consumer->on_demand_subscriptions_count += wifi_prop->numRadios;
      break;
    default:
      break;
    }
  }

  CcspTraceDebug(("Private vaps count [%d] subscriptions count [%u] "
                  "raw data subscriptions count [%u], "
                  "on demand subscriptions count [%u]\n",
                  consumer->vap_subs_count, consumer->subscriptions_count,
                  consumer->raw_data_subscriptions_count,
                  consumer->on_demand_subscriptions_count));

  consumer->subscriptions = calloc(1, sizeof(rbusEventSubscription_t) *
                                          consumer->subscriptions_count);
  if (consumer->subscriptions == NULL) {
    CcspTraceError(("Failed to allocate the subscriptions\n"));
    return RBUS_ERROR_BUS_ERROR;
  }

  consumer->raw_data_subscriptions =
      calloc(1, sizeof(rbusEventSubscription_t) *
                    consumer->raw_data_subscriptions_count);
  if (consumer->raw_data_subscriptions == NULL) {
    CcspTraceError(("Failed to allocate the raw data subscriptions\n"));
    return RBUS_ERROR_BUS_ERROR;
  }

  consumer->on_demand_subscriptions =
      calloc(1, sizeof(rbusEventSubscription_t) *
                    consumer->on_demand_subscriptions_count);
  if (consumer->on_demand_subscriptions == NULL) {
    CcspTraceError(("Failed to allocate the on demand subscriptions\n"));
    return RBUS_ERROR_BUS_ERROR;
  }

  /* So far we're collecting only the radio temperatures. If any other sensors
   * to be collected then the following code block needs to be adjusted
   * accordingly. */
  size_t temperature_data_size = wifi_prop->numRadios * sizeof(unsigned int);
  consumer->tcollect_ctx.temperature_data = calloc(1, temperature_data_size);
  if (consumer->tcollect_ctx.temperature_data == NULL) {
    CcspTraceError(("Failed to allocate the temperature collection context\n"));
    return RBUS_ERROR_BUS_ERROR;
  }
  consumer->tcollect_ctx.data_size = temperature_data_size;

  int count = 0;
  unsigned int subs_idx = 0;
  unsigned int raw_subs_idx = 0;
  unsigned int on_demand_subs_idx = 0;
  char buf[RBUS_MAX_NAME_LENGTH] = {0};
  char const *filler_name = NULL;
  for (unsigned int i = 0; i < filler_subs_count; i++) {
    filler_name = filler_subs[i].eventName;
    switch (i) {
    case 0: // WIFI_WEBCONFIG_DOC_DATA_NORTH
    case 1: // WIFI_WEBCONFIG_GET_ASSOC
      if (cujoagent_fill_subscription(consumer->subscriptions,
                                      consumer->subscriptions_count, subs_idx,
                                      filler_name, &filler_subs[i]) != 0) {
        return RBUS_ERROR_BUS_ERROR;
      }
      subs_idx++;
      break;
    case 2: // WIFI_LEVL_CSI_DATAFIFO
      if (cujoagent_fill_subscription(consumer->raw_data_subscriptions,
                                      consumer->raw_data_subscriptions_count,
                                      raw_subs_idx, filler_name,
                                      &filler_subs[i]) != 0) {
        return RBUS_ERROR_BUS_ERROR;
      }
      raw_subs_idx++;
      break;
    case 3: // DEV_WIFI_EVENTS_VAP_FRAMES_MGMT
      for (unsigned int j = 0; j < consumer->vap_subs_count; j++) {
        count = snprintf(buf, RBUS_MAX_NAME_LENGTH, filler_name,
                         consumer->vap_subs_indexes[j] + 1);
        if (count < 0 || count >= RBUS_MAX_NAME_LENGTH) {
          CcspTraceError(("Name [%s] doesn't fit into buffer\n", filler_name));
          return RBUS_ERROR_BUS_ERROR;
        }

        if (cujoagent_fill_subscription(consumer->subscriptions,
                                        consumer->subscriptions_count, subs_idx,
                                        buf, &filler_subs[i]) != 0) {
          return RBUS_ERROR_BUS_ERROR;
        }
        subs_idx++;
      }
      break;
    case 4: // DEV_WIFI_EVENTS_RADIO_TEMPERATURE
      for (unsigned int k = 0; k < wifi_prop->numRadios; k++) {
        count = snprintf(buf, RBUS_MAX_NAME_LENGTH, filler_name, k + 1);
        if (count < 0 || count >= RBUS_MAX_NAME_LENGTH) {
          CcspTraceError(("Name [%s] doesn't fit into buffer\n", filler_name));
          return RBUS_ERROR_BUS_ERROR;
        }

        if (cujoagent_fill_subscription(consumer->on_demand_subscriptions,
                                        consumer->on_demand_subscriptions_count,
                                        on_demand_subs_idx, buf,
                                        &filler_subs[i]) != 0) {
          return RBUS_ERROR_BUS_ERROR;
        }
        on_demand_subs_idx++;
      }
      break;
    default:
      break;
    }
  }

  rbusError_t err = rbusEvent_SubscribeEx(consumer->rbus_handle,
                                          consumer->subscriptions,
                                          consumer->subscriptions_count, 0);
  if (err) {
    CcspTraceError(("Unable to subscribe to event(s): [%d]\n", err));
    return err;
  }

  err = rbusEvent_SubscribeExRawData(consumer->rbus_handle,
                                     consumer->raw_data_subscriptions,
                                     consumer->raw_data_subscriptions_count, 0);
  if (err) {
    CcspTraceError(("Unable to subscribe to raw data event(s): [%d]\n", err));
  }

  return err;
}

static int cujoagent_consumer_initialize(cujoagent_wifi_consumer_t *consumer) {
  if (!consumer) {
    return -1;
  }

  if (!(!cujoagent_consumer_init(consumer) &&
        !cujoagent_spawn_loop(cujoagent_consumer_queue_loop, consumer) &&
        !cujoagent_spawn_loop(cujoagent_socket_loop, consumer) &&
        !cujoagent_spawn_loop(cujoagent_fifo_loop, consumer))) {
    cujoagent_wifidatacollection_deinit(consumer, FALSE);
    return -1;
  }

  return 0;
}

static int cujoagent_rbus_initialize(cujoagent_wifi_consumer_t *consumer) {
  extern rbusHandle_t g_rbus_handle;
  
  if (!consumer) {
    return -1;
  }

  /* Reuse the global RBUS handle instead of opening a new connection */
  consumer->rbus_handle = g_rbus_handle;
  if (!consumer->rbus_handle) {
    CcspTraceError(("cujoagent_rbus_initialize: g_rbus_handle is NULL\n"));
    return -1;
  }

  /* Order matters here:
   *  Get the WIFI_WEBCONFIG_INIT_DATA_NAMESPACE first, so that the appropriate
   *  wifi data is present in the consumer before any subscriptions happen.
   *
   *  Set the maximum L1 data collection clients allowed before subscribing.
   *  Ensures only the expected number of _simultaneous_ collections happen.
   *
   *  Query full assoc list after subscribing to WIFI_WEBCONFIG_GET_ASSOC.
   *  This ensures no stations are missed in the assoc list maintained in the
   *  consumer. Of course, at the small price of potentially missing some
   *  connects/disconnects happening right after subscribing, but before we
   *  sync the full assoc list. */
  if (!(!cujoagent_webconfig_init_get(consumer) &&
        !cujoagent_set_l1_max_clients(consumer) &&
        !cujoagent_rbus_subscribe(consumer) &&
        !cujoagent_assoc_list_init_get(consumer))) {
    cujoagent_wifidatacollection_deinit(consumer, FALSE);
    return -1;
  }

  return 0;
}

int cujoagent_wifidatacollection_init(cujoagent_wifi_consumer_t *consumer) {
  if (!consumer) {
    return -1;
  }

  CcspTraceInfo(("Initializing wifi data collection consumer\n"));
  if (cujoagent_consumer_initialize(g_cujoagent_dcl) != 0) {
    CcspTraceError(("Failed to initialize wifi data collection consumer!\n"));
    return -1;
  }

  CcspTraceInfo(("Initializing wifi data collection rbus\n"));
  if (cujoagent_rbus_initialize(g_cujoagent_dcl) != 0) {
    CcspTraceError(("Failed to initialize wifi data collection rbus!\n"));
    return -1;
  }

  return 0;
}

int cujoagent_wifidatacollection_deinit(cujoagent_wifi_consumer_t *consumer,
                                        bool do_rbus_event_unsubscribe) {
  if (!consumer) {
    return -1;
  }

  if (do_rbus_event_unsubscribe) {
    rbusEvent_UnsubscribeEx(consumer->rbus_handle,
                            consumer->subscriptions,
                            consumer->subscriptions_count);
    rbusEvent_UnsubscribeExRawData(consumer->rbus_handle,
                            consumer->raw_data_subscriptions,
                            consumer->raw_data_subscriptions_count);
  }

  cujoagent_l1_collector_t *collector = NULL;
  pthread_mutex_lock(&consumer->l1_lock);
  for (int i = 0; i < DCL_MAX_CSI_CLIENTS; i++) {
    if (!consumer->l1_collections[i]) {
      continue;
    }
    collector = consumer->l1_collections[i];
    cujoagent_write_event(collector->notification,
                          NOTIFY_L1_COLLECTION_THREAD_STOP);
    cujoagent_wait_for_event(consumer->queue_epoll,
                             NOTIFY_L1_COLLECTION_THREAD_RETURN,
                             EPOLL_TIMEOUT_MS);
  }
  consumer->disable_l1_collection = true;
  pthread_mutex_unlock(&consumer->l1_lock);

  cujoagent_write_event(consumer->fifo_notification, NOTIFY_FIFO_THREAD_STOP);
  cujoagent_wait_for_event(consumer->queue_epoll,
			   NOTIFY_FIFO_THREAD_RETURN,
			   EPOLL_TIMEOUT_MS);

  /* Allows the consumer queue thread start function to return. */
  pthread_mutex_lock(&consumer->lock);
  consumer->exit_consumer = true;
  consumer->queue_wakeup = true;
  pthread_mutex_unlock(&consumer->lock);
  pthread_cond_signal(&consumer->cond);

  /* Breaks the epoll_wait() loop to return the comms thread start function.
   * For the cases when the agent hello-version is in progress, the thread will
   * error out on a closed socket and proceed to the return anyway. */
  cujoagent_write_event(consumer->comms_notification,
                        NOTIFY_SOCKET_THREAD_STOP);
  cujoagent_wait_for_event(consumer->queue_epoll,
		           NOTIFY_SOCKET_THREAD_RETURN,
			   EPOLL_TIMEOUT_MS);
  cujoagent_close_if_valid(&consumer->sock_fd);

  cujoagent_free_all_associated_devices_maps(
      consumer->radios, consumer->hal_cap.wifi_prop.numRadios);
  cujoagent_consumer_deinit(consumer);
  return 0;
}
