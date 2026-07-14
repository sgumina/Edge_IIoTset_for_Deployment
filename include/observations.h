#ifndef OBSERVATIONS_H
#define OBSERVATIONS_H

#include <stdint.h>
#include <sys/time.h>

#include "feature_contract.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct edgeiiot_window_t {
    uint64_t window_id;
    uint32_t packet_count;
    uint64_t total_bytes;
    uint32_t tcp_ack_count;
    uint32_t tcp_packet_count;
    uint32_t max_pkt_size;
    uint64_t orig_bytes;

    struct timeval first_ts;
    struct timeval last_ts;
    int has_first_ts;

    double sum_iat;
    double sum_iat_sq;
    uint32_t iat_count;
} edgeiiot_window_t;

void edgeiiot_window_init(edgeiiot_window_t *window, uint64_t window_id);
void edgeiiot_window_add_packet(edgeiiot_window_t *window,
                                const struct timeval *ts,
                                uint32_t packet_len,
                                int is_tcp_ack,
                                int is_originator,
                                uint32_t originator_bytes);

double edgeiiot_feature_total_bytes(const edgeiiot_window_t *window);
double edgeiiot_feature_avg_pkt_size(const edgeiiot_window_t *window);
double edgeiiot_feature_duration(const edgeiiot_window_t *window);
double edgeiiot_feature_total_pkts(const edgeiiot_window_t *window);
double edgeiiot_feature_mean_iat(const edgeiiot_window_t *window);
double edgeiiot_feature_pkts_per_sec(const edgeiiot_window_t *window);
double edgeiiot_feature_ack_count(const edgeiiot_window_t *window);
double edgeiiot_feature_orig_bytes(const edgeiiot_window_t *window);
double edgeiiot_feature_burstiness_cv(const edgeiiot_window_t *window);
double edgeiiot_feature_max_pkt_size(const edgeiiot_window_t *window);

void edgeiiot_compute_feature_vector(const edgeiiot_window_t *window, double out[FEATURE_COUNT]);

#ifdef __cplusplus
}
#endif

#endif /* OBSERVATIONS_H */
