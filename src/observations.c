#include "observations.h"

#include <math.h>
#include <string.h>

static double timeval_diff_seconds(const struct timeval *start, const struct timeval *end)
{
    double sec = (double)end->tv_sec - (double)start->tv_sec;
    double usec = (double)end->tv_usec - (double)start->tv_usec;
    return sec + (usec / 1000000.0);
}

static void copy_timeval(struct timeval *dst, const struct timeval *src)
{
    dst->tv_sec = src->tv_sec;
    dst->tv_usec = src->tv_usec;
}

void edgeiiot_window_init(edgeiiot_window_t *window, uint64_t window_id)
{
    if (window == NULL) {
        return;
    }

    memset(window, 0, sizeof(*window));
    window->window_id = window_id;
    window->has_first_ts = 0;
}

void edgeiiot_window_add_packet(edgeiiot_window_t *window,
                                const struct timeval *ts,
                                uint32_t packet_len,
                                int is_tcp_ack,
                                int is_originator,
                                uint32_t originator_bytes)
{
    if (window == NULL || ts == NULL) {
        return;
    }

    if (!window->has_first_ts) {
        copy_timeval(&window->first_ts, ts);
        window->has_first_ts = 1;
    } else {
        double delta = timeval_diff_seconds(&window->last_ts, ts);
        if (delta >= 0.0) {
            window->sum_iat += delta;
            window->sum_iat_sq += delta * delta;
            window->iat_count++;
        }
    }

    copy_timeval(&window->last_ts, ts);

    window->packet_count++;
    window->total_bytes += (uint64_t)packet_len;
    if (packet_len > window->max_pkt_size) {
        window->max_pkt_size = packet_len;
    }

    if (is_tcp_ack) {
        window->tcp_ack_count++;
    }

    if (is_originator) {
        window->orig_bytes += (uint64_t)originator_bytes;
    }

    if (packet_len > 0) {
        window->tcp_packet_count++;
    }
}

double edgeiiot_feature_total_bytes(const edgeiiot_window_t *window)
{
    return (window == NULL) ? 0.0 : (double)window->total_bytes;
}

double edgeiiot_feature_avg_pkt_size(const edgeiiot_window_t *window)
{
    if (window == NULL || window->packet_count == 0) {
        return 0.0;
    }

    return (double)window->total_bytes / (double)window->packet_count;
}

double edgeiiot_feature_duration(const edgeiiot_window_t *window)
{
    if (window == NULL || !window->has_first_ts) {
        return 0.0;
    }

    return timeval_diff_seconds(&window->first_ts, &window->last_ts);
}

double edgeiiot_feature_total_pkts(const edgeiiot_window_t *window)
{
    return (window == NULL) ? 0.0 : (double)window->packet_count;
}

double edgeiiot_feature_mean_iat(const edgeiiot_window_t *window)
{
    if (window == NULL || window->iat_count == 0) {
        return 0.0;
    }

    return window->sum_iat / (double)window->iat_count;
}

double edgeiiot_feature_pkts_per_sec(const edgeiiot_window_t *window)
{
    if (window == NULL || window->packet_count == 0) {
        return 0.0;
    }

    double duration = edgeiiot_feature_duration(window);
    if (duration <= 0.0) {
        return 0.0;
    }

    return (double)window->packet_count / duration;
}

double edgeiiot_feature_ack_count(const edgeiiot_window_t *window)
{
    return (window == NULL) ? 0.0 : (double)window->tcp_ack_count;
}

double edgeiiot_feature_orig_bytes(const edgeiiot_window_t *window)
{
    return (window == NULL) ? 0.0 : (double)window->orig_bytes;
}

double edgeiiot_feature_burstiness_cv(const edgeiiot_window_t *window)
{
    if (window == NULL || window->iat_count < 2) {
        return 0.0;
    }

    double mean = window->sum_iat / (double)window->iat_count;
    if (mean <= 0.0) {
        return 0.0;
    }

    double mean_sq = window->sum_iat_sq / (double)window->iat_count;
    double variance = mean_sq - (mean * mean);
    if (variance < 0.0) {
        variance = 0.0;
    }

    return sqrt(variance) / mean;
}

double edgeiiot_feature_max_pkt_size(const edgeiiot_window_t *window)
{
    return (window == NULL) ? 0.0 : (double)window->max_pkt_size;
}

void edgeiiot_compute_feature_vector(const edgeiiot_window_t *window, double out[FEATURE_COUNT])
{
    if (out == NULL) {
        return;
    }

    out[FEATURE_TOTAL_BYTES] = edgeiiot_feature_total_bytes(window);
    out[FEATURE_AVG_PKT_SIZE] = edgeiiot_feature_avg_pkt_size(window);
    out[FEATURE_DURATION] = edgeiiot_feature_duration(window);
    out[FEATURE_TOTAL_PKTS] = edgeiiot_feature_total_pkts(window);
    out[FEATURE_MEAN_IAT] = edgeiiot_feature_mean_iat(window);
    out[FEATURE_PKTS_PER_SEC] = edgeiiot_feature_pkts_per_sec(window);
    out[FEATURE_ACK_COUNT] = edgeiiot_feature_ack_count(window);
    out[FEATURE_ORIG_BYTES] = edgeiiot_feature_orig_bytes(window);
    out[FEATURE_BURSTINESS_CV] = edgeiiot_feature_burstiness_cv(window);
    out[FEATURE_MAX_PKT_SIZE] = edgeiiot_feature_max_pkt_size(window);
}
