#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <ctype.h>

#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#define MAX_WINDOW_SIZE 64
#define MAX_LINE       1024
#define CSV_DELIM      ","

typedef struct {
    uint32_t total_packets;
    uint64_t total_bytes;
    uint32_t tcp_ack_count;
    uint32_t tcp_packet_count;
    struct timeval first_ts;
    struct timeval last_ts;
    int has_first_ts;
} WindowStats;

typedef struct {
    char pcap_path[512];
    char label[128];
    char device[128];
    int window_size;
    char output_csv[512];
} Config;

static void init_window_stats(WindowStats *s) {
    memset(s, 0, sizeof(WindowStats));
    s->has_first_ts = 0;
}

static double tv_diff_seconds(const struct timeval *start, const struct timeval *end) {
    double s = (double)end->tv_sec - (double)start->tv_sec;
    double us = (double)end->tv_usec - (double)start->tv_usec;
    return s + (us / 1000000.0);
}

static const char *basename_only(const char *path) {
    const char *slash = strrchr(path, '/');
#ifdef _WIN32
    const char *bslash = strrchr(path, '\\');
    if (!slash || (bslash && bslash > slash)) slash = bslash;
#endif
    return slash ? slash + 1 : path;
}

static void infer_label_and_device_from_path(const char *path, char *label, size_t label_sz, char *device, size_t device_sz) {
    const char *base = basename_only(path);
    char tmp[512];
    snprintf(tmp, sizeof(tmp), "%s", base);

    char *dot = strrchr(tmp, '.');
    if (dot) *dot = '\0';

    /* Very simple first-pass inference:
       - if path contains "normal" => label = normal
       - otherwise label = parent folder or filename token
       - device = parent folder if available
    */
    if (strstr(path, "Normal") || strstr(path, "normal")) {
        snprintf(label, label_sz, "normal");
    } else {
        /* fallback: use file stem as label candidate */
        snprintf(label, label_sz, "%s", tmp);
    }

    /* device is left as unknown unless you later decide to parse it from the directory tree */
    snprintf(device, device_sz, "unknown");
}

static int is_tcp_packet(const u_char *packet, uint32_t caplen, uint16_t *ip_total_len, uint8_t *tcp_flags, uint32_t *payload_len) {
    if (caplen < sizeof(struct ether_header)) return 0;

    const struct ether_header *eth = (const struct ether_header *)packet;
    if (ntohs(eth->ether_type) != ETHERTYPE_IP) return 0;

    const struct ip *ip_hdr = (const struct ip *)(packet + sizeof(struct ether_header));
    uint32_t ip_header_len = (uint32_t)ip_hdr->ip_hl * 4;
    if (ip_header_len < sizeof(struct ip)) return 0;

    if (caplen < sizeof(struct ether_header) + ip_header_len) return 0;

    *ip_total_len = ntohs(ip_hdr->ip_len);

    if (ip_hdr->ip_p != IPPROTO_TCP) return 0;

    const struct tcphdr *tcp_hdr = (const struct tcphdr *)((const u_char *)ip_hdr + ip_header_len);
    uint32_t tcp_header_len = (uint32_t)tcp_hdr->th_off * 4;
    if (tcp_header_len < sizeof(struct tcphdr)) return 0;

    uint32_t l2_l3_len = sizeof(struct ether_header) + ip_header_len + tcp_header_len;
    if (caplen < l2_l3_len) return 0;

    uint32_t total_ip_tcp_len = (uint32_t)(ntohs(ip_hdr->ip_len));
    if (total_ip_tcp_len < ip_header_len + tcp_header_len) {
        *payload_len = 0;
    } else {
        *payload_len = total_ip_tcp_len - ip_header_len - tcp_header_len;
    }

    *tcp_flags = tcp_hdr->th_flags;
    return 1;
}

static void finalize_window(FILE *csv, const Config *cfg, const WindowStats *s, uint32_t window_id) {
    if (s->total_packets == 0) return;

    double duration = 0.0;
    if (s->has_first_ts) {
        duration = tv_diff_seconds(&s->first_ts, &s->last_ts);
        if (duration < 0.0) duration = 0.0;
    }

    double avg_pkt_size = s->total_packets ? ((double)s->total_bytes / (double)s->total_packets) : 0.0;
    double packet_rate = (duration > 0.0) ? ((double)s->total_packets / duration) : 0.0;
    double mean_iat = (s->total_packets > 1 && duration > 0.0) ? (duration / (double)(s->total_packets - 1)) : 0.0;

    /* Candidate extensions can be added here as the spec matures.
       For now, burstiness_cv and orig_bytes are set to 0.0 as placeholders. */
    double burstiness_cv = 0.0;
    uint64_t orig_bytes = 0;

    fprintf(csv,
            "%u%s%s%s%s%s%u%s%llu%s%.6f%s%.6f%s%.6f%s%u%s%llu%s%.6f%s%.6f%s%.6f%s%.6f%s%llu\n",
            window_id,
            CSV_DELIM,
            cfg->label,
            CSV_DELIM,
            cfg->device,
            CSV_DELIM,
            s->total_packets,
            CSV_DELIM,
            (unsigned long long)s->total_bytes,
            CSV_DELIM,
            avg_pkt_size,
            CSV_DELIM,
            duration,
            CSV_DELIM,
            mean_iat,
            CSV_DELIM,
            s->tcp_ack_count,
            CSV_DELIM,
            (unsigned long long)orig_bytes,
            CSV_DELIM,
            packet_rate,
            CSV_DELIM,
            burstiness_cv,
            CSV_DELIM,
            (double)0.0,   /* max_pkt_size placeholder if not tracked yet */
            CSV_DELIM,
            (unsigned long long)0);

    (void)window_id;
}

static void print_usage(const char *prog) {
    fprintf(stderr,
            "Usage: %s <input.pcap> <output.csv> [window_size]\n"
            "Example: %s data/raw/sample.pcap data/processed/sample.csv 8\n",
            prog, prog);
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        print_usage(argv[0]);
        return EXIT_FAILURE;
    }

    Config cfg;
    memset(&cfg, 0, sizeof(cfg));
    snprintf(cfg.pcap_path, sizeof(cfg.pcap_path), "%s", argv[1]);
    snprintf(cfg.output_csv, sizeof(cfg.output_csv), "%s", argv[2]);
    cfg.window_size = (argc >= 4) ? atoi(argv[3]) : 8;

    if (cfg.window_size <= 0 || cfg.window_size > MAX_WINDOW_SIZE) {
        fprintf(stderr, "Invalid window size. Must be 1..%d\n", MAX_WINDOW_SIZE);
        return EXIT_FAILURE;
    }

    infer_label_and_device_from_path(cfg.pcap_path, cfg.label, sizeof(cfg.label), cfg.device, sizeof(cfg.device));

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_offline(cfg.pcap_path, errbuf);
    if (!handle) {
        fprintf(stderr, "pcap_open_offline failed: %s\n", errbuf);
        return EXIT_FAILURE;
    }

    FILE *csv = fopen(cfg.output_csv, "w");
    if (!csv) {
        fprintf(stderr, "Failed to open output CSV: %s\n", cfg.output_csv);
        pcap_close(handle);
        return EXIT_FAILURE;
    }

    /* Header */
    fprintf(csv, "window_id,label,device,total_packets,total_bytes,avg_pkt_size,duration,mean_iat,tcp_ack_count,orig_bytes,packet_rate,burstiness_cv,max_pkt_size,reserved\n");

    struct pcap_pkthdr *header = NULL;
    const u_char *packet = NULL;
    int rc = 0;
    uint32_t window_packets = 0;
    uint32_t window_id = 0;
    WindowStats stats;
    init_window_stats(&stats);

    while ((rc = pcap_next_ex(handle, &header, &packet)) >= 0) {
        if (rc == 0) {
            continue; /* timeout; mostly relevant for live capture, harmless here */
        }

        if (!stats.has_first_ts) {
            stats.first_ts = header->ts;
            stats.has_first_ts = 1;
        }
        stats.last_ts = header->ts;

        stats.total_packets++;
        stats.total_bytes += header->len;

        uint16_t ip_total_len = 0;
        uint8_t tcp_flags = 0;
        uint32_t payload_len = 0;

        if (is_tcp_packet(packet, header->caplen, &ip_total_len, &tcp_flags, &payload_len)) {
            stats.tcp_packet_count++;
            if (tcp_flags & TH_ACK) {
                stats.tcp_ack_count++;
            }
        }

        window_packets++;

        if (window_packets >= (uint32_t)cfg.window_size) {
            window_id++;
            finalize_window(csv, &cfg, &stats, window_id);
            init_window_stats(&stats);
            window_packets = 0;
        }
    }

    /* Flush the final partial window if any packets remain */
    if (window_packets > 0) {
        window_id++;
        finalize_window(csv, &cfg, &stats, window_id);
    }

    fclose(csv);
    pcap_close(handle);

    fprintf(stdout, "Wrote %u windows to %s\n", window_id, cfg.output_csv);
    return EXIT_SUCCESS;
}
