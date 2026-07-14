#ifndef FEATURE_CONTRACT_H
#define FEATURE_CONTRACT_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Edge-IIoT defensive observations.
 * Keep the ordering stable: this order is the contract used by CSV output,
 * training, and later ONNX / C inference alignment.
 */
typedef enum feature_id_t {
    FEATURE_TOTAL_BYTES = 0,
    FEATURE_AVG_PKT_SIZE,
    FEATURE_DURATION,
    FEATURE_TOTAL_PKTS,
    FEATURE_MEAN_IAT,
    FEATURE_PKTS_PER_SEC,
    FEATURE_ACK_COUNT,
    FEATURE_ORIG_BYTES,
    FEATURE_BURSTINESS_CV,
    FEATURE_MAX_PKT_SIZE,
    FEATURE_COUNT
} feature_id_t;

typedef struct feature_contract_t {
    const char *name;
    size_t feature_count;
    const char *const *feature_names;
} feature_contract_t;

extern const char *const EDGEIIOT_FEATURE_NAMES[FEATURE_COUNT];
extern const feature_contract_t EDGEIIOT_FEATURE_CONTRACT;

const char *feature_name(feature_id_t id);

#ifdef __cplusplus
}
#endif

#endif /* FEATURE_CONTRACT_H */
