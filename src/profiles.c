#include "profiles.h"

#include <string.h>

const char *const EDGEIIOT_FEATURE_NAMES[FEATURE_COUNT] = {
    "total_bytes",
    "avg_pkt_size",
    "duration",
    "total_pkts",
    "mean_iat",
    "pkts_per_sec",
    "ack_count",
    "orig_bytes",
    "burstiness_cv",
    "max_pkt_size"
};

const feature_contract_t EDGEIIOT_FEATURE_CONTRACT = {
    "edgeiiot_feature_contract_v1",
    FEATURE_COUNT,
    EDGEIIOT_FEATURE_NAMES
};

const profile_t EDGEIIOT_PROFILE = {
    "edgeiiot",
    "Edge-IIoT defensive observation profile",
    &EDGEIIOT_FEATURE_CONTRACT,
    8u
};

const char *feature_name(feature_id_t id)
{
    if (id < 0 || id >= FEATURE_COUNT) {
        return "unknown";
    }
    return EDGEIIOT_FEATURE_NAMES[id];
}

const profile_t *get_profile(const char *name)
{
    if (name == NULL) {
        return &EDGEIIOT_PROFILE;
    }

    if (strcmp(name, "edgeiiot") == 0) {
        return &EDGEIIOT_PROFILE;
    }

    return NULL;
}
