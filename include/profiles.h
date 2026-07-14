#ifndef PROFILES_H
#define PROFILES_H

#include "feature_contract.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct profile_t {
    const char *name;
    const char *description;
    const feature_contract_t *contract;
    unsigned int window_size;
} profile_t;

/*
 * Single baseline profile for Edge-IIoT.
 * Later, you can clone this into edgeiiot_w4, edgeiiot_w8, edgeiiot_w16, etc.
 */
extern const profile_t EDGEIIOT_PROFILE;

const profile_t *get_profile(const char *name);

#ifdef __cplusplus
}
#endif

#endif /* PROFILES_H */
