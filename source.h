/* FMADIO Ring Buffer Capture Plugin for Suricata
 * Copyright 2024-2025. Fidelis Machines, LLC
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef SURICATA_SOURCE_FMADIO_RING_H
#define SURICATA_SOURCE_FMADIO_RING_H

#include "suricata-common.h"

#define FMADIO_RING_IFACE_NAME_LENGTH 128

/**
 * Interface configuration structure.
 * Passed to thread init as initdata, similar to PfringIfaceConfig.
 */
typedef struct FmadioRingIfaceConfig_ {
    char iface[FMADIO_RING_IFACE_NAME_LENGTH];  /* Short device name (e.g., lxc_ring0) */
    const char *ring_path;                       /* Full ring path (e.g., /opt/fmadio/queue/lxc_ring0) */
    int threads;                                 /* Number of threads (always 1) */
    SC_ATOMIC_DECLARE(unsigned int, ref);        /* Reference count */
    void (*DerefFunc)(void *);                   /* Dereference callback */
} FmadioRingIfaceConfig;

/**
 * Register the FMADIO Ring receive thread module.
 *
 * @param slot The thread module slot to register in (TMM_RECEIVEPLUGIN)
 */
void TmModuleReceiveFmadioRingRegister(int slot);

/**
 * Register the FMADIO Ring decode thread module.
 *
 * @param slot The thread module slot to register in (TMM_DECODEPLUGIN)
 */
void TmModuleDecodeFmadioRingRegister(int slot);

#endif /* SURICATA_SOURCE_FMADIO_RING_H */
