/* FMADIO Ring Buffer Capture Plugin for Suricata
 * Copyright 2024-2025. Fidelis Machines, LLC
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef SURICATA_SOURCE_FMADIO_RING_H
#define SURICATA_SOURCE_FMADIO_RING_H

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
