/* FMADIO Ring Buffer Capture Plugin for Suricata
 * Copyright 2024-2025. Fidelis Machines, LLC
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef SURICATA_RUNMODE_FMADIO_RING_H
#define SURICATA_RUNMODE_FMADIO_RING_H

/**
 * Get the default runmode for FMADIO Ring capture.
 *
 * @return "workers" - the recommended mode for FMADIO Ring
 */
const char *FmadioRingGetDefaultRunMode(void);

/**
 * Register FMADIO Ring runmodes with Suricata.
 *
 * @param slot The runmode slot to register in (RUNMODE_PLUGIN)
 */
void FmadioRingRunmodeRegister(int slot);

#endif /* SURICATA_RUNMODE_FMADIO_RING_H */
