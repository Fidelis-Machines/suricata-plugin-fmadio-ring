/* FMADIO Ring Buffer Capture Plugin for Suricata
 * Copyright 2024-2025. Fidelis Machines, LLC
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "suricata-common.h"
#include "suricata.h"
#include "runmodes.h"
#include "tm-threads.h"
#include "util-affinity.h"
#include "util-device.h"

#include "runmode.h"
#include "source.h"

/* Thread name prefix - use fmadio_ prefix to avoid conflict with Suricata's extern globals */
static const char *fmadio_thread_name_single = "RxFmadioRing";
static const char *fmadio_thread_name_workers = "W#";

/* External function to get the ring path from plugin.c */
extern const char *FmadioRingGetPath(void);

/**
 * Get the default runmode for FMADIO Ring capture.
 */
const char *FmadioRingGetDefaultRunMode(void)
{
    return "workers";
}

/**
 * Single-threaded runmode.
 * All processing happens in a single thread.
 */
static int RunModeSingle(void)
{
    SCLogNotice("Running FMADIO Ring in single thread mode");

    /* Get the ring buffer path from command line args */
    const char *ring_path = FmadioRingGetPath();

    char thread_name[TM_THREAD_NAME_MAX];
    snprintf(thread_name, sizeof(thread_name), "%s#01", fmadio_thread_name_single);

    ThreadVars *tv = TmThreadCreatePacketHandler(thread_name,
            "packetpool", "packetpool",
            "packetpool", "packetpool",
            "pktacqloop");
    if (tv == NULL) {
        SCLogError("TmThreadCreatePacketHandler failed");
        return -1;
    }

    TmModule *tm_module = TmModuleGetByName("ReceiveFmadioRing");
    if (tm_module == NULL) {
        FatalError("TmModuleGetByName failed for ReceiveFmadioRing");
    }
    /* Pass ring_path as initdata to the thread module */
    TmSlotSetFuncAppend(tv, tm_module, (void *)ring_path);

    tm_module = TmModuleGetByName("DecodeFmadioRing");
    if (tm_module == NULL) {
        FatalError("TmModuleGetByName failed for DecodeFmadioRing");
    }
    TmSlotSetFuncAppend(tv, tm_module, NULL);

    tm_module = TmModuleGetByName("FlowWorker");
    if (tm_module == NULL) {
        FatalError("TmModuleGetByName failed for FlowWorker");
    }
    TmSlotSetFuncAppend(tv, tm_module, NULL);

    TmThreadSetCPU(tv, WORKER_CPU_SET);

    if (TmThreadSpawn(tv) != TM_ECODE_OK) {
        FatalError("TmThreadSpawn failed");
    }

    return 0;
}

/**
 * Workers runmode.
 * Each worker thread handles all processing for its packets.
 * This is the recommended mode for FMADIO Ring.
 */
static int RunModeWorkers(void)
{
    SCLogNotice("Running FMADIO Ring in workers mode");

    /* Get the ring buffer path from command line args */
    const char *ring_path = FmadioRingGetPath();

    char thread_name[TM_THREAD_NAME_MAX];
    snprintf(thread_name, sizeof(thread_name), "%s%s", fmadio_thread_name_workers, "FmadioRing");

    ThreadVars *tv = TmThreadCreatePacketHandler(thread_name,
            "packetpool", "packetpool",
            "packetpool", "packetpool",
            "pktacqloop");
    if (tv == NULL) {
        SCLogError("TmThreadCreatePacketHandler failed");
        return -1;
    }

    TmModule *tm_module = TmModuleGetByName("ReceiveFmadioRing");
    if (tm_module == NULL) {
        FatalError("TmModuleGetByName failed for ReceiveFmadioRing");
    }
    /* Pass ring_path as initdata to the thread module */
    TmSlotSetFuncAppend(tv, tm_module, (void *)ring_path);

    tm_module = TmModuleGetByName("DecodeFmadioRing");
    if (tm_module == NULL) {
        FatalError("TmModuleGetByName failed for DecodeFmadioRing");
    }
    TmSlotSetFuncAppend(tv, tm_module, NULL);

    tm_module = TmModuleGetByName("FlowWorker");
    if (tm_module == NULL) {
        FatalError("TmModuleGetByName failed for FlowWorker");
    }
    TmSlotSetFuncAppend(tv, tm_module, NULL);

    TmThreadSetCPU(tv, WORKER_CPU_SET);

    if (TmThreadSpawn(tv) != TM_ECODE_OK) {
        FatalError("TmThreadSpawn failed");
    }

    return 0;
}

/**
 * Register FMADIO Ring runmodes with Suricata.
 */
void FmadioRingRunmodeRegister(int slot)
{
    SCLogDebug("Registering FMADIO Ring runmodes in slot %d", slot);

    RunModeRegisterNewRunMode(slot, "single",
            "Single threaded FMADIO Ring mode",
            RunModeSingle, NULL);

    RunModeRegisterNewRunMode(slot, "workers",
            "Workers mode - each thread handles all processing (recommended)",
            RunModeWorkers, NULL);
}
