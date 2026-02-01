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
#include "util-runmodes.h"
#include "util-time.h"

#include "runmode.h"
#include "source.h"

/**
 * Get the default runmode for FMADIO Ring capture.
 */
const char *FmadioRingGetDefaultRunMode(void)
{
    return "workers";
}

/**
 * Dereference and free config structure.
 */
static void FmadioRingDerefConfig(void *conf)
{
    FmadioRingIfaceConfig *pfconf = (FmadioRingIfaceConfig *)conf;
    if (SC_ATOMIC_SUB(pfconf->ref, 1) == 1) {
        SCFree(pfconf);
    }
}

/**
 * Parse interface configuration.
 * Called by RunModeSetLiveCapture* for each device.
 *
 * @param iface Ring buffer path (device name)
 * @return Allocated config structure, or NULL on error
 */
static void *ParseFmadioRingConfig(const char *iface)
{
    if (iface == NULL) {
        SCLogError("Interface name is NULL");
        return NULL;
    }

    FmadioRingIfaceConfig *conf = SCMalloc(sizeof(*conf));
    if (unlikely(conf == NULL)) {
        SCLogError("Failed to allocate FMADIO Ring config");
        return NULL;
    }

    memset(conf, 0, sizeof(*conf));
    strlcpy(conf->iface, iface, sizeof(conf->iface));
    conf->threads = 1;  /* Always 1 thread per ring */
    conf->DerefFunc = FmadioRingDerefConfig;
    SC_ATOMIC_INIT(conf->ref);
    (void)SC_ATOMIC_ADD(conf->ref, 1);

    SCLogDebug("Parsed config for interface: %s", iface);
    return conf;
}

/**
 * Get thread count for a device.
 * Always returns 1 - each ring gets exactly one thread.
 *
 * @param conf Config structure
 * @return Number of threads (always 1)
 */
static int FmadioRingGetThreadsCount(void *conf)
{
    FmadioRingIfaceConfig *pfconf = (FmadioRingIfaceConfig *)conf;
    return pfconf->threads;
}

/**
 * AutoFP runmode.
 * Multi-threaded mode where packets from each flow are assigned to
 * a single detect thread.
 */
static int RunModeAutoFp(void)
{
    SCEnter();
    int ret;

    TimeModeSetLive();

    ret = RunModeSetLiveCaptureAutoFp(
            ParseFmadioRingConfig,
            FmadioRingGetThreadsCount,
            "ReceiveFmadioRing",
            "DecodeFmadioRing",
            thread_name_autofp,
            NULL);

    if (ret != 0) {
        FatalError("FMADIO Ring autofp runmode failed");
    }

    SCLogNotice("FMADIO Ring autofp runmode initialized");
    return 0;
}

/**
 * Single-threaded runmode.
 * Creates one thread per configured ring buffer.
 */
static int RunModeSingle(void)
{
    SCEnter();
    int ret;

    TimeModeSetLive();

    ret = RunModeSetLiveCaptureSingle(
            ParseFmadioRingConfig,
            FmadioRingGetThreadsCount,
            "ReceiveFmadioRing",
            "DecodeFmadioRing",
            thread_name_single,
            NULL);

    if (ret != 0) {
        FatalError("FMADIO Ring single runmode failed");
    }

    SCLogNotice("FMADIO Ring single runmode initialized");
    return 0;
}

/**
 * Workers runmode.
 * Each worker thread handles all processing for its ring's packets.
 * This is the recommended mode for FMADIO Ring.
 */
static int RunModeWorkers(void)
{
    SCEnter();
    int ret;

    TimeModeSetLive();

    ret = RunModeSetLiveCaptureWorkers(
            ParseFmadioRingConfig,
            FmadioRingGetThreadsCount,
            "ReceiveFmadioRing",
            "DecodeFmadioRing",
            thread_name_workers,
            NULL);

    if (ret != 0) {
        FatalError("FMADIO Ring workers runmode failed");
    }

    SCLogNotice("FMADIO Ring workers runmode initialized");
    return 0;
}

/**
 * Register FMADIO Ring runmodes with Suricata.
 */
void FmadioRingRunmodeRegister(int slot)
{
    SCLogDebug("Registering FMADIO Ring runmodes in slot %d", slot);

    RunModeRegisterNewRunMode(slot, "autofp",
            "Multi-threaded FMADIO Ring mode with auto flow pinning",
            RunModeAutoFp, NULL);

    RunModeRegisterNewRunMode(slot, "single",
            "Single threaded FMADIO Ring mode",
            RunModeSingle, NULL);

    RunModeRegisterNewRunMode(slot, "workers",
            "Workers mode - each thread handles all processing (recommended)",
            RunModeWorkers, NULL);
}
