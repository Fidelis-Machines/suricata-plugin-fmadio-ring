/* FMADIO Ring Buffer Capture Plugin for Suricata
 * Copyright 2024-2025. Fidelis Machines, LLC
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * This plugin enables Suricata to capture packets from FMADIO devices
 * via their shared memory ring buffer interface.
 */

#include "suricata-plugin.h"
#include "suricata-common.h"
#include "util-debug.h"

#include "source.h"
#include "runmode.h"

/* Global storage for the ring buffer path from command line args.
 * This is set in InitCapturePlugin and read by FmadioRingGetPath(). */
static const char *fmadio_ring_path = NULL;

/**
 * Get the ring buffer path.
 * @return The ring buffer path from --capture-plugin-args, or NULL if not set.
 */
const char *FmadioRingGetPath(void)
{
    return fmadio_ring_path;
}

/**
 * Initialize the capture plugin.
 * Called by Suricata when the plugin is selected via --capture-plugin.
 *
 * @param args Plugin arguments from --capture-plugin-args (ring buffer path)
 * @param plugin_slot Runmode slot (RUNMODE_PLUGIN)
 * @param receive_slot Thread module slot for receiver (TMM_RECEIVEPLUGIN)
 * @param decode_slot Thread module slot for decoder (TMM_DECODEPLUGIN)
 */
static void InitCapturePlugin(const char *args, int plugin_slot,
                               int receive_slot, int decode_slot)
{
    SCLogNotice("Initializing FMADIO Ring capture plugin");
    SCLogNotice("Ring buffer path: %s", args ? args : "(default)");

    /* Store the ring buffer path for later use */
    fmadio_ring_path = args;

    /* Register runmodes (workers, single) */
    FmadioRingRunmodeRegister(plugin_slot);

    /* Register thread modules */
    TmModuleReceiveFmadioRingRegister(receive_slot);
    TmModuleDecodeFmadioRingRegister(decode_slot);
}

/**
 * Plugin initialization callback.
 * Called when the plugin shared library is loaded.
 */
static void SCPluginInit(void)
{
    SCLogNotice("Loading FMADIO Ring capture plugin");

    SCCapturePlugin *plugin = SCCalloc(1, sizeof(SCCapturePlugin));
    if (plugin == NULL) {
        FatalError("Failed to allocate memory for FMADIO Ring capture plugin");
    }

    plugin->name = "fmadio-ring";
    plugin->Init = InitCapturePlugin;
    plugin->GetDefaultMode = FmadioRingGetDefaultRunMode;

    SCPluginRegisterCapture(plugin);
}

/**
 * Plugin registration structure.
 * Must be named PluginRegistration and returned by SCPluginRegister().
 */
const SCPlugin PluginRegistration = {
    .version = SC_API_VERSION,
    .suricata_version = SC_PACKAGE_VERSION,
    .name = "fmadio-ring",
    .plugin_version = "0.1.0",
    .author = "Fidelis Machines, LLC",
    .license = "GPL-2.0-only",
    .Init = SCPluginInit,
};

/**
 * Plugin entry point.
 * Called by Suricata via dlsym() when the plugin is loaded.
 *
 * @return Pointer to the plugin registration structure
 */
const SCPlugin *SCPluginRegister(void)
{
    return &PluginRegistration;
}
