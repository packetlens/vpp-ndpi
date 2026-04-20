/*
 * ndpi_classify_callback.c — Phase 7: DPI classification callback API.
 *
 * Provides ndpi_register_classify_callback() / ndpi_unregister_classify_callback()
 * for external plugins that want to receive nDPI flow verdicts in real time.
 *
 * The registered function is called from VPP worker threads once per flow,
 * immediately after nDPI reaches a final verdict (either a confident classify
 * or a give-up), before the nDPI flow struct is released.  The callback
 * receives the complete L7 verdict: app/master protocol, category, risk
 * bitmask, TLS SNI, and JA3 client fingerprint.
 *
 * Copyright (c) 2026 PacketFlow (packetflow.dev)
 * Licensed under Apache 2.0
 */

#include <ndpi/ndpi.h>
#include <ndpi/ndpi_classify_callback.h>
#include <vlib/vlib.h>
#include <string.h>

int
ndpi_register_classify_callback (const char *name,
                                   ndpi_on_flow_classified_fn_t fn,
                                   void *ctx)
{
  if (!fn || !name)
    return -1;

  ndpi_main_t *nm = &ndpi_main;

  /*
   * Swap fn/ctx atomically from the data plane's perspective:
   * take the worker barrier so no worker thread is mid-callback during
   * the pointer update.
   */
  vlib_worker_thread_barrier_sync (nm->vlib_main);
  nm->classify_cb      = fn;
  nm->classify_cb_ctx  = ctx;
  nm->classify_cb_calls = 0;
  strncpy ((char *) nm->classify_cb_name, name,
           sizeof (nm->classify_cb_name) - 1);
  nm->classify_cb_name[sizeof (nm->classify_cb_name) - 1] = '\0';
  vlib_worker_thread_barrier_release (nm->vlib_main);

  vlib_log_info (nm->log_class, "classify callback registered: %s", name);
  return 0;
}

void
ndpi_unregister_classify_callback (void)
{
  ndpi_main_t *nm = &ndpi_main;

  vlib_worker_thread_barrier_sync (nm->vlib_main);
  nm->classify_cb         = NULL;
  nm->classify_cb_ctx     = NULL;
  nm->classify_cb_name[0] = '\0';
  vlib_worker_thread_barrier_release (nm->vlib_main);

  vlib_log_info (nm->log_class, "classify callback unregistered");
}
