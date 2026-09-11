/*
 * policy.h
 *
 * Copyright (c) 2026 PacketFlow (packetflow.dev)
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * policy.h - vpp-policy: per-app drop/permit enforcement for vpp-ndpi.
 *
 * Runs as a VPP feature node after ndpi-observe in the ip4-unicast arc.
 * Reads the app_protocol classification from the flow entry and applies
 * configurable drop/permit rules per application.
 *
 * Compiled into ndpi_plugin.so alongside ndpi, ipfix, and flowspec code.
 *
 * Copyright (c) 2026 PacketFlow (packetflow.dev)
 * Licensed under Apache 2.0
 */

#ifndef __included_vpp_policy_h__
#define __included_vpp_policy_h__

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vlib/vlib.h>
#include <ndpi/ndpi.h>

#define POLICY_PLUGIN_VERSION "0.1.0"

/* Per-packet enforcement actions. */
#define POLICY_ACTION_PERMIT  0
#define POLICY_ACTION_DROP    1

/* Per-app rule entry, indexed by nDPI app_protocol ID in the data-plane vec.
 * valid==0 means no rule is set for this slot (use default_action). */
typedef struct
{
  u8 action; /* POLICY_ACTION_* */
  u8 valid;  /* 1 = rule explicitly configured */
} policy_app_rule_t;

/* Named rule — stored for 'show policy' display. */
typedef struct
{
  u8 app_name[64]; /* NUL-terminated */
  u16 app_id;
  u8 action;
} policy_named_rule_t;

/* Plugin main struct. One global instance. */
typedef struct
{
  /* Data-plane vec: index = nDPI app_protocol ID.  Read on hot path.
   * Writes serialised with vlib_worker_thread_barrier_sync(). */
  policy_app_rule_t *app_rules;

  /* Named rules for 'show policy' display.  Not accessed on hot path. */
  policy_named_rule_t *named_rules;

  /* Action taken when no per-app rule matches a classified flow. */
  u8 default_action; /* POLICY_ACTION_PERMIT by default */

  u32 log_class;
  vlib_main_t *vlib_main;
} policy_main_t;

extern policy_main_t policy_main;

/* policy.c — public API used by policy_cli.c */
int policy_set_app (const u8 *app_name, u8 action);
int policy_clear_app (const u8 *app_name);
int policy_set_default_action (u8 action);
int policy_interface_enable_disable (u32 sw_if_index, int enable);

#endif /* __included_vpp_policy_h__ */
