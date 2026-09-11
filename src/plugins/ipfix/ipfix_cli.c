/*
 * ipfix_cli.c - vppctl commands for vpp-ipfix.
 *
 * Copyright (c) 2026 PacketFlow (packetflow.dev)
 * Licensed under Apache 2.0
 */

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <ipfix/ipfix.h>

/* ---------- set ipfix exporter ---------- */

static clib_error_t *
set_ipfix_exporter_fn (vlib_main_t *vm, unformat_input_t *input,
		       vlib_cli_command_t *cmd)
{
  ip4_address_t collector_ip = { 0 };
  ip4_address_t src_ip = { 0 };
  u32 port = 2055;
  int collector_set = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "collector %U", unformat_ip4_address, &collector_ip))
	collector_set = 1;
      else if (unformat (input, "port %u", &port))
	;
      else if (unformat (input, "src-address %U", unformat_ip4_address,
			 &src_ip))
	;
      else
	return clib_error_return (0, "unknown input '%U'",
				  format_unformat_error, input);
    }

  if (!collector_set)
    return clib_error_return (0, "collector IP required");
  if (port > 65535)
    return clib_error_return (0, "port must be 0–65535");

  int rv = ipfix_exporter_add (&collector_ip, (u16) port, &src_ip);
  if (rv)
    return clib_error_return (0, "ipfix_exporter_add rv=%d", rv);

  vlib_cli_output (vm, "IPFIX collector %U:%u added", format_ip4_address,
		   &collector_ip, port);
  return 0;
}

VLIB_CLI_COMMAND (set_ipfix_exporter_cmd, static) = {
  .path = "set ndpi-ipfix exporter",
  .short_help =
    "set ndpi-ipfix exporter collector <IP> [port <P>] [src-address <IP>]",
  .function = set_ipfix_exporter_fn,
};

/* ---------- clear ndpi-ipfix exporter ---------- */

static clib_error_t *
clear_ipfix_exporter_fn (vlib_main_t *vm, unformat_input_t *input,
			 vlib_cli_command_t *cmd)
{
  ipfix_exporter_del_all ();
  vlib_cli_output (vm, "IPFIX: all collectors removed, export disabled");
  return 0;
}

VLIB_CLI_COMMAND (clear_ipfix_exporter_cmd, static) = {
  .path = "clear ndpi-ipfix exporter",
  .short_help = "clear ndpi-ipfix exporter",
  .function = clear_ipfix_exporter_fn,
};

/* ---------- set ndpi-ipfix enable/disable ---------- */

static clib_error_t *
set_ipfix_ndpi_fn (vlib_main_t *vm, unformat_input_t *input,
		   vlib_cli_command_t *cmd)
{
  int enable = 1;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "enable"))
	enable = 1;
      else if (unformat (input, "disable"))
	enable = 0;
      else
	return clib_error_return (0, "unknown input '%U'",
				  format_unformat_error, input);
    }

  ipfix_main_t *im = &ipfix_main;
  if (enable && im->n_collectors == 0)
    return clib_error_return (
      0,
      "no collector configured — use 'set ndpi-ipfix exporter' first");

  ipfix_enable_disable (enable);
  vlib_cli_output (vm, "IPFIX export %s", enable ? "enabled" : "disabled");
  return 0;
}

VLIB_CLI_COMMAND (set_ipfix_ndpi_cmd, static) = {
  .path = "set ndpi-ipfix",
  .short_help = "set ndpi-ipfix [enable|disable]",
  .function = set_ipfix_ndpi_fn,
};

/* ---------- show ndpi-ipfix exporter ---------- */

static clib_error_t *
show_ipfix_exporter_fn (vlib_main_t *vm, unformat_input_t *input,
			vlib_cli_command_t *cmd)
{
  ipfix_main_t *im = &ipfix_main;

  vlib_cli_output (vm, "IPFIX export: %s",
		   im->enabled ? "enabled" : "disabled");
  if (im->n_collectors == 0)
    {
      vlib_cli_output (vm, "  No collectors configured");
      return 0;
    }
  for (u32 i = 0; i < im->n_collectors; i++)
    {
      ipfix_collector_t *c = &im->collectors[i];
      vlib_cli_output (vm, "  Collector %u: %U:%u (fd=%d)", i,
		       format_ip4_address, &c->ip, c->port, c->fd);
    }
  return 0;
}

VLIB_CLI_COMMAND (show_ipfix_exporter_cmd, static) = {
  .path = "show ndpi-ipfix exporter",
  .short_help = "show ndpi-ipfix exporter",
  .function = show_ipfix_exporter_fn,
};

/* ---------- show ipfix stats ---------- */

static clib_error_t *
show_ndpi_ipfix_stats_fn (vlib_main_t *vm, unformat_input_t *input,
			  vlib_cli_command_t *cmd)
{
  ipfix_main_t *im = &ipfix_main;

  vlib_cli_output (vm, "flows exported:      %llu", im->flows_exported);
  vlib_cli_output (vm, "PDUs sent:           %llu", im->pdus_sent);
  vlib_cli_output (vm, "ring overflow drops: %llu", im->ring_overflow_drops);
  vlib_cli_output (vm, "UDP send errors:     %llu", im->udp_send_errors);
  vlib_cli_output (vm, "templates sent:      %llu", im->templates_sent);
  vlib_cli_output (vm, "pending records:     %u", vec_len (im->pending));
  return 0;
}

VLIB_CLI_COMMAND (show_ndpi_ipfix_stats_cmd, static) = {
  .path = "show ndpi-ipfix stats",
  .short_help = "show ndpi-ipfix stats",
  .function = show_ndpi_ipfix_stats_fn,
};

/* ---------- clear ipfix stats ---------- */

static clib_error_t *
clear_ndpi_ipfix_stats_fn (vlib_main_t *vm, unformat_input_t *input,
			   vlib_cli_command_t *cmd)
{
  ipfix_main_t *im = &ipfix_main;
  im->flows_exported = 0;
  im->pdus_sent = 0;
  im->ring_overflow_drops = 0;
  im->udp_send_errors = 0;
  im->templates_sent = 0;
  vlib_cli_output (vm, "IPFIX stats cleared");
  return 0;
}

VLIB_CLI_COMMAND (clear_ndpi_ipfix_stats_cmd, static) = {
  .path = "clear ndpi-ipfix stats",
  .short_help = "clear ndpi-ipfix stats",
  .function = clear_ndpi_ipfix_stats_fn,
};
