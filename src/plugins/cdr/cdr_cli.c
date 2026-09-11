/*
 * cdr_cli.c
 *
 * Copyright (c) 2026 PacketFlow (packetflow.dev)
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * cdr_cli.c - vpp-cdr CLI commands.
 *
 * Commands:
 *   set cdr hep server <ip> [port <n>]      — configure Homer destination
 *   set cdr hep agent-id <n>                — capture agent ID (default 1)
 *   set cdr hep password <string>           — optional HEP auth key
 *   set interface cdr enable  <iface>       — enable mirroring on interface
 *   set interface cdr disable <iface>       — disable mirroring on interface
 *   show cdr                                — show config + stats
 *
 * Copyright (c) 2026 PacketFlow (packetflow.dev)
 * Licensed under Apache 2.0
 */

#include <cdr/cdr.h>
#include <vnet/vnet.h>
#include <vlib/vlib.h>
#include <vnet/ip/ip4.h>
#include <vnet/ip/format.h>

#include <sys/socket.h>
#include <unistd.h>

/* ── set cdr hep server ──────────────────────────────────────────────────── */

static clib_error_t *
set_cdr_hep_fn (vlib_main_t *vm, unformat_input_t *input,
                vlib_cli_command_t *cmd)
{
  cdr_main_t *cm = &cdr_main;
  unformat_input_t _line_input, *li = &_line_input;

  if (!unformat_user (input, unformat_line_input, li))
    return clib_error_return (0, "expected arguments");

  clib_error_t *err = 0;
  int saw_server = 0;
  ip4_address_t server = { 0 };
  u32 port = cm->homer_port;
  u32 agent_id = ~0u;
  u8 *password = 0;
  int clear_password = 0;

  while (unformat_check_input (li) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (li, "server %U", unformat_ip4_address, &server))
        {
          saw_server = 1;
          if (unformat (li, "port %u", &port))
            ;
        }
      else if (unformat (li, "agent-id %u", &agent_id))
        ;
      else if (unformat (li, "password %s", &password))
        ;
      else if (unformat (li, "no-password"))
        clear_password = 1;
      else
        {
          err = clib_error_return (0, "unknown argument '%U'",
                                   format_unformat_error, li);
          goto done;
        }
    }

  if (saw_server)
    {
      /* Close any existing socket — will be re-opened with new address */
      if (cm->hep_sock >= 0)
        {
          close (cm->hep_sock);
          cm->hep_sock = -1;
        }
      cm->homer_ip4  = server.as_u32;
      cm->homer_port = (u16) port;
      /* Eager open */
      cdr_hep_sock_open (cm);
      vlib_cli_output (vm, "HEP server set to %U:%u",
                       format_ip4_address, &server, port);
    }

  if (agent_id != ~0u)
    {
      cm->capture_agent_id = agent_id;
      vlib_cli_output (vm, "capture agent-id set to %u", agent_id);
    }

  if (password)
    {
      vec_free (cm->hep_password);
      cm->hep_password = password;
      password = 0;
      vlib_cli_output (vm, "HEP password set (%u bytes)",
                       vec_len (cm->hep_password));
    }
  else if (clear_password)
    {
      vec_free (cm->hep_password);
      cm->hep_password = 0;
      vlib_cli_output (vm, "HEP password cleared");
    }

done:
  vec_free (password);
  unformat_free (li);
  return err;
}

VLIB_CLI_COMMAND (set_cdr_hep_cmd, static) = {
  .path       = "set cdr hep",
  .short_help = "set cdr hep server <ip> [port <n>] [agent-id <n>] "
                "[password <str>|no-password]",
  .function   = set_cdr_hep_fn,
};

/* ── set interface cdr enable / disable ─────────────────────────────────── */

static clib_error_t *
set_interface_cdr_fn (vlib_main_t *vm, unformat_input_t *input,
                      vlib_cli_command_t *cmd)
{
  vnet_main_t *vnm = vnet_get_main ();
  unformat_input_t _li, *li = &_li;

  if (!unformat_user (input, unformat_line_input, li))
    return clib_error_return (0, "expected arguments");

  clib_error_t *err = 0;
  u32 sw_if_index = ~0;
  int enable = -1;

  while (unformat_check_input (li) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (li, "enable %U", unformat_vnet_sw_interface, vnm,
                    &sw_if_index))
        enable = 1;
      else if (unformat (li, "disable %U", unformat_vnet_sw_interface, vnm,
                         &sw_if_index))
        enable = 0;
      else
        {
          err = clib_error_return (0, "unknown argument '%U'",
                                   format_unformat_error, li);
          goto done;
        }
    }

  if (sw_if_index == ~0 || enable < 0)
    {
      err = clib_error_return (0, "usage: set interface cdr enable|disable "
                               "<interface>");
      goto done;
    }

  int rv = cdr_interface_enable_disable (sw_if_index, enable);
  if (rv)
    err = clib_error_return (0, "cdr_interface_enable_disable: %d", rv);
  else
    vlib_cli_output (vm, "cdr %s on %U",
                     enable ? "enabled" : "disabled",
                     format_vnet_sw_if_index_name, vnm, sw_if_index);

done:
  unformat_free (li);
  return err;
}

VLIB_CLI_COMMAND (set_interface_cdr_cmd, static) = {
  .path       = "set interface cdr",
  .short_help = "set interface cdr enable|disable <interface>",
  .function   = set_interface_cdr_fn,
};

/* ── show cdr ────────────────────────────────────────────────────────────── */

static clib_error_t *
show_cdr_fn (vlib_main_t *vm, unformat_input_t *input,
             vlib_cli_command_t *cmd)
{
  cdr_main_t *cm = &cdr_main;
  vnet_main_t *vnm = vnet_get_main ();

  /* Config */
  if (cm->homer_ip4)
    vlib_cli_output (vm, "Homer server:    %U:%u",
                     format_ip4_address, &cm->homer_ip4, cm->homer_port);
  else
    vlib_cli_output (vm, "Homer server:    not configured");

  vlib_cli_output (vm, "Agent ID:        %u", cm->capture_agent_id);
  vlib_cli_output (vm, "Auth key:        %s",
                   cm->hep_password ? "set" : "none");
  vlib_cli_output (vm, "Socket:          %s",
                   cm->hep_sock >= 0 ? "open" : "closed");
  vlib_cli_output (vm, "SIP proto ID:    %u", cm->sip_proto_id);
  vlib_cli_output (vm, "");

  /* Enabled interfaces */
  vlib_cli_output (vm, "Enabled interfaces:");
  uword sw_if_index;
  int any = 0;
  clib_bitmap_foreach (sw_if_index, cm->enabled_sw_if_indices)
    {
      vlib_cli_output (vm, "  %U",
                       format_vnet_sw_if_index_name, vnm, sw_if_index);
      any = 1;
    }
  if (!any)
    vlib_cli_output (vm, "  (none)");

  /* Stats */
  vlib_cli_output (vm, "");
  vlib_cli_output (vm, "Stats:");
  vlib_cli_output (vm, "  pkts_mirrored:       %llu",
                   (unsigned long long) cm->pkts_mirrored);
  vlib_cli_output (vm, "  pkts_failed:         %llu",
                   (unsigned long long) cm->pkts_failed);
  vlib_cli_output (vm, "  pkts_not_configured: %llu",
                   (unsigned long long) cm->pkts_not_configured);

  return 0;
}

VLIB_CLI_COMMAND (show_cdr_cmd, static) = {
  .path       = "show cdr",
  .short_help = "show CDR HEP3 export configuration and stats",
  .function   = show_cdr_fn,
};
