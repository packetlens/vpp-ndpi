/*
 * cdr.c - vpp-cdr plugin init and interface management.
 *
 * Copyright (c) 2026 PacketFlow (packetflow.dev)
 * Licensed under Apache 2.0
 */

#include <cdr/cdr.h>
#include <vnet/plugin/plugin.h>
#include <vnet/feature/feature.h>
#include <vnet/ip/format.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <unistd.h>

cdr_main_t cdr_main;

/* ── Plugin registration ─────────────────────────────────────────────────── */

VLIB_PLUGIN_REGISTER () = {
  .version     = CDR_VERSION,
  .description = "vpp-cdr: SIP CDR export via HEP3 to Homer (PacketLens)",
};

/* ── Socket management ───────────────────────────────────────────────────── */

int
cdr_hep_sock_open (cdr_main_t *cm)
{
  if (cm->hep_sock >= 0)
    return 0;                         /* already open */

  if (!cm->homer_ip4)
    return -1;                        /* not configured */

  int fd = socket (AF_INET, SOCK_DGRAM, 0);
  if (fd < 0)
    {
      vlib_log_err (cm->log_class, "socket() failed: %d", errno);
      return -1;
    }

  /* Non-blocking so sendto() never stalls the forwarding path */
  int fl = fcntl (fd, F_GETFL, 0);
  if (fl >= 0)
    fcntl (fd, F_SETFL, fl | O_NONBLOCK);

  /* Pre-connect so each send() needs no sockaddr lookup */
  struct sockaddr_in sa = { 0 };
  sa.sin_family      = AF_INET;
  sa.sin_addr.s_addr = cm->homer_ip4;          /* already network order */
  sa.sin_port        = clib_host_to_net_u16 (cm->homer_port);

  if (connect (fd, (struct sockaddr *) &sa, sizeof (sa)) < 0)
    {
      /* UDP connect() to a remote addr may fail if the host is unreachable;
       * that is OK — we'll get errors at send() time, not here. */
      vlib_log_debug (cm->log_class, "connect() hint: %d (non-fatal)", errno);
    }

  cm->hep_sock = fd;
  vlib_log_info (cm->log_class, "HEP socket opened → %U:%u",
                 format_ip4_address, &cm->homer_ip4, cm->homer_port);
  return 0;
}

/* ── Interface enable / disable ─────────────────────────────────────────── */

int
cdr_interface_enable_disable (u32 sw_if_index, int enable)
{
  cdr_main_t *cm = &cdr_main;

  int rv = vnet_feature_enable_disable ("ip4-unicast", "cdr-observe",
                                        sw_if_index, enable, 0, 0);
  if (rv)
    return rv;

  cm->enabled_sw_if_indices =
    clib_bitmap_set (cm->enabled_sw_if_indices, sw_if_index, enable ? 1 : 0);

  vlib_log_info (cm->log_class, "%s cdr-observe on sw_if_index %u",
                 enable ? "enabled" : "disabled", sw_if_index);
  return 0;
}

/* ── Plugin init ─────────────────────────────────────────────────────────── */

static clib_error_t *
cdr_init (vlib_main_t *vm)
{
  cdr_main_t *cm = &cdr_main;

  cm->vlib_main        = vm;
  cm->vnet_main        = vnet_get_main ();
  cm->log_class        = vlib_log_register_class ("cdr", 0);
  cm->homer_ip4        = 0;
  cm->homer_port       = CDR_HEP_DEFAULT_PORT;
  cm->hep_sock         = -1;
  cm->capture_agent_id = CDR_HEP_DEFAULT_AGENT;
  cm->hep_password     = 0;
  cm->sip_proto_id     = 0;   /* resolved lazily on first tick */

  return 0;
}
VLIB_INIT_FUNCTION (cdr_init);
