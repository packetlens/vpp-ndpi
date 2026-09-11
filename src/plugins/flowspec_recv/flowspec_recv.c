/*
 * flowspec_recv.c
 *
 * Copyright (c) 2026 PacketFlow (packetflow.dev)
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * flowspec_recv.c - vpp-flowspec-recv plugin init and process node.
 *
 * The flowspec-recv-process node wakes every 100 ms, attempts to connect to
 * the Unix socket served by the flowspec-recv Go sidecar, and drains all
 * available JSON lines.  Each line is parsed as a rule install or remove
 * command.  Install commands add a prefix + action entry to the rule vec;
 * remove commands delete by rule_id.  Both write paths take the worker
 * barrier to keep the data-plane vec consistent.
 *
 * Copyright (c) 2026 PacketFlow (packetflow.dev)
 * Licensed under Apache 2.0
 */

#include <flowspec_recv/flowspec_recv.h>
#include <vnet/plugin/plugin.h>
#include <vnet/policer/xlate.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>

flowspec_recv_main_t flowspec_recv_main;

/* ── Plugin registration ─────────────────────────────────────────────────── */

VLIB_PLUGIN_REGISTER () = {
  .version = FLOWSPEC_RECV_VERSION,
  .description = "FlowSpec receive: enforce BGP FlowSpec rules in VPP (scrubber mode)",
};

/* ── Socket helpers ──────────────────────────────────────────────────────── */

static int
frr_sock_connect (flowspec_recv_main_t *fm)
{
  if (fm->sock_fd >= 0)
    return 0;

  if (!fm->sock_path || fm->sock_path[0] == '\0')
    return -1;

  int fd = socket (AF_UNIX, SOCK_STREAM, 0);
  if (fd < 0)
    return -1;

  struct sockaddr_un sa;
  clib_memset (&sa, 0, sizeof (sa));
  sa.sun_family = AF_UNIX;
  strncpy (sa.sun_path, (const char *) fm->sock_path, sizeof (sa.sun_path) - 1);

  if (connect (fd, (struct sockaddr *) &sa, sizeof (sa)) < 0)
    {
      close (fd);
      return -1;
    }

  vlib_log_info (fm->log_class, "connected to %s", fm->sock_path);
  fm->sock_fd = fd;
  return 0;
}

static void
frr_sock_close (flowspec_recv_main_t *fm)
{
  if (fm->sock_fd >= 0)
    {
      close (fm->sock_fd);
      fm->sock_fd = -1;
    }
  fm->recv_buf_len = 0;
}

/* ── JSON parsing helpers ────────────────────────────────────────────────── */

/* Minimal JSON string field extractor. Finds "key":"value" in buf.
 * Copies value (without quotes) into dst up to dst_len-1 bytes.
 * Returns 1 on success, 0 if key not found. */
static int
json_get_string (const char *buf, const char *key, char *dst, u32 dst_len)
{
  char search[64];
  snprintf (search, sizeof (search), "\"%s\":\"", key);
  const char *p = strstr (buf, search);
  if (!p)
    return 0;
  p += strlen (search);
  const char *end = strchr (p, '"');
  if (!end)
    return 0;
  u32 len = (u32) (end - p);
  if (len >= dst_len)
    len = dst_len - 1;
  memcpy (dst, p, len);
  dst[len] = '\0';
  return 1;
}

/* Minimal JSON integer field extractor. Finds "key":number. */
static int
json_get_u64 (const char *buf, const char *key, u64 *out)
{
  char search[64];
  snprintf (search, sizeof (search), "\"%s\":", key);
  const char *p = strstr (buf, search);
  if (!p)
    return 0;
  p += strlen (search);
  *out = (u64) strtoull (p, NULL, 10);
  return 1;
}

/* ── Rule install / remove ───────────────────────────────────────────────── */

/* Parse "10.0.0.1/32" into address + prefix_len.  Returns 1 on success. */
static int
parse_cidr (const char *cidr, ip4_address_t *addr, u8 *plen)
{
  char tmp[32];
  strncpy (tmp, cidr, sizeof (tmp) - 1);
  tmp[sizeof (tmp) - 1] = '\0';

  char *slash = strchr (tmp, '/');
  if (!slash)
    return 0;
  *slash = '\0';
  *plen = (u8) atoi (slash + 1);
  if (*plen > 32)
    return 0;

  u32 a = 0;
  if (sscanf (tmp, "%u.%u.%u.%u",
	      (unsigned *) &((u8 *) &a)[0],
	      (unsigned *) &((u8 *) &a)[1],
	      (unsigned *) &((u8 *) &a)[2],
	      (unsigned *) &((u8 *) &a)[3]) != 4)
    return 0;

  addr->as_u32 = a;
  /* Mask to network address. */
  if (*plen == 0)
    addr->as_u32 = 0;
  else
    {
      u32 mask = ~0u << (32 - *plen);
      addr->as_u32 &= clib_host_to_net_u32 (mask);
    }
  return 1;
}

static void
frr_rule_install (flowspec_recv_main_t *fm, const char *line)
{
  char rule_id[37] = { 0 };
  char dst_cidr[32] = { 0 };
  char action_str[16] = { 0 };
  u64 rate_bps = 0;

  if (!json_get_string (line, "rule_id", rule_id, sizeof (rule_id)))
    {
      vlib_log_warn (fm->log_class, "install: missing rule_id");
      return;
    }
  if (!json_get_string (line, "dst", dst_cidr, sizeof (dst_cidr)))
    {
      vlib_log_warn (fm->log_class, "install: missing dst");
      return;
    }
  if (!json_get_string (line, "action", action_str, sizeof (action_str)))
    {
      vlib_log_warn (fm->log_class, "install: missing action");
      return;
    }
  json_get_u64 (line, "rate_bps", &rate_bps);

  ip4_address_t addr;
  u8 plen;
  if (!parse_cidr (dst_cidr, &addr, &plen))
    {
      vlib_log_warn (fm->log_class, "install: bad cidr %s", dst_cidr);
      return;
    }

  u8 action = FLOWSPEC_RECV_ACTION_DROP;
  if (strcmp (action_str, "rate_limit") == 0 ||
      strcmp (action_str, "rate-limit") == 0)
    action = FLOWSPEC_RECV_ACTION_RATE_LIMIT;

  /* Remove any existing rule with the same rule_id (idempotent reinstall). */
  flowspec_recv_rule_t *r;
  vec_foreach (r, fm->rules)
    {
      if (strncmp ((char *) r->rule_id, rule_id, 36) == 0 && r->valid)
	{
	  vlib_worker_thread_barrier_sync (fm->vlib_main);
	  r->valid = 0;
	  vlib_worker_thread_barrier_release (fm->vlib_main);
	  if (r->pol_index != ~0u)
	    {
	      policer_del (fm->vlib_main, r->pol_index);
	      r->pol_index = ~0u;
	    }
	  break;
	}
    }

  u32 pol_index = ~0u;

  if (action == FLOWSPEC_RECV_ACTION_RATE_LIMIT && rate_bps > 0)
    {
      char pol_name[64];
      snprintf (pol_name, sizeof (pol_name), "frrecv-%s", rule_id);

      /* kbps = rate_bps * 8 / 1000 */
      u32 rate_kbps = (u32) ((rate_bps * 8) / 1000);
      if (rate_kbps == 0)
	rate_kbps = 1;
      u32 burst_bytes = (u32) (rate_bps / 8); /* ~1 second burst */
      if (burst_bytes < 1500)
	burst_bytes = 1500;

      qos_pol_cfg_params_st cfg;
      clib_memset (&cfg, 0, sizeof (cfg));
      cfg.rb.kbps.cir_kbps = rate_kbps;
      cfg.rb.kbps.cb_bytes = burst_bytes;
      cfg.rb.kbps.eb_bytes = 0;
      cfg.rate_type = QOS_RATE_KBPS;
      cfg.rnd_type = QOS_ROUND_TO_CLOSEST;
      cfg.rfc = QOS_POLICER_TYPE_1R2C;
      cfg.conform_action.action_type = QOS_ACTION_TRANSMIT;
      cfg.exceed_action.action_type = QOS_ACTION_DROP;
      cfg.violate_action.action_type = QOS_ACTION_DROP;

      if (policer_add (fm->vlib_main, (u8 *) pol_name, &cfg, &pol_index))
	{
	  vlib_log_warn (fm->log_class,
			 "install: policer_add failed for %s, using drop",
			 rule_id);
	  action = FLOWSPEC_RECV_ACTION_DROP;
	  pol_index = ~0u;
	}
    }

  /* Find a free (invalid) slot or append a new one. */
  flowspec_recv_rule_t *slot = NULL;
  vec_foreach (r, fm->rules)
    {
      if (!r->valid)
	{
	  slot = r;
	  break;
	}
    }

  flowspec_recv_rule_t new_rule;
  clib_memset (&new_rule, 0, sizeof (new_rule));
  new_rule.dst = addr;
  new_rule.prefix_len = plen;
  new_rule.action = action;
  new_rule.rate_bps = rate_bps;
  new_rule.pol_index = pol_index;
  new_rule.valid = 1;
  strncpy ((char *) new_rule.rule_id, rule_id, 36);

  vlib_worker_thread_barrier_sync (fm->vlib_main);
  if (slot)
    *slot = new_rule;
  else
    vec_add1 (fm->rules, new_rule);
  fm->rules_installed++;
  vlib_worker_thread_barrier_release (fm->vlib_main);

  vlib_log_info (fm->log_class, "installed rule %s dst=%s action=%s",
		 rule_id, dst_cidr, action_str);
}

static void
frr_rule_remove (flowspec_recv_main_t *fm, const char *line)
{
  char rule_id[37] = { 0 };
  if (!json_get_string (line, "rule_id", rule_id, sizeof (rule_id)))
    {
      vlib_log_warn (fm->log_class, "remove: missing rule_id");
      return;
    }

  flowspec_recv_rule_t *r;
  vec_foreach (r, fm->rules)
    {
      if (strncmp ((char *) r->rule_id, rule_id, 36) == 0 && r->valid)
	{
	  u32 pol_index = r->pol_index;

	  vlib_worker_thread_barrier_sync (fm->vlib_main);
	  r->valid = 0;
	  r->pol_index = ~0u;
	  fm->rules_removed++;
	  vlib_worker_thread_barrier_release (fm->vlib_main);

	  if (pol_index != ~0u)
	    policer_del (fm->vlib_main, pol_index);

	  vlib_log_info (fm->log_class, "removed rule %s", rule_id);
	  return;
	}
    }
  vlib_log_warn (fm->log_class, "remove: rule_id %s not found", rule_id);
}

/* ── Process one complete JSON line ─────────────────────────────────────── */

static void
frr_process_line (flowspec_recv_main_t *fm, const char *line)
{
  char type_str[16] = { 0 };
  if (!json_get_string (line, "type", type_str, sizeof (type_str)))
    return;

  if (strcmp (type_str, "install") == 0)
    frr_rule_install (fm, line);
  else if (strcmp (type_str, "remove") == 0)
    frr_rule_remove (fm, line);
  else
    vlib_log_warn (fm->log_class, "unknown event type: %s", type_str);
}

/* ── Read available data from socket, split on newlines ─────────────────── */

#define RECV_CHUNK 4096

static void
frr_sock_drain (flowspec_recv_main_t *fm)
{
  u8 chunk[RECV_CHUNK];

  while (1)
    {
      ssize_t n = recv (fm->sock_fd, chunk, sizeof (chunk) - 1, MSG_DONTWAIT);
      if (n <= 0)
	{
	  if (n == 0 || (errno != EAGAIN && errno != EWOULDBLOCK))
	    {
	      /* Connection closed or error. */
	      if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK)
		fm->socket_errors++;
	      frr_sock_close (fm);
	    }
	  return;
	}

      /* Append to line buffer. */
      vec_add (fm->recv_buf, chunk, (u32) n);
      fm->recv_buf_len += (u32) n;

      /* Process all complete lines. */
      while (1)
	{
	  /* Find newline in recv_buf[0..recv_buf_len-1]. */
	  u8 *nl = NULL;
	  for (u32 i = 0; i < fm->recv_buf_len; i++)
	    {
	      if (fm->recv_buf[i] == '\n')
		{
		  nl = &fm->recv_buf[i];
		  break;
		}
	    }
	  if (!nl)
	    break;

	  u32 line_len = (u32) (nl - fm->recv_buf);
	  /* NUL-terminate the line in place. */
	  *nl = '\0';
	  if (line_len > 0)
	    frr_process_line (fm, (const char *) fm->recv_buf);

	  /* Shift buffer left past the consumed line + newline. */
	  u32 consumed = line_len + 1;
	  u32 remaining = fm->recv_buf_len - consumed;
	  if (remaining > 0)
	    memmove (fm->recv_buf, fm->recv_buf + consumed, remaining);
	  fm->recv_buf_len -= consumed;
	  vec_set_len (fm->recv_buf, fm->recv_buf_len);
	}
    }
}

/* ── Process node (wakes every 100 ms) ──────────────────────────────────── */

static uword
flowspec_recv_process_fn (vlib_main_t *vm, vlib_node_runtime_t *rt,
			  vlib_frame_t *frame)
{
  flowspec_recv_main_t *fm = &flowspec_recv_main;

  while (1)
    {
      vlib_process_wait_for_event_or_clock (vm, 0.1 /* seconds */);
      vlib_process_get_events (vm, 0 /* discard */);

      if (!fm->sock_path || fm->sock_path[0] == '\0')
	continue;

      if (fm->sock_fd < 0)
	{
	  if (frr_sock_connect (fm) < 0)
	    continue; /* sidecar not yet up — retry next tick */
	}

      frr_sock_drain (fm);
    }

  return 0;
}

VLIB_REGISTER_NODE (flowspec_recv_process_node) = {
  .function = flowspec_recv_process_fn,
  .name = "flowspec-recv-process",
  .type = VLIB_NODE_TYPE_PROCESS,
};

/* ── Public API ──────────────────────────────────────────────────────────── */

int
flowspec_recv_set_socket_path (const char *path)
{
  flowspec_recv_main_t *fm = &flowspec_recv_main;

  frr_sock_close (fm);

  vec_free (fm->sock_path);
  fm->sock_path = 0;

  if (path && path[0])
    {
      u32 len = strlen (path) + 1;
      vec_validate (fm->sock_path, len - 1);
      clib_memcpy (fm->sock_path, path, len);
      fm->sock_path[len - 1] = '\0';
      fm->recv_buf_len = 0;
    }

  return 0;
}

int
flowspec_recv_enable_disable_interface (u32 sw_if_index, int enable)
{
  return vnet_feature_enable_disable ("ip4-unicast", "flowspec-recv",
				      sw_if_index, enable, 0, 0);
}

/* ── Plugin init ─────────────────────────────────────────────────────────── */

static clib_error_t *
flowspec_recv_init (vlib_main_t *vm)
{
  flowspec_recv_main_t *fm = &flowspec_recv_main;
  fm->vlib_main = vm;
  fm->log_class = vlib_log_register_class ("flowspec-recv", 0);
  fm->sock_fd = -1;

  /* Default socket path — same as plan. */
  const char *dflt = FLOWSPEC_RECV_SOCK_PATH;
  u32 len = strlen (dflt) + 1;
  vec_validate (fm->sock_path, len - 1);
  clib_memcpy (fm->sock_path, dflt, len);

  vec_validate (fm->recv_buf, 4095);
  vec_set_len (fm->recv_buf, 0);
  fm->recv_buf_len = 0;

  vlib_log_info (fm->log_class, "vpp-flowspec-recv %s initialized",
		 FLOWSPEC_RECV_VERSION);
  return 0;
}

VLIB_INIT_FUNCTION (flowspec_recv_init);
