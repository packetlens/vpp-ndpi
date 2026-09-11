# Copyright (c) 2026 PacketFlow (packetflow.dev)

add_vpp_plugin(ndpi
  SOURCES
  ndpi.c
  ndpi_api.c
  ndpi_cli.c
  ndpi_classify_callback.c
  ndpi_counters.c
  ndpi_stats.c
  ndpi_flow.c
  ndpi_ndpi.c
  node_observe.c

  # IPFIX export — compiled into the ndpi plugin to avoid cross-.so symbol deps
  ../ipfix/ipfix.c
  ../ipfix/ipfix_cli.c
  ../ipfix/ipfix_export.c

  # FlowSpec threshold notification — compiled into the same .so
  ../flowspec/flowspec.c
  ../flowspec/flowspec_cli.c

  # Per-app drop/permit policy enforcement — compiled into the same .so
  ../policy/policy.c
  ../policy/policy_node.c
  ../policy/policy_cli.c

  # Per-app token-bucket rate limiting using the VPP policer engine
  ../policer_ndpi/policer_ndpi.c
  ../policer_ndpi/policer_ndpi_node.c
  ../policer_ndpi/policer_ndpi_cli.c

  API_FILES
  ndpi.api

  INSTALL_HEADERS
  ndpi.h
  ndpi_classify_callback.h
  ../ipfix/ipfix.h
  ../flowspec/flowspec.h
  ../policy/policy.h
  ../policer_ndpi/policer_ndpi.h

  LINK_LIBRARIES
  ${NDPI_LIBRARIES}
)
