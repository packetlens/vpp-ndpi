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

  API_FILES
  ndpi.api

  INSTALL_HEADERS
  ndpi.h
  ndpi_classify_callback.h

  LINK_LIBRARIES
  ${NDPI_LIBRARIES}
)
