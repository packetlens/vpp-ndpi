# Copyright (c) 2026 PacketFlow (packetflow.dev)

add_vpp_plugin(ipfix
  SOURCES
  ipfix.c
  ipfix_api.c
  ipfix_cli.c
  ipfix_export.c

  API_FILES
  ipfix.api

  INSTALL_HEADERS
  ipfix.h
)
