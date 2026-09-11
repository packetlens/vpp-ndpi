# Copyright (c) 2026 PacketFlow (packetflow.dev)
# vpp-flowspec-recv: BGP FlowSpec receive enforcement plugin.
# Standalone — does NOT depend on vpp-ndpi.

add_vpp_plugin(flowspec_recv
  SOURCES
    flowspec_recv.c
    flowspec_recv_node.c
    flowspec_recv_cli.c

  MULTIARCH_SOURCES
    flowspec_recv_node.c

  INSTALL_HEADERS
    flowspec_recv.h
)
