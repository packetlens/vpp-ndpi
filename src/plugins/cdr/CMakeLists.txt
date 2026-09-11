add_vpp_plugin(cdr
  SOURCES
    cdr.c
    cdr_node.c
    cdr_hep3.c
    cdr_cli.c

  MULTIARCH_SOURCES
    cdr_node.c

  INSTALL_HEADERS
    cdr.h
)
