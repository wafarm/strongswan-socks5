AM_CPPFLAGS = \
	-I$(top_srcdir)/src/libstrongswan \
	-I$(top_srcdir)/src/libcharon \
	-I$(top_srcdir)/src/libipsec

AM_CFLAGS = \
	$(PLUGIN_CFLAGS)

if MONOLITHIC
noinst_LTLIBRARIES = libstrongswan-kernel-libipsec.la
else
plugin_LTLIBRARIES = libstrongswan-kernel-libipsec.la
endif

libstrongswan_kernel_libipsec_la_SOURCES = \
	kernel_libipsec_plugin.h kernel_libipsec_plugin.c \
	kernel_libipsec_ipsec.h kernel_libipsec_ipsec.c \
	kernel_libipsec_plain.h \
	kernel_libipsec_router.h kernel_libipsec_router.c \
	kernel_libipsec_tun.h kernel_libipsec_tun.c \
	kernel_libipsec_esp_handler.h kernel_libipsec_esp_handler.c

if USE_KERNEL_LIBIPSEC_SOCKS
AM_CPPFLAGS += \
	-I$(srcdir)/lwip_port \
	-I$(srcdir)/lwip/src/include

libstrongswan_kernel_libipsec_la_SOURCES += \
	kernel_libipsec_socks.h kernel_libipsec_socks.c \
	kernel_libipsec_socks_parser.h kernel_libipsec_socks_parser.c \
	kernel_libipsec_lwip_port.h kernel_libipsec_lwip_port.c \
	lwip/src/core/def.c \
	lwip/src/core/dns.c \
	lwip/src/core/inet_chksum.c \
	lwip/src/core/init.c \
	lwip/src/core/ip.c \
	lwip/src/core/mem.c \
	lwip/src/core/memp.c \
	lwip/src/core/netif.c \
	lwip/src/core/pbuf.c \
	lwip/src/core/raw.c \
	lwip/src/core/stats.c \
	lwip/src/core/sys.c \
	lwip/src/core/tcp.c \
	lwip/src/core/tcp_in.c \
	lwip/src/core/tcp_out.c \
	lwip/src/core/timeouts.c \
	lwip/src/core/udp.c \
	lwip/src/core/ipv4/icmp.c \
	lwip/src/core/ipv4/ip4.c \
	lwip/src/core/ipv4/ip4_addr.c \
	lwip/src/core/ipv4/ip4_frag.c \
	lwip/src/core/ipv6/icmp6.c \
	lwip/src/core/ipv6/inet6.c \
	lwip/src/core/ipv6/ip6.c \
	lwip/src/core/ipv6/ip6_addr.c \
	lwip/src/core/ipv6/ip6_frag.c \
	lwip/src/core/ipv6/nd6.c
endif

libstrongswan_kernel_libipsec_la_LIBADD = $(top_builddir)/src/libipsec/libipsec.la

libstrongswan_kernel_libipsec_la_LDFLAGS = -module -avoid-version

EXTRA_DIST = lwip lwip_port
