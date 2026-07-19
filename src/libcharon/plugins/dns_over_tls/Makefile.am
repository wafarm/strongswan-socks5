AM_CPPFLAGS = \
	-I$(top_srcdir)/src/libstrongswan \
	-I$(top_srcdir)/src/libcharon \
	-I$(top_srcdir)/src/libtls

AM_CFLAGS = \
	$(PLUGIN_CFLAGS)

if MONOLITHIC
noinst_LTLIBRARIES = libstrongswan-dns-over-tls.la
else
plugin_LTLIBRARIES = libstrongswan-dns-over-tls.la
libstrongswan_dns_over_tls_la_LIBADD = \
	$(top_builddir)/src/libtls/libtls.la
endif

libstrongswan_dns_over_tls_la_SOURCES = \
	dns_over_tls_plugin.h dns_over_tls_plugin.c \
	dns_over_tls_resolver.h dns_over_tls_resolver.c \
	dns_over_tls_dns.h dns_over_tls_dns.c

libstrongswan_dns_over_tls_la_LDFLAGS = -module -avoid-version
