TESTS = dns_over_tls_tests

check_PROGRAMS = $(TESTS)

dns_over_tls_tests_SOURCES = \
	tests.h tests.c \
	suites/test_endpoint.c \
	suites/test_dns.c \
	suites/test_transport.c

dns_over_tls_tests_CFLAGS = \
	-I$(top_srcdir)/src/libstrongswan \
	-I$(top_srcdir)/src/libstrongswan/tests \
	-I$(top_srcdir)/src/libcharon \
	-I$(top_srcdir)/src/libtls \
	-I$(top_srcdir)/src/libcharon/plugins/dns_over_tls \
	-DPLUGINDIR=\""$(abs_top_builddir)/src/libstrongswan/plugins\"" \
	-DPLUGINS=\""${s_plugins}\"" \
	-DDOT_TEST_CRED_DIR=\""$(abs_top_srcdir)/testing/tests/ikev2/rw-eap-tls-fragments/hosts/moon/etc/swanctl\"" \
	@COVERAGE_CFLAGS@

dns_over_tls_tests_LDFLAGS = @COVERAGE_LDFLAGS@
dns_over_tls_tests_LDADD = \
	../libstrongswan-dns-over-tls.la \
	$(top_builddir)/src/libcharon/libcharon.la \
	$(top_builddir)/src/libtls/libtls.la \
	$(top_builddir)/src/libstrongswan/tests/libtest.la \
	$(top_builddir)/src/libstrongswan/libstrongswan.la
