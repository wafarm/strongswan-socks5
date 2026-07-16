TESTS = kernel_libipsec_socks_tests

check_PROGRAMS = $(TESTS)

kernel_libipsec_socks_tests_SOURCES = \
	tests.h tests.c \
	suites/test_socks_parser.c \
	../kernel_libipsec_socks_parser.c

kernel_libipsec_socks_tests_CFLAGS = \
	-I$(top_srcdir)/src/libstrongswan \
	-I$(top_srcdir)/src/libstrongswan/tests \
	-I$(top_srcdir)/src/libcharon \
	-I$(top_srcdir)/src/libcharon/plugins/kernel_libipsec \
	@COVERAGE_CFLAGS@

kernel_libipsec_socks_tests_LDFLAGS = @COVERAGE_LDFLAGS@
kernel_libipsec_socks_tests_LDADD = \
	$(top_builddir)/src/libstrongswan/tests/libtest.la \
	$(top_builddir)/src/libstrongswan/libstrongswan.la
