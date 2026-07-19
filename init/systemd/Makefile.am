
EXTRA_DIST = strongswan.service.in \
	strongswan-socks-portable@.service \
	strongswan-socks-portable-user@.service
CLEANFILES = strongswan.service

systemdsystemunit_DATA = strongswan.service

strongswan.service : strongswan.service.in
	$(AM_V_GEN) \
	sed \
	-e "s:@SBINDIR@:$(sbindir):" \
	$(srcdir)/$@.in > $@
