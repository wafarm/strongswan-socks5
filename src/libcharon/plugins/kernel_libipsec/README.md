# Portable kernel-libipsec SOCKS5 runtime

`--enable-kernel-libipsec-socks-portable` builds a relocatable POSIX runtime
profile for the kernel-libipsec SOCKS5 data plane.  It enables
`kernel-libipsec-socks`, `charon`, `swanctl`, and VICI (and the existing
kernel-libipsec dependencies).  Explicitly disabling any of these components is
a configuration error.  The profile is not supported for Windows targets.

The profile does not select static or monolithic linking and does not change
plugin installation.  Use the existing build options and packaging appropriate
for the target system.

## Runtime layout

Deploy `charon` and `swanctl` together with their configuration files:

```text
bundle/
├── charon
├── swanctl
├── strongswan.conf
├── swanctl.conf
├── x509/
├── x509ca/
├── x509aa/
├── x509ocsp/
├── x509crl/
├── x509ac/
├── pubkey/
├── private/
├── rsa/
├── ecdsa/
├── pkcs8/
└── pkcs12/
```

Only credential directories that are actually used have to exist.  At runtime,
`charon.pid` and `charon.vici` are created beside the executables and removed
during normal shutdown.

Both programs resolve symbolic links and switch to the physical executable's
directory before initialization.  Consequently they work when launched from an
unrelated working directory, via a relative path, or via `PATH`.  A symlink in a
different directory does not relocate the configuration; the physical binary's
directory is used.

The adjacent defaults can be replaced as usual:

- `STRONGSWAN_CONF` selects another `strongswan.conf`.
- `SWANCTL_DIR` selects another swanctl configuration and credential base.
- swanctl `--file` selects another `swanctl.conf`.
- swanctl `--uri` selects another VICI service.

Relative override paths and relative UNIX socket URIs are resolved from the
application directory.

## Profile defaults

Unless set explicitly in `strongswan.conf`, the profile uses:

```text
charon.plugins.kernel-libipsec.data_plane = socks5
charon.install_routes = no
charon.install_virtual_ip = no
charon.port = 0
charon.port_nat_t = 0
charon.plugins.vici.socket = unix://charon.vici
```

These are defaults, not enforced values.  Explicit configuration continues to
take precedence.

For a build whose compiled plugin lists contain everything it needs, a minimal
non-modular `strongswan.conf` is:

```text
charon {
	load_modular = no
}
```

This avoids filesystem includes and lets `charon` use the plugin list compiled
by the selected build options.  The stock `strongswan.conf` uses modular
includes such as `strongswan.d/charon/*.conf`; if that file is deployed instead,
the referenced `strongswan.d` hierarchy must accompany the executables.
