# Portable kernel-libipsec SOCKS5 runtime

`--enable-kernel-libipsec-socks-portable` builds a relocatable POSIX runtime
profile for the kernel-libipsec SOCKS5 data plane.  It enables
`kernel-libipsec-socks`, `charon`, `swanctl`, VICI, and the `dns-over-tls`
gateway resolver (and the existing kernel-libipsec dependencies).  Explicitly
disabling any of these components is a configuration error.  The profile is
also built in the MSYS2 environment on Windows.

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

## systemd

The `strongswan-socks-portable@.service` template starts a bundle at any
absolute path, waits for its adjacent VICI socket, and loads its
`swanctl.conf`.  Install and start it with:

```sh
sudo install -m 0644 init/systemd/strongswan-socks-portable@.service \
    /etc/systemd/system/

BUNDLE=/opt/strongswan-socks
UNIT=$(systemd-escape --path \
    --template=strongswan-socks-portable@.service "$BUNDLE")

sudo systemctl daemon-reload
sudo systemctl enable --now "$UNIT"
```

Use `systemctl reload "$UNIT"` to reload `strongswan.conf`, connections, and
credentials.  To initiate a connection automatically when the service starts,
set `start_action = start` in its child configuration in `swanctl.conf`.

### User service

The SOCKS5 data plane can run without elevated capabilities when the portable
defaults are retained: it uses unprivileged IKE ports, UDP-encapsulated ESP,
does not create a TUN device, and does not install addresses or routes.  Put the
bundle in a directory owned and writable by the user because `charon.pid` and
`charon.vici` are created in it.  Then install the user-service variant:

```sh
install -d -m 0755 "$HOME/.config/systemd/user"
install -m 0644 init/systemd/strongswan-socks-portable-user@.service \
    "$HOME/.config/systemd/user/"

BUNDLE="$HOME/.local/lib/strongswan-socks"
UNIT=$(systemd-escape --path \
    --template=strongswan-socks-portable-user@.service "$BUNDLE")

systemctl --user daemon-reload
systemctl --user enable --now "$UNIT"
```

Inspect it with `systemctl --user status "$UNIT"` and
`journalctl --user-unit="$UNIT" -f`.  A user manager normally stops after the
last login session ends.  To start the service at boot and keep it running
after logout, enable lingering with `sudo loginctl enable-linger "$USER"`.

Do not override `charon.port` or `charon.port_nat_t` with privileged ports and
do not enable `charon.plugins.kernel-libipsec.raw_esp` in a user service.  Stop
any system-scope instance that listens on the same SOCKS5 address (port 1080 by
default), or configure distinct listener ports.
