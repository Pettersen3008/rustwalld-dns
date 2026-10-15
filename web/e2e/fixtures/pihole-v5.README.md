# Synthetic Pi-hole v5 Teleporter fixture

`pihole-v5.tar.gz` uses the ordinary USTAR/gzip layout and JSON table filenames
documented by Pi-hole Web v5.21's Teleporter exporter. It contains public test
data only, a loopback mock resolver and an intentionally excluded password
sentinel. It is not copied from an appliance or from Pi-hole source code.

The fixture includes exact allow/block rules, group associations, a local host
and a CNAME. Downloaded gravity contents are absent, as in the real exporter;
no enabled publisher is configured in this successful-import fixture.
