# Changelog

All notable changes to this project will be documented in this file.

## [0.1.6] - 2025-02-22

### Highlights

-   Fixed hairpinning, it was broken since v0.1.3..
-   `bpf_fib_lookup_external` now respect `ip rule` selectors `ipproto`, `sport`, `dport` and `fwmark` in addition to previously working `from`, `to` and `oif`.
    This is useful for balancing traffic to multiple external source addresses in a static manner, see <https://github.com/EHfive/einat-ebpf/discussions/26>.

### 🚀 Features

-   Add features info to cli version info
-   _(bpf)_ Lookup external source address with fwmark if possible
-   _(bpf)_ Fib lookup route with layer 4 ports passed

### 🐛 Bug Fixes

-   Fix setting of hairpinning flag and route table

### Improve

-   Hide developer facing option --bpf-log from the help message
-   _(bpf)_ Update the bpf log tag to [einat]
-   Avoid converting OsString to String for config file path
-   Explicitly specify encap type for IP tunnel link types

## [0.1.5] - 2024-12-09

### 🐛 Bug Fixes

-   Prevent pkg_config from emitting Cargo linking instructions
-   Fix CLI arg --internal not being applied

### Improve

-   Re-enable libbpf logging
-   TCX attach before all other links
-   Prefix match binding & ct addresses with external network CIDR
-   _(build)_ Error out if build commands not exit with success
-   Allow using bpftool for stripping

## [0.1.4] - 2024-11-20

This is a hotfix addressing build error on Rust 1.80 on which is the minimal version that einat requires to build.

### 🐛 Bug Fixes

-   Elided lifetimes in associated constant

### 🧪 Testing

-   Add tests for einat skel

## [0.1.3] - 2024-11-19

### Highlights

-   Fix a bug that might cause silent packet drop, which has been observed on PPPoE interface for large packets.
-   Use pure-rust Aya loader by default, einat now has zero native dependency except libc on target platform.
    This should make einat be built more easily especially for cross-compilation.
-   Allow attaching eBPF programs with new TCX interface, aya loader only.
-   Allow do SNAT for specified internal network only

```bash
# do SNAT for internal packets with source of 192.168.1.0/24 only
einat -i extern0 --hairpin-if intern0 lo --internal 192.168.1.0/24
```

### 🚀 Features

-   Add pure-Rust aya loading backend support
-   Add config option to toggle TCX interface usage
-   Allow do NAT for specified internal network only
-   Add CLI options for snat_internals and bpf_loader

### 🐛 Bug Fixes

-   Workaround an unroll failure
-   _(ebpf)_ Always pull first header bytes
-   Split EINAT_BPF_CFLAGS args

### Improve

-   Increase log level of libbpf netlink error to DEBUG
-   Describe NAT44 enabling more specifically
-   Log eBPF loader used
-   Enable bpf_fib_lookup_external by default on kernel>=6.7

## [0.1.2] - 2024-04-13

### 🚀 Features

-   Implement interface monitoring and dynamic attaching
-   Add CLI option to print einat version

### 🐛 Bug Fixes

-   Filter out link address of all zero
-   Fix checksums calculation of IPv6 packets
-   Passthrough unsupported types of IPv6 packet

### Improve

-   Change the default UDP/ICMP timeout to 2 mins
-   [**breaking**] Disallow user supplied if_index

## [0.1.1] - 2024-04-07

### 🚀 Features

-   Add more CLI options

### 🐛 Bug Fixes

-   Guard against division by zero in libbpf-rs
-   Do not use unspecified IP address as external address
-   Fix port range merging algorithm
-   Prefer local address over prefix address

## [0.1.0] - 2024-04-05

Initial release.
