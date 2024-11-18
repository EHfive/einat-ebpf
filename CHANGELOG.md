# Changelog

All notable changes to this project will be documented in this file.

## [0.1.3] - 2024-11-19

### Highlights

-   Use pure-rust Aya loader by default, einat now has zero native dependency except libc on target platform.
    This should make einat be built more easily especially for cross-compilation.
-   Allow attaching eBPF programs with new TCX interface, aya loader only.
-   Fix a bug that might cause silent packet drop, which has been observed on PPPoE interface for large packets.

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
