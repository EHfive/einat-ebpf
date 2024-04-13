# Changelog

All notable changes to this project will be documented in this file.

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
