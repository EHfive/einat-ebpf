# einat

einat is an eBPF-based Endpoint-Independent NAT(Network Address Translation).

The eBPF part of einat implements an "Endpoint-Independent Mapping" and "Endpoint-Independent Filtering" NAT on TC egress and ingress hooks.

### Features

-   **eBPF**: IPv4 to IPv4 NAPT(Network Address Port Translation)
-   **eBPF**: IPv6 to IPv6 NAPT
-   **eBPF**: Endpoint-Independent(Full Cone) NAT for TCP, UDP and ICMP
-   **eBPF**: Partial external port range usage, allows reserving external ports for other usage
-   **Frontend**: Automatic reconfiguration on interface address changes
-   **Frontend**: Automatic IP rule and route setup for hairpinning, see https://github.com/EHfive/einat-ebpf/issues/4

See example [use cases](./docs/guide/use-case.md) for what can be achieved with EIM + EIF and other features `einat` provides.

For implementation details, see documentations under [reference](./docs/reference/).

## Requirement

-   Linux kernel >= 5.15 (compiled with BPF and BTF support) on target machine
-   Rust toolchain (`cargo` etc.)
-   `clang` for compiling BPF C code
-   `libbpf` headers
-   (optional) `pkg-config` to locate `libbpf` headers
-   `llvm-strip` for stripping compiled BPF object

Additional dependencies for `"libbpf"` loader:

-   `rustfmt` for formatting generated code
-   `clang` libs for bindgen
-   `libelf` from elfutils and  `zlib` on target platform

Currently we support `"aya"`, `"libbpf"` and `"libbpf-skel"` eBPF loaders, only the `"aya"` is enabled by default as it requires no native dependencies on target platform except libc.

The `"libbpf-skel"` loader is served as reference purpose and you should just use `aya` or `libbpf` instead.

It's also required the eBPF JIT implementation for target architecture in kernel has implemented support for BPF-to-BPF calls, which is not the case for MIPS and other architectures have less interests. This application is only tested to work on x86-64 or aarch64.

See also [OpenWrt guide](./docs/guide/openwrt.md) for pitfalls running this on OpenWrt.

## Installation

```shell
cargo install --git https://github.com/EHfive/einat-ebpf.git
```

You can also enable IPv6 NAT66 feature with `--features ipv6` flag, however it would increase load time of eBPF programs to about 4 times.

Or build static binaries with Nix flakes we provide, run `nix flake show` to list all available packages.

```shell
nix build "github:EHfive/einat-ebpf#static-x86_64-unknown-linux-musl"
nix build "github:EHfive/einat-ebpf#ipv6-static-x86_64-unknown-linux-musl"
# Cross compile for aarch64
nix build "github:EHfive/einat-ebpf#static-aarch64-unknown-linux-musl"
```

For NixOS, you can use module [`github:EHfive/einat-ebpf#nixosModules.default`](./nix/module.nix).

For OpenWrt, there are [openwrt-einat-ebpf](https://github.com/muink/openwrt-einat-ebpf) and [luci-app-einat](https://github.com/muink/luci-app-einat) by @muink.

See also [cross-compilation guide](./docs/guide/cross-aya.md) for cross-compilation on Debian/Debian-based distros.

### Build Environment Variables

| Name                   | Example Value              | Note                                            |
| ---------------------- | -------------------------- | ----------------------------------------------- |
| `EINAT_BPF_CFLAGS`     | `-I/usr/include/<triplet>` | Specify extra CFLAGS for BPF object compilation |
| `LIBBPF_NO_PKG_CONFIG` | `1`                        | Disable [pkg_config lookup] of libbpf.          |

[pkg_config lookup]: (https://docs.rs/pkg-config/0.3.31/pkg_config/index.html#environment-variables)

You can combine `LIBBPF_NO_PKG_CONFIG` and `EINAT_BPF_CFLAGS` to specify include flag of libbpf headers manually.

See also [build.rs](./build.rs) for reference.

## Usage

```
einat - An eBPF-based Endpoint-Independent NAT

USAGE:
  einat [OPTIONS]

OPTIONS:
  -h, --help                   Print this message
  -c, --config <file>          Path to configuration file
  -i, --ifname <name>          External network interface name, e.g. eth0
      --nat44                  Enable NAT44/NAPT44 for specified network interface, enabled by
                               default if neither --nat44 nor --nat66 are specified
      --nat66                  Enable NAT66/NAPT66 for specified network interface
      --ports <range> ...      External TCP/UDP port ranges, defaults to 20000-29999
      --hairpin-if <name> ...  Hairpin internal network interface names, e.g. lo, lan0
      --internal <CIDR> ...    Perform source NAT for these internal networks only
      --bpf-log <level>        BPF tracing log level, 0 to 5, defaults to 0, disabled
      --bpf-loader <loader>    BPF loading backend used, one of aya or libbpf
  -v, --version                Print einat version
```

You would only need to specify external interface name in a minimal setup, and `einat` would select an external IP address on specified interface and reconfigures automatically.

```shell
# Enable IP forwarding if not already
sudo sysctl net.ipv4.ip_forward=1
# With simplified CLI options,
# this setup NAT for traffic forwarding to and from wan0 and setup hairpin
# routing for traffic forwarding from lo or lan0 to wan0
sudo einat --ifname wan0 --hairpin-if lo lan0
# With config file
sudo einat --config /path/to/config.toml
```

See [config.sample.toml](./config.sample.toml) for more configuration options. This program requires `cap_sys_admin` for passing eBPF verification and `cap_net_admin` for attaching eBPF program to TC hooks on network interface.

Also make sure nftables/iptables masquerading rule is not set and forwarding of inbound traffic from external interface to internal interfaces for port ranges `einat` uses is allowed.

If you attach einat to tunnel interfaces(e.g. PPPoE, WireGuard) with MTU less than 1500 bytes,
you might also want to setup [TCP MSS clamping] in case there is ICMP black hole which prevent PMTUD(Path MTU Discovery) from functioning on either internal or remote side,
see <https://github.com/EHfive/einat-ebpf/issues/19>. Though this only works for TCP.

[TCP MSS clamping]: https://wiki.nftables.org/wiki-nftables/index.php/Mangling_packet_headers#Mangling_TCP_options

To test if this works, you can use tools below on internal network behind NAT. Notice you could only got "Full Cone" NAT if your external network is already "Full Cone" NAT or has a public IP.

-   `stunclient` from [stuntman](https://github.com/jselbie/stunserver)
-   [stun-nat-behaviour](https://github.com/pion/stun/tree/master/cmd/stun-nat-behaviour)
-   [go-stun](https://github.com/ccding/go-stun)
-   [NatTypeTester](https://github.com/HMBSbige/NatTypeTester) on Windows

## Alternatives

-   [netfilter-full-cone-nat](https://github.com/Chion82/netfilter-full-cone-nat)
-   [nft-fullcone](https://github.com/fullcone-nat-nftables)

Instead of relying on existing Netfilter conntrack system like these out-of-tree kernel modules did, we implement a fully functional Endpoint Independent NAT engine on eBPF TC hook from scratch thus avoiding hassles dealing with "Address and Port-Dependent" Netfilter conntrack system and being slim and efficient.

And `einat` utilizes libbpf's CO-RE(Compile Once – Run Everywhere) capabilities that hugely simplifies distribution and deployment.

## Recommended Reading

-   How NAT traversal works, by David Anderson <https://tailscale.com/blog/how-nat-traversal-works>
-   RFC 4787, Network Address Translation (NAT) Behavioral Requirements for Unicast UDP, <https://datatracker.ietf.org/doc/html/rfc4787>
-   [Chinese] einat-ebpf，用 eBPF 从头写一个 Full Cone NAT, <https://eh5.me/zh-cn/blog/einat-introduction/>

## COPYING

Sources under ./src/bpf/kernel are derived from Linux kernel, hence they are GPL-2.0-only licensed.
For other files under this project, unless specified, they are GPL-2.0-or-later licensed.

Notice our BPF program calls into GPL-licensed kernel functions so you need to choose GPL-2.0-only license to distribute it.
