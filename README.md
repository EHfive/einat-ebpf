# eBPF-based Endpoint-Independent NAT

This eBPF application implements an "Endpoint-Independent Mapping" and "Endpoint-Independent Filtering" NAT(network address translation) on TC egress and ingress hooks.

### Features

-   **eBPF**: IPv4 to IPv4 NAPT(Network Address Port Translation)
-   **eBPF**: IPv6 to IPv6 NAPT
-   **eBPF**: Endpoint-Independent(Full Cone) NAT for TCP, UDP and ICMP
-   **eBPF**: Partial port-range usage, allows reserving external ports for other usage
-   **Frontend**: Automatic reconfiguration on interface address changes
-   **Frontend**: Automatic hairpin IP rule and route setup, see https://github.com/EHfive/einat-ebpf/issues/4

## Requirement

-   Linux kernel >= 5.15 (compiled with BPF and BTF support) on target machine
-   `libelf` from elfutils
-   `zlib`
-   `clang` to compile BPF C code
-   `cargo` and `rustfmt` for building

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

See also [cross-compilation guide](./docs/guide/cross.md) for cross-compilation on Debian/Debian-based distros.

## Usage

```
einat - An eBPF-based Endpoint-Independent NAT

USAGE:
  einat [OPTIONS]

OPTIONS:
  -h, --help                   Print this message
  -c, --config <file>          Path to configuration file
  -i, --ifname                 External network interface name, e.g. eth0
      --ifindex                External network interface index number, e.g. 2
      --nat44                  Enable NAT44/NAPT44 for specified network interface
      --nat66                  Enable NAT66/NAPT66 for specified network interface
      --ports <range> ...      External TCP/UDP port ranges, defaults to 20000-29999
      --hairpin-if <name> ...  Hairpin internal network interface names, e.g. lo, lan0
      --bpf-log <level>        BPF tracing log level, 0 to 5, defaults to 0, disabled
```

You would only need to specify external interface name in a minimal setup, and `einat` would select an external IP address on specified interface and reconfigures automatically.

```shell
# Enable IP forwarding if not already
sudo sysctl net.ipv4.ip_forward=1
# With simplified CLI options,
# this setup NAT for traffic forwarding to and from wan0 and setup hairpin
# routing for traffic forwarding from lo and lan0 to wan0
sudo einat --ifname wan0 --hairpin-if lo lan0
# With config file
sudo einat --config /path/to/config.toml
```

See [config.sample.toml](./config.sample.toml) for more configuration options. This program requires `cap_sys_admin` for passing eBPF verification and `cap_net_admin` for attaching eBPF program to TC hooks on network interface. Also make sure nftables/iptables masquerading rule is not set.

To test if this works, you can use tools below on internal network behind NAT. Notice you could only got "Full Cone" NAT if your external network is already "Full Cone" NAT or has a public IP.

-   `stunclient` from [stuntman](https://github.com/jselbie/stunserver)
-   [stun-nat-behaviour](https://github.com/pion/stun/tree/master/cmd/stun-nat-behaviour)
-   [go-stun](https://github.com/ccding/go-stun)
-   [NatTypeTester](https://github.com/HMBSbige/NatTypeTester) on Windows

## Alternatives

-   [netfilter-full-cone-nat](https://github.com/Chion82/netfilter-full-cone-nat)
-   [nft-fullcone](https://github.com/fullcone-nat-nftables)

Instead of relying on existing Netfilter conntrack system like these out-of-tree kernel modules did, we implement a fully functional Endpoint Independent NAT engine on eBPF TC hook from scratch thus avoiding hassles dealing with "Address and Port-Dependent" Netfilter conntrack system and being slim and efficient.

And our application enjoys libbpf's CO-RE(Compile Once – Run Everywhere) capabilities that hugely simplifies distribution and deployment.

## Recommended Reading

-   How NAT traversal works, by David Anderson <https://tailscale.com/blog/how-nat-traversal-works>
-   RFC 4787, Network Address Translation (NAT) Behavioral Requirements for Unicast UDP, <https://datatracker.ietf.org/doc/html/rfc4787>

## COPYING

Sources under ./src/bpf/kernel are derived from Linux kernel, hence they are GPL-2.0-only licensed.
For other files under this project, unless specified, they are GPL-2.0-or-later licensed.

Notice our BPF program calls into GPL-licensed kernel functions so you need to choose GPL-2.0-only license to distribute it.
