> [!CAUTION]
> This application is currently under heavy development, do not use in production.

# eBPF Full Cone NAT

This eBPF application implements an "Endpoint-Independent Mapping" and "Endpoint-Independent Filtering" NAT(network address translation).

## Requirement

-   Linux kernel >= 5.15 (compiled with BPF and BTF support) on target machine
-   `libelf` from elfutils
-   `zlib`
-   `clang` to compile BPF C code
-   `cargo` and `rustfmt` for building

## Installation

```shell
cargo install --git https://github.com/EHfive/bpf-full-cone-nat
```

Or use Nix flakes we provide.

```shell
nix build github:EHfive/bpf-full-cone-nat
```

## Usage

The interface address monitoring is not implemented yet, currently you need to specify IP address of the interface statically with `--external-ip` flag.

```shell
sudo bpf-full-cone-nat --ifname eth0 --external-ip x.x.x.x
```

Currently only IPv4 UDP/ICMP SNAT are implemented, you would need to setup masquerading for TCP using iptables/nftables as well. And the UDP port mapping range is also hard coded to `20000-23999` and `25000-29999` for testing purpose.

```nft
table ip nat {
  chain postrouting {
    type nat hook postrouting priority srcnat; policy accept;
    meta l4proto tcp oifname eth0 masquerade
  }
}
```

View BPF tracing logs with

```shell
cat /sys/kernel/debug/tracing/trace_pipe
```

To test if this works, you can use tools below on internal network behind NAT. Notice you could only got "Full Cone" NAT if your external network is already "Full Cone" NAT or has a public IP.

-   `stunclient` from [stuntman](https://github.com/jselbie/stunserver)
-   [stun-nat-behaviour](https://github.com/pion/stun/tree/master/cmd/stun-nat-behaviour)
-   [go-stun](https://github.com/ccding/go-stun)
-   [NatTypeTester](https://github.com/HMBSbige/NatTypeTester) on Windows

## Alternatives

-   [netfilter-full-cone-nat](https://github.com/Chion82/netfilter-full-cone-nat)
-   [nft-fullcone](https://github.com/fullcone-nat-nftables)

Instead of relying on existing Netfilter conntrack system like these programs did, we implement a fully functional Endpoint Independent NAT engine on eBPF TC hook from scratch thus avoiding hassles dealing with "Address and Port-Dependent" Netfilter conntrack system and being slim and efficient.

## Recommended Reading

-   How NAT traversal works, by David Anderson <https://tailscale.com/blog/how-nat-traversal-works>
-   RFC 4787, Network Address Translation (NAT) Behavioral Requirements for Unicast UDP, <https://datatracker.ietf.org/doc/html/rfc4787>

## COPYING

Sources under ./src/bpf/kernel are derived from Linux kernel, hence they are GPL-2.0-only licensed.
For other files under this project, unless specified, they are GPL-2.0-or-later licensed.

Notice our BPF program calls into GPL-licensed kernel functions so you need to choose GPL-2.0-only license to distribute it.
