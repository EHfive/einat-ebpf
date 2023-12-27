# BPF Full Cone Nat

This BPF program implement an "Endpoint-Independent Filtering" UDP NAT(network address translation) behavior cooperating with existing Netfilter masquerade NAT engine to provide "Full Cone" NAT.

## Requirement

-   Linux kernel >= 6.4 (compiled with BPF and BTF support) on target machine
-   `libelf` from elfutils
-   `zlib`
-   `clang` to compile BPF C code

The kernel version requirement would be lifted on demand as the BPF kernel functions(kfuncs) apis we use are unstable and unfinished (e.g. current bpf linked list and red-black tree apis only allows you to model double-ended queue and priority queue).

## Installation

```
cargo install --git https://github.com/EHfive/bpf-full-cone-nat
```

Or use Nix flakes we provide.

```
nix build github:EHfive/bpf-full-cone-nat
```

## Usage

Setup masquerade NAT using nftables or iptables as usual, this will gives you "Endpoint-Independent Mapping" but "Address and Port-Dependent Filtering" NAT.

Example nftables rule that source NAT IP/TCP, IP/UDP, ... packets from `192.168.1.0/24` to eth0, the "external" interface.

```nft
table inet nat {
  chain postrouting {
    type nat hook postrouting priority srcnat; policy accept;
    ip saddr 192.168.1.0/24 oifname eth0 masquerade
  }
}
```

Then just start `bpf-full-cone-nat`, it will monitor SNATs at interface egress and relaxing filtering by add extra Netfilter SNAT conntracks on demand at ingress, i.e. "Endpoint-Independent Filtering". When combined this with "Endpoint-Independent Mapping" that Netfilter already provides, you got so-called "Full Cone" NAT.

```shell
bpf-full-cone-nat --ifname eth0
```

To test if this works, you can use tools below. Notice you could only got "Full Cone NAT" if your external network is already "Full Cone" NAT or is a public IP.

-   [stun-nat-behaviour](https://github.com/pion/stun/tree/master/cmd/stun-nat-behaviour)
-   [go-stun](https://github.com/ccding/go-stun)
-   [NatTypeTester](https://github.com/HMBSbige/NatTypeTester) on Windows

## TODO

-   [ ] Investigate concurrency control in this BPF application
-   [ ] Tagged logging
-   [ ] Refine userland CLI

## Alternatives

-   [netfilter-full-cone-nat](https://github.com/Chion82/netfilter-full-cone-nat)
-   [nft-fullcone](https://github.com/fullcone-nat-nftables)

The project works similarly to these kernel modules but we don't require an extra iptables/nftables extension code in userland, hence hugely simplifies the deployment. And the tool needs you no change to existing NAT iptables/nftables rules but just turns "Address and Port-Dependent Filtering" to "Endpoint-Independent Filtering".

## Recommended Reading

-   How NAT traversal works, by David Anderson <https://tailscale.com/blog/how-nat-traversal-works>
-   RFC 4787, Network Address Translation (NAT) Behavioral Requirements for Unicast UDP, <https://datatracker.ietf.org/doc/html/rfc4787>
-   从 DNAT 到 netfilter 内核子系统，浅谈 Linux 的 Full Cone NAT 实现, by @Chion82 <https://blog.chionlab.moe/2018/02/09/full-cone-nat-with-linux/>
