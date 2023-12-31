# BPF Full Cone NAT

This eBPF application implements an "Endpoint-Independent Filtering" UDP NAT(network address translation) behavior cooperating with existing Netfilter masquerade NAT engine to provide "Full Cone" NAT. It also supports operating in "Address-Dependent Filtering" mode.

## Requirement

-   Linux kernel >= 6.4 (compiled with BPF and BTF support) on target machine
-   `libelf` from elfutils
-   `zlib`
-   `clang` to compile BPF C code
-   `cargo` and `rustfmt` for building

The kernel version requirement would be lifted on demand as the BPF kernel functions(kfuncs) apis we use are unstable and unfinished (e.g. current bpf linked list and red-black tree apis only allows you to model double-ended queue and priority queue).

## Installation

```shell
cargo install --git https://github.com/EHfive/bpf-full-cone-nat
```

Or use Nix flakes we provide.

```shell
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

Then just start `bpf-full-cone-nat`, it will monitor SNATs at interface egress and relaxing filtering by adding extra Netfilter SNAT conntracks on demand at ingress, i.e. "Endpoint-Independent Filtering". When combined this with "Endpoint-Independent Mapping" that Netfilter already provides, you got so-called "Full Cone" NAT.

```shell
# You might need to `modprobe nf_nat` first
# if you run this before applying nftables/iptables masquerade rules
sudo bpf-full-cone-nat --ifname eth0
```

You can also set the program to operates in "Address-Dependent Filtering" mode with `-m/--mode` flag, e.g. `bpf-full-cone-nat --ifname eth0 --mode 2`.

To test if this works, you can use tools below on internal network behind NAT. Notice you could only got "Full Cone NAT" if your external network is already "Full Cone" NAT or is a public IP.

-   `stunclient` from [stuntman](https://github.com/jselbie/stunserver)
-   [stun-nat-behaviour](https://github.com/pion/stun/tree/master/cmd/stun-nat-behaviour)
-   [go-stun](https://github.com/ccding/go-stun)
-   [NatTypeTester](https://github.com/HMBSbige/NatTypeTester) on Windows

## TODO

-   [x] Investigate concurrency control in this BPF application. (**Solution**: Use atomic based spin-lock to sync mapping operations)
-   [ ] Tagged logging
-   [ ] Refine userland CLI
-   [ ] Add end-to-end tests and CI

## Known Issue

-   SNAT conntracks added by BPF program would not be immediately removed if attached network interface reconfigures (e.g. changes the IP address), they will only timing out. There is indeed an extra conntrack nat extension field `masq_index` handling this case, but it's not accessible from BPF program.
-   -   **Workaround**: We have added a userland [netlink](https://man7.org/linux/man-pages/man7/netlink.7.html) monitor to cleanup obsolete conntracks when interface goes down, which I think is fine as it's not as timing sensitive as live packet filtering.

## Alternatives

-   [netfilter-full-cone-nat](https://github.com/Chion82/netfilter-full-cone-nat)
-   [nft-fullcone](https://github.com/fullcone-nat-nftables)

The project works similarly to these kernel modules, but we don't require compiling out-of-tree kernel module for specific kernel version or applying an extra out-of-tree iptables/nftables extension patch in userland, hence hugely simplifies the deployment. And the tool needs you no change to existing NAT iptables/nftables rules but just turns "Address and Port-Dependent Filtering" to "Endpoint-Independent Filtering".

## Recommended Reading

-   How NAT traversal works, by David Anderson <https://tailscale.com/blog/how-nat-traversal-works>
-   RFC 4787, Network Address Translation (NAT) Behavioral Requirements for Unicast UDP, <https://datatracker.ietf.org/doc/html/rfc4787>
-   从 DNAT 到 netfilter 内核子系统，浅谈 Linux 的 Full Cone NAT 实现, by @Chion82 <https://blog.chionlab.moe/2018/02/09/full-cone-nat-with-linux/>

## COPYING

Sources under ./src/bpf/kernel are derived from Linux kernel, hence they are GPL-2.0-only licensed.
For other files under this project, unless specified, they are GPL-2.0-or-later licensed.

Notice our BPF program calls into GPL-licensed kernel functions so you need to choose GPL-2.0-only license to distribute it.
