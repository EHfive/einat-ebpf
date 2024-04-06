## OpenWrt

As said in [README](../../README.md), `einat` requires a kernel with BPF and BTF support enabled which is not the default.
And `einat` requires running kernel for target architecture has support for BPF-to-BPF calls, which is not the case for MIPS and other older architectures.

So if the architecture of your router is not x86-64 or aarch64 or other actively maintained architecture in kernel, your router would mostly not be able to run `einat`.

### Build Configs

Make sure to use latest OpenWrt release or OpenWrt on main branch.

```
CONFIG_KERNEL_DEBUG_KERNEL=y
CONFIG_KERNEL_DEBUG_INFO=y
CONFIG_KERNEL_DEBUG_INFO_REDUCED=n
CONFIG_KERNEL_DEBUG_INFO_BTF=y
```

These translate to kernel configs below

```
CONFIG_DEBUG_KERNEL=y
CONFIG_DEBUG_INFO=y
CONFIG_DEBUG_INFO_REDUCED=n
CONFIG_DEBUG_INFO_BTF=y
```

### Kernel Configs

Additionally kernel configs required, you might need to add these to kernel config file manually, see https://openwrt.org/docs/guide-developer/toolchain/use-buildsystem#kernel_configuration_optional .

```
CONFIG_BPF_SYSCALL=y
CONFIG_BPF_JIT=y
CONFIG_NET_CLS_BPF=y
CONFIG_NET_ACT_BPF=y
```

See https://github.com/iovisor/bcc/blob/master/docs/kernel_config.md for explanation on these BPF options.

### NAT setup

Find out interface names for your router with `ip addr`, it would be `pppoe-wan` or `wan` for external interface and `br-lan` for internal interface in a common OpenWrt setup.

Download pre-built binaries for x86_64 or aarch64 from [release page](https://github.com/EHfive/einat-ebpf/releases/latest) or [actions snapshot build](https://github.com/EHfive/einat-ebpf/actions/workflows/build.yml).

```shell
# Download build for aarch64
wget -O einat https://github.com/EHfive/einat-ebpf/releases/latest/download/einat-static-aarch64-unknown-linux-musl
chmod +x einat

# replace pppoe-wan with wan if you are not using PPPoE
einat -i pppoe-wan --hairpin-if lo br-lan
```

You would also need to disable IP masquerading for WAN firewall zone, it can be done in Luci - Firewall page.

If this works, you can add a init script to run `einat` as a service, see https://openwrt.org/docs/techref/initscripts.
