---
name: Bug report
about: Create a report to help us improve
title: ""
labels: ""
assignees: ""
---

<!-- [en] Please use English language, you may use machine translation here. -->
<!-- [zh] 请使用英语，可以使用翻译软件 -->

**Describe the bug**
A clear and concise description of what the bug is.

**Expected behavior**
A clear and concise description of what you expected to happen.

**Configuration**
Command-line options:

```
einat <args>
```

Configuration file:

```toml
# content of einat configuration file
```

**Target Machine (please complete the following information):**

-   Architecture: [e.g. x86-64, aarch64]
-   Linux distribution and version: [e.g. Arch Linux (rolling), OpenWrt (v23.05.5)]
-   Kernel version: [e.g. 5.15, 6.7.1]
-   einat version: [e.g. 0.1.1]

**Additional context**
Add any other context about the problem here, e.g. network interface information, firewall(iptables/nftables) configuration.
And connection test results of `nslookup aliyun.com 223.5.5.5`, `traceroute -T 223.5.5.5`, `ping -M do -s 1464 223.5.5.5`, etc. .

Please elaborate what you have changed in detail for unchecked options below.

-   [ ] I have read **README** and notes in **config.sample.toml**.
-   [ ] I don't have any (hardware) offload/acceleration solutions enabled.
-   [ ] I have a clean firewall or with only firewall rule of TCP MSS Clamping.
-   [ ] I don't have any special/advanced routing rules other than the basic default routing.
