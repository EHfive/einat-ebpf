# Use Cases

The following use cases assume:

-   A Linux network setup with loopback interface `lo`, an internal network interface `lan` and an external network interface `wan` on router.
-   An EIM + EIF(Full Cone) external network (like an EIM + EIF CGNAT) or a external network with public IPv4 address on `wan`.
-   The firewall is not blocking traffic of interfaces or ports that `einat` interacts.
-   `einat` NAPT44 is setup on `wan` and have hairpin routing setup for traffic from `lo` and `lan`, i.e. `einat -i wan --hairpin-if lo lan`.

And we give the following example network configuration:

| Host     | interface | network          | address         | note                         |
| -------- | --------- | ---------------- | --------------- | ---------------------------- |
| Router   | `wan`     | `233.252.0.0/24` | `233.252.0.200` | Have default route setup     |
| Router   | `lan`     | `192.168.1.1/24` | `192.168.1.1`   | Forwarding to lo or wan      |
| Device 1 | `eth0`    | `192.168.1.1/24` | `192.168.1.100` | Connected with lan on router |
|          |           |                  | `192.168.1.200` | Secondary address            |

We call the address of `wan`(`233.252.0.200` here) on router as "external address".

## STUN NAT behavior test

Install [stuntman](https://github.com/jselbie/stunserver) which contains `stunclient` and `stunserver`.

Test NAT behavior on device 1:

```shell
$ stunclient stunserver.stunprotocol.org --mode full --verbosity 1 --protocol udp --localaddr 192.168.1.100 --localport 20000
# or test for TCP
$ stunclient stunserver.stunprotocol.org --mode full --verbosity 1 --protocol tcp --localport 192.168.1.200 --localport 20000
```

It should gives

```
Local address: 192.168.1.100:20000
Mapped address: 233.252.0.200:20000
Behavior test: success
Nat behavior: Endpoint Independent Mapping
Filtering test: success
Nat filtering: Endpoint Independent Filtering
```

Also if you perform NAT behavior test with the same local source port but from a different address in a short gap, the result should also be EIM + EIF and the resulting external port should not be the same with previous test. Otherwise, for a network setup with `einat` behind an external NAT, the external NAT has a fake EIM behavior.

```shell
$ stunclient stunserver.stunprotocol.org --mode full --verbosity 1 --protocol udp --localaddr 192.168.1.200 --localport 20000
Local address: 192.168.1.200:20000
Mapped address: 233.252.0.200:[20001] <- this should changes
Behavior test: success
Nat behavior: Endpoint Independent Mapping
Filtering test: success
Nat filtering: Endpoint Independent Filtering
```

## STUN-based port mapping with Natter

[Natter](https://github.com/MikeWang000000/Natter) is a STUN-based port mapping daemon, you can use this tool to hold an external TCP/UDP port and forwarding the traffic to a specified target(e.g. a local TCP listening service).

Run Natter on device 1 with test forwarder.

```shell
$ python natter.py -b 20000 -m test
[I] Natter v2.0.0
[I]
[I] tcp://192.168.1.100:20000 <--Natter--> tcp://233.252.0.200:20000
[I]
[I] Test mode in on.
[I] Please check [ http://233.252.0.200:20000 ]
...

# curl on test HTTP service served on the external port should gives:
$ curl http://233.252.0.200:20000
<html><body><h1>It works!</h1><hr/>Natter</body></html>
```

Similar work can also be done with [natmap](https://github.com/heiher/natmap).

You can optionally start a STUN server for port mapping on private external address, which is not reachable(i.e. behind an external NAT) by public STUN server. With hairpin routing setup, we can reach the STUN server with external address. Note the STUN server port(default is `3478`) should be excluded from NAT port ranges that `einat` uses.

Start STUN server on router:

```shell
stunserver --protocol tcp
```

Run Natter with router STUN server specified on device 1:

```shell
python natter.py -b 20001 -m test -s 233.252.0.200
```
