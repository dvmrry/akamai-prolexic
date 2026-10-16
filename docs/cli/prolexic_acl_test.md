## prolexic acl test

test packets against an ACL version's rules (nothing is changed)

### Synopsis

Evaluates an ACL version's rules (default: production) against simulated packets with the ACL analyzer and reports each packet's verdict and the rule that decided it. The rules tested are those of the packets' IP family, renumbered from 1 for the analyzer and mapped back to their real indexes in the output. Give one packet with --src and --dst, or up to 5 with --packets FILE (a JSON array of packets in the analyzer's shape).

```
prolexic acl test [flags]
```

### Examples

```
  prolexic acl test --src 192.0.2.10 --dst 198.51.100.5 --proto tcp --dport 443
  prolexic acl test --version 8 --packets packets.json
```

### Options

```
      --dport int        destination port (tcp, udp)
      --dst string       destination IP address
      --established      the packet belongs to an established TCP connection
      --flags strings    TCP flags present, comma-separated: fin, syn, rst, psh, ack, urg, ece, cwr
      --fragment         the packet is an IP fragment
  -h, --help             help for test
      --icmp-code int    ICMP code (icmp)
      --icmp-type int    ICMP type (icmp)
      --length int       packet length in bytes
      --packets string   JSON array of up to 5 packets in the analyzer's shape (instead of the packet flags)
      --proto string     protocol: ip, ipv4, ipv6, icmp, igmp, ipinip, tcp, igrp, udp, gre, esp, ahp, eigrp, ospf, nos, pim (default "ip")
      --sport int        source port (tcp, udp)
      --src string       source IP address
      --ttl int          IP time to live, 1-255
      --version int      ACL version number (default: the version in production)
```

### Options inherited from parent commands

```
      --account-key string     accountSwitchKey, overriding the credentials' account_key ($PROLEXIC_ACCOUNT_KEY)
      --edgerc string          EdgeGrid credentials file (default ~/.edgerc; $PROLEXIC_EDGERC)
      --format string          output format: auto (text on a terminal, else json), json or text (default "auto")
      --section string         credentials section for reads ($PROLEXIC_SECTION) (default "default")
      --write-section string   credentials section for writes; only apply uses it ($PROLEXIC_WRITE_SECTION) (default "write")
```

### SEE ALSO

* [prolexic acl](prolexic_acl.md)	 - ACL versions, rules and deployment

