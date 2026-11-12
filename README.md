![Sluice gate close up as the race pours through the gap under its boards, foam and green water at the sill and the red wheel handle sharp above](intro-banner.png)

# analyze-traffic

![Mill race running the width of the frame channelled through one timber sluice gate at its centre, the water green and fast under the boards, a side rack at the frame edge holding caught branches the gate turned back and the red wheel handle standing above the beam](banner.png)

![Timber sluice gate straight on across a narrow mill race, green water pouring through the gap under its boards, one red wheel handle on the beam above the gate and grey stone wall at either side](logo.png)

![Bench scene in the shop window: masts sway far off in the doorway, a highlight travels along the shelf of finished sextants, dust drifts in the near light](scene.svg)


Analyze network traffic patterns from a CSV file or a PCAP capture, focusing on data analysis and reporting.


![Section divider](sep-light.svg)

## Input formats

CSV input is read with the columns Source IP, Destination IP, Source Port, Destination Port, and Protocol, and the filters below match on those columns.

PCAP input (`-f pcap`) is parsed by the tool itself, in the Python standard library, into the same columns, plus Timestamp and Length. Both byte orders and both timestamp resolutions (microsecond and nanosecond) are read. Supported link types are Ethernet (including VLAN tagged frames), raw IP (link types 101 and 12), Linux cooked capture v1 and v2 (113 and 276), and loopback (0). IPv4 and IPv6 packets are decoded: source and destination addresses, protocol, and the TCP, UDP, or SCTP ports. Protocol is recorded as a name (TCP, UDP, ICMP, ICMPv6, IGMP, SCTP) or as the IP protocol number for anything else. Packets that are not IP, such as ARP, are skipped and counted in the log. Other link types are not supported. A truncated or malformed capture is an error and the run exits 1; it is never reported as an empty result.

> Maker's tag: a truncated or malformed capture is an error and the run exits 1. It is never reported as an empty result.

> Maker's tag: packets that are not IP, such as ARP, are skipped and counted in the log. Other link types are not supported.


![Section divider](sep-heavy.svg)

## Install
`git clone https://github.com/ShadowStrikeHQ/analyze-traffic`


![Section divider](sep-light.svg)

## Usage
`./analyze-traffic [params]`

> Maker's tag: the usage line names no input file argument. How the CSV or PCAP file itself is supplied is not spelled out in that line.


![Section divider](sep-heavy.svg)

## Parameters
- `-h`: Show help message and exit
- `-o`: Path to the output report file. Defaults to stdout.
- `-f`: Type of the input file: csv or pcap. PCAP captures are parsed as described under Input formats above; a truncated or malformed capture exits 1.
- `-ip`: Filter traffic by a specific IP address.
- `-p`: Filter traffic by a specific port number.
- `-proto`: Filter traffic by a specific protocol (e.g., TCP, UDP).
- `-n`: Number of rows to process.
- `--src_ip`: Filter by source IP.
- `--dst_ip`: Filter by destination IP.
- `--src_port`: Filter by source port.
- `--dst_port`: Filter by destination port.


![Section divider](sep-heavy.svg)

## License
Copyright (c) ShadowStrikeHQ
