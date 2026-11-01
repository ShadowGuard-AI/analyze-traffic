import argparse
import ipaddress
import logging
import pandas as pd
import struct
import sys

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.
    """
    parser = argparse.ArgumentParser(description="Analyze network traffic patterns - Focused on Data analysis and reporting.")
    parser.add_argument("input_file", help="Path to the input traffic data file (e.g., CSV, PCAP).")
    parser.add_argument("-o", "--output_file", help="Path to the output report file (e.g., CSV, TXT).  Defaults to stdout.", default=None)
    parser.add_argument("-f", "--file_type", help="Type of the input file: csv or pcap. PCAP captures are parsed into the CSV column shape; a truncated or malformed capture exits 1.  Defaults to csv.", default="csv", choices=['csv', 'pcap'])
    parser.add_argument("-ip", "--ip_address", help="Filter traffic by a specific IP address.", default=None)
    parser.add_argument("-p", "--port", type=int, help="Filter traffic by a specific port number.", default=None)
    parser.add_argument("-proto", "--protocol", help="Filter traffic by a specific protocol (e.g., TCP, UDP).", default=None)
    parser.add_argument("-n", "--num_rows", type=int, help="Number of rows to process.", default=None)
    parser.add_argument("--src_ip", help="Filter by source IP.", default=None)
    parser.add_argument("--dst_ip", help="Filter by destination IP.", default=None)
    parser.add_argument("--src_port", type=int, help="Filter by source port.", default=None)
    parser.add_argument("--dst_port", type=int, help="Filter by destination port.", default=None)

    return parser.parse_args()


# PCAP parsing, pure standard library. The parser reads the classic PCAP
# container (both endiannesses, microsecond and nanosecond timestamps)
# and decodes each packet into the same column shape the CSV branch
# produces and the filters below read: Source IP, Destination IP,
# Source Port, Destination Port, and Protocol, plus Timestamp and
# Length. A truncated or malformed capture raises ValueError, which
# analyze_traffic turns into a failed run at exit 1, never an empty
# result at exit 0.
PCAP_COLUMNS = ['Timestamp', 'Source IP', 'Destination IP', 'Source Port',
                'Destination Port', 'Protocol', 'Length']

_PROTOCOL_NAMES = {
    1: "ICMP",
    2: "IGMP",
    6: "TCP",
    17: "UDP",
    58: "ICMPv6",
    132: "SCTP",
}

_LINKTYPE_ETHERNET = 1
_LINKTYPE_NULL = 0
_LINKTYPE_RAW = 101
_LINKTYPE_RAW_ALT = 12
_LINKTYPE_LINUX_SLL = 113
_LINKTYPE_LINUX_SLL2 = 276
_SUPPORTED_LINKTYPES = {
    _LINKTYPE_ETHERNET, _LINKTYPE_NULL, _LINKTYPE_RAW, _LINKTYPE_RAW_ALT,
    _LINKTYPE_LINUX_SLL, _LINKTYPE_LINUX_SLL2,
}


def _protocol_name(number):
    return _PROTOCOL_NAMES.get(number, str(number))


def _decode_ip_packet(ip_data):
    """Decode one IPv4 or IPv6 packet into a filter row, or return None
    for a packet that is not IP. Raises ValueError on a truncated header."""
    if len(ip_data) < 1:
        raise ValueError("Truncated packet: no IP header bytes.")
    version = ip_data[0] >> 4
    if version == 4:
        if len(ip_data) < 20:
            raise ValueError("Truncated packet: incomplete IPv4 header.")
        header_len = (ip_data[0] & 0x0F) * 4
        if header_len < 20 or len(ip_data) < header_len:
            raise ValueError("Truncated packet: incomplete IPv4 header.")
        total_length = struct.unpack_from(">H", ip_data, 2)[0]
        protocol_number = ip_data[9]
        source = str(ipaddress.IPv4Address(ip_data[12:16]))
        destination = str(ipaddress.IPv4Address(ip_data[16:20]))
        fragment_offset = struct.unpack_from(">H", ip_data, 6)[0] & 0x1FFF
        end = total_length if 0 < total_length <= len(ip_data) else len(ip_data)
        transport = ip_data[header_len:end]
    elif version == 6:
        if len(ip_data) < 40:
            raise ValueError("Truncated packet: incomplete IPv6 header.")
        protocol_number = ip_data[6]
        source = str(ipaddress.IPv6Address(ip_data[8:24]))
        destination = str(ipaddress.IPv6Address(ip_data[24:40]))
        fragment_offset = 0
        offset = 40
        # Walk the common extension headers so the ports below come from
        # the real transport header. Anything unrecognised stops the walk
        # and is reported under its own protocol number.
        for _ in range(8):
            if protocol_number in (0, 43, 60):  # hop by hop, routing, destination options
                if len(ip_data) < offset + 2:
                    raise ValueError("Truncated packet: incomplete IPv6 extension header.")
                next_header = ip_data[offset]
                offset += (ip_data[offset + 1] + 1) * 8
                protocol_number = next_header
            elif protocol_number == 44:  # fragment
                if len(ip_data) < offset + 8:
                    raise ValueError("Truncated packet: incomplete IPv6 fragment header.")
                next_header = ip_data[offset]
                fragment_offset = struct.unpack_from(">H", ip_data, offset + 2)[0] >> 3
                offset += 8
                protocol_number = next_header
            elif protocol_number == 51:  # authentication header
                if len(ip_data) < offset + 2:
                    raise ValueError("Truncated packet: incomplete IPv6 authentication header.")
                next_header = ip_data[offset]
                offset += (ip_data[offset + 1] + 2) * 4
                protocol_number = next_header
            else:
                break
        if len(ip_data) < offset:
            raise ValueError("Truncated packet: IPv6 extension headers run past the packet.")
        transport = ip_data[offset:]
    else:
        return None

    source_port = None
    destination_port = None
    # Ports exist only in the first fragment of a TCP, UDP, or SCTP packet.
    if protocol_number in (6, 17, 132) and fragment_offset == 0 and len(transport) >= 4:
        source_port, destination_port = struct.unpack_from(">HH", transport, 0)

    return {
        'Source IP': source,
        'Destination IP': destination,
        'Source Port': source_port,
        'Destination Port': destination_port,
        'Protocol': _protocol_name(protocol_number),
    }


def _decode_link_packet(packet, linktype, endian):
    """Strip the link layer header and decode the IP packet inside.
    Returns None for a non IP packet (for example ARP). Raises
    ValueError on a packet too short for its link header."""
    if linktype == _LINKTYPE_ETHERNET:
        if len(packet) < 14:
            raise ValueError("Truncated packet: incomplete Ethernet header.")
        ether_type = struct.unpack_from(">H", packet, 12)[0]
        offset = 14
        while ether_type in (0x8100, 0x88A8):  # VLAN tags
            if len(packet) < offset + 4:
                raise ValueError("Truncated packet: incomplete VLAN tag.")
            ether_type = struct.unpack_from(">H", packet, offset + 2)[0]
            offset += 4
        if ether_type == 0x0800:
            ip_version = 4
        elif ether_type == 0x86DD:
            ip_version = 6
        else:
            return None
        ip_data = packet[offset:]
        if len(ip_data) < 1 or (ip_data[0] >> 4) != ip_version:
            raise ValueError("Truncated packet: link header promises an IP packet that is not there.")
        return _decode_ip_packet(ip_data)
    if linktype == _LINKTYPE_LINUX_SLL:
        if len(packet) < 16:
            raise ValueError("Truncated packet: incomplete Linux cooked header.")
        ether_type = struct.unpack_from(">H", packet, 14)[0]
        if ether_type not in (0x0800, 0x86DD):
            return None
        return _decode_ip_packet(packet[16:])
    if linktype == _LINKTYPE_LINUX_SLL2:
        if len(packet) < 20:
            raise ValueError("Truncated packet: incomplete Linux cooked v2 header.")
        ether_type = struct.unpack_from(">H", packet, 0)[0]
        if ether_type not in (0x0800, 0x86DD):
            return None
        return _decode_ip_packet(packet[20:])
    if linktype in (_LINKTYPE_RAW, _LINKTYPE_RAW_ALT):
        return _decode_ip_packet(packet)
    if linktype == _LINKTYPE_NULL:
        if len(packet) < 4:
            raise ValueError("Truncated packet: incomplete loopback header.")
        address_family = struct.unpack_from(endian + "I", packet, 0)[0]
        if address_family not in (2, 24, 28, 30):  # AF_INET, and the BSD AF_INET6 values
            return None
        return _decode_ip_packet(packet[4:])
    raise ValueError(f"Unsupported PCAP link type: {linktype}")


def parse_pcap_file(input_file):
    """
    Parses a PCAP capture file into a DataFrame with the CSV column shape.

    Raises FileNotFoundError when the file does not exist and ValueError
    when the capture is truncated, malformed, or uses an unsupported
    link type, so a bad capture fails the run instead of reading as an
    empty result.
    """
    with open(input_file, "rb") as handle:
        data = handle.read()

    if len(data) < 24:
        raise ValueError(f"PCAP file is too short to hold a PCAP header: {input_file}")
    magic = data[:4]
    # Classic PCAP only. A pcapng capture, which is what current
    # Wireshark writes by default, fails this magic test and exits as
    # not a PCAP file; the error is honest about it, at least.
    if magic == b"\xa1\xb2\xc3\xd4":
        endian, fraction_divisor = ">", 1_000_000
    elif magic == b"\xd4\xc3\xb2\xa1":
        endian, fraction_divisor = "<", 1_000_000
    elif magic == b"\xa1\xb2\x3c\x4d":
        endian, fraction_divisor = ">", 1_000_000_000
    elif magic == b"\x4d\x3c\xb2\xa1":
        endian, fraction_divisor = "<", 1_000_000_000
    else:
        raise ValueError(f"Not a PCAP file (bad magic number): {input_file}")

    _major, _minor, _thiszone, _sigfigs, _snaplen, linktype = struct.unpack_from(endian + "HHiIII", data, 4)
    if linktype not in _SUPPORTED_LINKTYPES:
        raise ValueError(f"Unsupported PCAP link type: {linktype}")

    rows = []
    skipped_non_ip = 0
    offset = 24
    while offset < len(data):
        if len(data) - offset < 16:
            raise ValueError(f"Truncated PCAP file: packet record header at byte {offset} is incomplete.")
        ts_seconds, ts_fraction, captured_len, original_len = struct.unpack_from(endian + "IIII", data, offset)
        offset += 16
        if len(data) - offset < captured_len:
            raise ValueError(
                f"Truncated PCAP file: packet at byte {offset} claims {captured_len} bytes, "
                f"only {len(data) - offset} remain."
            )
        packet = data[offset:offset + captured_len]
        offset += captured_len
        row = _decode_link_packet(packet, linktype, endian)
        if row is None:
            skipped_non_ip += 1
            continue
        # The timestamp is a float of epoch seconds, so at current
        # epoch values a float64 keeps about microsecond resolution:
        # a nanosecond capture's last digits are rounded away here.
        # Length is the wire length from the record header, not the
        # captured length, so a snaplen truncated packet still reports
        # the size it had on the wire.
        row['Timestamp'] = ts_seconds + ts_fraction / fraction_divisor
        row['Length'] = original_len
        rows.append(row)

    if skipped_non_ip:
        logging.info(f"PCAP parsing skipped {skipped_non_ip} non IP packet(s).")
    logging.info(f"PCAP parsing read {len(rows)} IP packet(s) from {input_file}")
    return pd.DataFrame(rows, columns=PCAP_COLUMNS)


def analyze_traffic(input_file, file_type, ip_address, port, protocol, num_rows, src_ip, dst_ip, src_port, dst_port):
    """
    Analyzes network traffic data based on specified criteria.

    Args:
        input_file (str): Path to the input traffic data file.
        file_type (str): Type of the input file (e.g., CSV).
        ip_address (str): IP address to filter traffic by.
        port (int): Port number to filter traffic by.
        protocol (str): Protocol to filter traffic by.
        num_rows (int): Number of rows to process.
        src_ip (str): Filter by source IP.
        dst_ip (str): Filter by destination IP.
        src_port (int): Filter by source port.
        dst_port (int): Filter by destination port.

    Returns:
        pandas.DataFrame: A DataFrame containing the analyzed traffic data.
    """
    try:
        if file_type == "csv":
            try:
                df = pd.read_csv(input_file)
                if num_rows is not None:
                    if num_rows < 0:
                        raise ValueError("Number of rows must not be negative.")
                    df = df.head(num_rows)
            except FileNotFoundError:
                logging.error(f"Input file not found: {input_file}")
                raise
            except pd.errors.ParserError:
                logging.error(f"Error parsing CSV file: {input_file}.  Check for correct formatting.")
                raise
            except Exception as e:
                logging.error(f"An unexpected error occurred while reading the CSV file: {e}")
                raise

        elif file_type == "pcap":
            # Real PCAP parsing in the standard library (see
            # parse_pcap_file). A truncated or malformed capture raises
            # and fails the run at exit 1; it never reads as an empty
            # result.
            df = parse_pcap_file(input_file)
            if num_rows is not None:
                if num_rows < 0:
                    raise ValueError("Number of rows must not be negative.")
                df = df.head(num_rows)
        else:
            raise ValueError(f"Unsupported file type: {file_type}")
        

        # Input validation: Prevent SQL Injection-like attacks by validating inputs
        if ip_address:
            if not isinstance(ip_address, str):
                raise ValueError("IP address must be a string.")

        if port is not None:
            if not isinstance(port, int) or port < 0 or port > 65535:
                raise ValueError("Port must be an integer between 0 and 65535.")
        
        if src_port is not None:
            if not isinstance(src_port, int) or src_port < 0 or src_port > 65535:
                raise ValueError("Source port must be an integer between 0 and 65535.")
        
        if dst_port is not None:
            if not isinstance(dst_port, int) or dst_port < 0 or dst_port > 65535:
                raise ValueError("Destination port must be an integer between 0 and 65535.")

        # num_rows was applied at load time, above, so it limits the
        # rows the filters see, not the rows the filters return: the
        # first hundred rows of the file, filtered, which can be none
        # of them even when matches exist later in the file. The
        # protocol test is an exact string match, and the two input
        # branches spell values differently, the PCAP parser produces
        # TCP in capitals while a CSV carries whatever its author
        # wrote, so the same filter value can match one source and
        # silently miss the other.
        if ip_address:
            df = df[(df['Source IP'] == ip_address) | (df['Destination IP'] == ip_address)]  # Assuming 'Source IP' and 'Destination IP' columns

        if port is not None:
            df = df[(df['Source Port'] == port) | (df['Destination Port'] == port)]  # Assuming 'Source Port' and 'Destination Port' columns

        if protocol:
            df = df[df['Protocol'] == protocol] # Assuming 'Protocol' column

        if src_ip:
            df = df[df['Source IP'] == src_ip]
        
        if dst_ip:
            df = df[df['Destination IP'] == dst_ip]
        
        if src_port is not None:
            df = df[df['Source Port'] == src_port]
            
        if dst_port is not None:
            df = df[df['Destination Port'] == dst_port]

        if df.empty:
            logging.warning("No data found matching the specified criteria.")
        else:
            logging.info(f"Traffic analysis completed. Number of rows returned: {len(df)}")

        return df

    # Errors return None, not an empty frame. An empty frame is a real
    # result (the filters matched nothing); returning one for a missing
    # file or a bad port used to make main print it and exit 0.
    except FileNotFoundError as e:
        logging.error(f"File not found: {e}")
        return None
    except ValueError as e:
        logging.error(f"Invalid input: {e}")
        return None
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        return None

def main():
    """
    Main function to execute the traffic analysis tool.
    """
    args = setup_argparse()

    try:
        analyzed_data = analyze_traffic(args.input_file, args.file_type, args.ip_address, args.port, args.protocol, args.num_rows, args.src_ip, args.dst_ip, args.src_port, args.dst_port)
        if analyzed_data is None:
            sys.exit(1)

        if args.output_file:
            try:
                analyzed_data.to_csv(args.output_file, index=False) # Output as CSV. Consider adding output format options.
                logging.info(f"Analysis results saved to: {args.output_file}")
            except Exception as e:
                logging.error(f"Error writing to output file: {e}")
                sys.exit(1)

        else:
            print(analyzed_data.to_string()) # Output to stdout.  Use to_string() for better formatting
            logging.info("Analysis results printed to standard output.")

    except Exception as e:
        logging.error(f"An error occurred during execution: {e}")
        sys.exit(1)


if __name__ == "__main__":
    # Example Usage:
    # python main.py traffic_data.csv -ip 192.168.1.1 -o output.csv
    # python main.py traffic_data.csv -p 80
    # python main.py capture.pcap -f pcap -proto TCP
    # python main.py traffic_data.csv -n 100
    main()
