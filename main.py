import argparse
import logging
import pandas as pd
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
    parser.add_argument("-f", "--file_type", help="Type of the input file (csv, pcap, etc.).  Defaults to csv.", default="csv", choices=['csv', 'pcap'])
    parser.add_argument("-ip", "--ip_address", help="Filter traffic by a specific IP address.", default=None)
    parser.add_argument("-p", "--port", type=int, help="Filter traffic by a specific port number.", default=None)
    parser.add_argument("-proto", "--protocol", help="Filter traffic by a specific protocol (e.g., TCP, UDP).", default=None)
    parser.add_argument("-n", "--num_rows", type=int, help="Number of rows to process.", default=None)
    parser.add_argument("--src_ip", help="Filter by source IP.", default=None)
    parser.add_argument("--dst_ip", help="Filter by destination IP.", default=None)
    parser.add_argument("--src_port", type=int, help="Filter by source port.", default=None)
    parser.add_argument("--dst_port", type=int, help="Filter by destination port.", default=None)

    return parser.parse_args()


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
                df = pd.read_csv(input_file)  # Consider specifying encoding if necessary, e.g., encoding='utf-8'
                if num_rows:
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
            logging.warning("PCAP file parsing is not yet implemented.  Returning an empty DataFrame.")
            df = pd.DataFrame()  # Placeholder.  Requires a proper PCAP parsing library like dpkt or scapy.
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

        # Filtering data
        if ip_address:
            df = df[(df['Source IP'] == ip_address) | (df['Destination IP'] == ip_address)]  # Assuming 'Source IP' and 'Destination IP' columns

        if port:
            df = df[(df['Source Port'] == port) | (df['Destination Port'] == port)]  # Assuming 'Source Port' and 'Destination Port' columns

        if protocol:
            df = df[df['Protocol'] == protocol] # Assuming 'Protocol' column

        if src_ip:
            df = df[df['Source IP'] == src_ip]
        
        if dst_ip:
            df = df[df['Destination IP'] == dst_ip]
        
        if src_port:
            df = df[df['Source Port'] == src_port]
            
        if dst_port:
            df = df[df['Destination Port'] == dst_port]

        if df.empty:
            logging.warning("No data found matching the specified criteria.")
        else:
            logging.info(f"Traffic analysis completed. Number of rows returned: {len(df)}")

        return df

    except FileNotFoundError as e:
        logging.error(f"File not found: {e}")
        return pd.DataFrame()  # Return an empty DataFrame in case of error
    except ValueError as e:
        logging.error(f"Invalid input: {e}")
        return pd.DataFrame()  # Return an empty DataFrame in case of error
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        return pd.DataFrame() # Return an empty DataFrame in case of error

def main():
    """
    Main function to execute the traffic analysis tool.
    """
    args = setup_argparse()

    try:
        analyzed_data = analyze_traffic(args.input_file, args.file_type, args.ip_address, args.port, args.protocol, args.num_rows, args.src_ip, args.dst_ip, args.src_port, args.dst_port)

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
    # python main.py traffic_data.csv -f pcap  (PCAP support not fully implemented)
    # python main.py traffic_data.csv -n 100
    main()