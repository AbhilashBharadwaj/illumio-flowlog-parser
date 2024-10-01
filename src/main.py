import csv
import logging
import os
from collections import defaultdict
from typing import Any, Dict, Tuple

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)

# Constants
PROTOCOL_MAPPING = {"6": "tcp", "17": "udp", "1": "icmp"}
EXPECTED_HEADERS = ["dstport", "protocol", "tag"]


class LookupTableError(Exception):
    """Custom exception for lookup table errors."""

    pass


def parse_lookup_table(lookup_file: str) -> Dict[Tuple[str, str], str]:
    """Parses the lookup table from a CSV file."""
    lookup = {}
    try:
        with open(lookup_file, "r") as file:
            reader = csv.DictReader(file)
            if reader.fieldnames != EXPECTED_HEADERS:
                raise LookupTableError(
                    f"Invalid headers in {lookup_file}. Expected: {EXPECTED_HEADERS}"
                )

            for row in reader:
                port = row["dstport"]
                protocol = row["protocol"].lower()
                tag = row["tag"]
                lookup[(port, protocol)] = tag

            if not lookup:
                raise LookupTableError(f"{lookup_file} contains no data rows.")

    except FileNotFoundError:
        logging.error(f"{lookup_file} not found.")
        raise
    except LookupTableError as e:
        logging.error(e)
        raise

    return lookup


def process_flow_log_line(
    line: str, lookup_table: Dict[Tuple[str, str], str]
) -> Tuple[str, Tuple[str, str]]:
    """Processes a line from the flow log."""
    parts = line.strip().split()

    # Ensure there are enough parts in the line
    if len(parts) != 14:
        logging.warning(f"Skipping malformed line: {line.strip()}")
        return None, None

    dstport = parts[6]
    protocol_num = parts[7]
    protocol = PROTOCOL_MAPPING.get(protocol_num)

    version = parts[0]
    if version != "2":
        logging.warning(f"Skipping line with unsupported version: {version}")
        return None, None

    status = parts[-1]
    if status == "NODATA":
        logging.info(f"Skipping line with NODATA status: {line.strip()}")
        return None, None
    elif status == "SKIPDATA":
        logging.info(f"Skipping line with SKIPDATA status: {line.strip()}")
        return None, None

    if protocol is None:
        logging.warning(f"Unknown protocol: {protocol_num} in line: {line.strip()}")
        return None, None

    tag = lookup_table.get((dstport, protocol), "Untagged")
    return tag, (dstport, protocol)


def parse_flow_logs(
    flow_log_file: str, lookup_table: Dict[Tuple[str, str], str]
) -> Tuple[Dict[str, int], Dict[Tuple[str, str], int]]:
    """Parses the flow log file and counts tags and port/protocol combinations."""
    tag_count = defaultdict(int)
    port_protocol_count = defaultdict(int)

    try:
        with open(flow_log_file, "r") as file:
            for line in file:
                tag, port_protocol = process_flow_log_line(line, lookup_table)

                if tag and port_protocol:
                    tag_count[tag] += 1
                    port_protocol_count[port_protocol] += 1

        if not tag_count:
            raise ValueError(
                f"{flow_log_file} does not contain any valid flow log entries."
            )

    except FileNotFoundError:
        logging.error(f"{flow_log_file} not found.")
        raise
    except ValueError as ve:
        logging.error(ve)
        raise

    return tag_count, port_protocol_count


def write_output(
    tag_count: Dict[str, int],
    port_protocol_count: Dict[Tuple[str, str], int],
    output_file: str,
):
    """Writes the tag and port/protocol counts to an output file."""
    try:
        with open(output_file, "w", newline="") as file:
            writer = csv.writer(file)

            # Write Tag Counts
            writer.writerow(["Tag Counts"])
            writer.writerow(["Tag", "Count"])
            for tag, count in tag_count.items():
                writer.writerow([tag, count])

            # Write Port/Protocol Counts
            writer.writerow([])
            writer.writerow(["Port/Protocol Combination Counts"])
            writer.writerow(["Port", "Protocol", "Count"])
            for (port, protocol), count in port_protocol_count.items():
                writer.writerow([port, protocol, count])

    except Exception as e:
        logging.error(f"Error writing to output file: {e}")
        raise


def main():
    base_dir = os.path.dirname(os.path.abspath(__file__))

    lookup_file = os.path.join(base_dir, "../data/lookup.csv")
    flow_log_file = os.path.join(base_dir, "../data/flow_log.txt")
    output_file = os.path.join(base_dir, "../output/output.txt")

    try:
        lookup_table = parse_lookup_table(lookup_file)
        tag_count, port_protocol_count = parse_flow_logs(flow_log_file, lookup_table)
        write_output(tag_count, port_protocol_count, output_file)
        logging.info("Process completed successfully.")

    except (FileNotFoundError, LookupTableError, ValueError) as e:
        logging.error(f"An error occurred during the execution: {e}")

    except Exception as e:
        logging.critical(f"Unexpected error: {e}")
        raise


if __name__ == "__main__":
    main()
