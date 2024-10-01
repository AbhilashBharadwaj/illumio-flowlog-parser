import unittest
from unittest.mock import mock_open, patch
from src.main import (
    parse_lookup_table,
    process_flow_log_line,
    parse_flow_logs,
    write_output,
    LookupTableError,
)
from collections import defaultdict


class TestFlowLogParser(unittest.TestCase):

    def setUp(self):
        # Setup a basic lookup table example for use in tests
        self.lookup_table = {
            ("25", "tcp"): "sv_P1",
            ("110", "tcp"): "email",
            ("993", "tcp"): "email",
            ("143", "tcp"): "email",
        }
        self.malformed_line = "malformed log line"

    def test_parse_lookup_table_valid(self):
        # Test parsing a valid lookup CSV file
        lookup_csv = "dstport,protocol,tag\n25,tcp,sv_P1\n110,tcp,email"
        with patch("builtins.open", mock_open(read_data=lookup_csv)):
            result = parse_lookup_table("dummy.csv")
            expected = {("25", "tcp"): "sv_P1", ("110", "tcp"): "email"}
            self.assertEqual(result, expected)

    def test_parse_lookup_table_invalid_headers(self):
        # Test if invalid headers raise a LookupTableError
        invalid_csv = "wrong,dstport,headers\n25,tcp,sv_P1"
        with patch("builtins.open", mock_open(read_data=invalid_csv)):
            with self.assertRaises(LookupTableError):
                parse_lookup_table("dummy.csv")

    def test_parse_lookup_table_no_data(self):
        # Test when the lookup table has no data rows
        empty_csv = "dstport,protocol,tag\n"
        with patch("builtins.open", mock_open(read_data=empty_csv)):
            with self.assertRaises(LookupTableError):
                parse_lookup_table("dummy.csv")

    def test_process_flow_log_line_valid(self):
        # Test processing a valid flow log line
        line = "2 123456789012 eni-9k10l11m 192.168.1.5 51.15.99.115 49321 25 6 20 10000 1620140661 1620140721 ACCEPT OK"
        tag, port_protocol = process_flow_log_line(line, self.lookup_table)
        self.assertEqual(tag, "sv_P1")
        self.assertEqual(port_protocol, ("25", "tcp"))

    def test_process_flow_log_line_invalid_protocol(self):
        # Test flow log line with unknown protocol
        line = "2 123456789012 eni-9k10l11m 192.168.1.5 51.15.99.115 49321 25 999 20 10000 1620140661 1620140721 ACCEPT OK"
        tag, port_protocol = process_flow_log_line(line, self.lookup_table)
        self.assertIsNone(tag)
        self.assertIsNone(port_protocol)

    def test_process_flow_log_line_malformed(self):
        # Test malformed flow log line
        tag, port_protocol = process_flow_log_line(
            self.malformed_line, self.lookup_table
        )
        self.assertIsNone(tag)
        self.assertIsNone(port_protocol)

    def test_parse_flow_logs(self):
        # Test parsing the flow logs with valid and malformed entries
        flow_log_content = (
            "2 123456789012 eni-9k10l11m 192.168.1.5 51.15.99.115 49321 25 6 20 10000 1620140661 1620140721 ACCEPT OK\n"
            "2 123456789012 eni-1a2b3c4d 192.168.1.6 87.250.250.242 49152 110 6 5 2500 1620140661 1620140721 ACCEPT OK\n"
            f"{self.malformed_line}\n"
        )

        with patch("builtins.open", mock_open(read_data=flow_log_content)):
            tag_count, port_protocol_count = parse_flow_logs(
                "dummy.txt", self.lookup_table
            )

        # Check the tag count results
        expected_tag_count = {"sv_P1": 1, "email": 1}
        self.assertEqual(tag_count, expected_tag_count)

        # Check the port/protocol combination count
        expected_port_protocol_count = {("25", "tcp"): 1, ("110", "tcp"): 1}
        self.assertEqual(port_protocol_count, expected_port_protocol_count)

    def test_write_output(self):
        # Test writing the output to a file
        tag_count = {"sv_P1": 2, "email": 3}
        port_protocol_count = {("25", "tcp"): 2, ("110", "tcp"): 3}

        with patch("builtins.open", mock_open()) as mock_file:
            write_output(tag_count, port_protocol_count, "dummy_output.txt")

            # Get the file handle and check the write calls
            file_handle = mock_file()
            file_handle.write.assert_called()  # Ensure something was written to the file

    def test_process_flow_log_line_invalid_version(self):
        # Test flow log line with unsupported version
        line = "1 123456789012 eni-9k10l11m 192.168.1.5 51.15.99.115 49321 25 6 20 10000 1620140661 1620140721 ACCEPT OK"
        tag, port_protocol = process_flow_log_line(line, self.lookup_table)
        self.assertIsNone(tag)
        self.assertIsNone(port_protocol)

    def test_process_flow_log_line_nodata(self):
        # Test flow log line with NODATA status
        line = "2 123456789010 eni-1235b8ca123456789 - - - - - - - 1431280876 1431280934 - NODATA"
        tag, port_protocol = process_flow_log_line(line, self.lookup_table)
        self.assertIsNone(tag)
        self.assertIsNone(port_protocol)

    def test_process_flow_log_line_skipdata(self):
        # Test flow log line with SKIPDATA status
        line = "2 123456789010 eni-11111111aaaaaaaaa - - - - - - - 1431280876 1431280934 - SKIPDATA"
        tag, port_protocol = process_flow_log_line(line, self.lookup_table)
        self.assertIsNone(tag)
        self.assertIsNone(port_protocol)


if __name__ == "__main__":
    unittest.main()
