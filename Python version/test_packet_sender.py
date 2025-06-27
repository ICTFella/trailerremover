#!/usr/bin/env python3
"""
Test Packet Sender for PRP Trailer Removal

This script sends sample TCP packets from source port 102 with PRP trailers
to test the trailerremover.py script functionality.

Requirements:
- scapy library: pip install scapy
- Run as Administrator on Windows
- Ensure trailerremover.py is running to intercept the packets
"""

import time
import logging
import struct
import random

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

# PRP Trailer constants (matching trailerremover.py)
PRP_SUFFIX = b'\x88\xfb'
PRP_TRAILER_LENGTH = 6

def create_prp_trailer():
    """
    Creates a 6-byte PRP trailer ending with the PRP suffix.
    
    Returns:
        bytes: 6-byte PRP trailer
    """
    # Create 4 bytes of random data + 2-byte PRP suffix
    random_data = struct.pack('>I', random.randint(0, 0xFFFFFFFF))[:4]
    trailer = random_data + PRP_SUFFIX
    logger.debug(f"Created PRP trailer: {trailer.hex()} (length: {len(trailer)} bytes)")
    return trailer

def display_packet_details(packet, description):
    """
    Display detailed packet information for debugging.
    
    Args:
        packet: The scapy packet object
        description (str): Description of the packet
    """
    logger.info(f"\n--- {description} ---")
    logger.info(f"Packet summary: {packet.summary()}")
    
    # Extract and display the raw payload
    if packet.haslayer('Raw'):
        raw_payload = bytes(packet['Raw'])
        logger.info(f"Raw payload length: {len(raw_payload)} bytes")
        logger.info(f"Raw payload (hex): {raw_payload.hex()}")
        logger.info(f"Raw payload (ascii): {raw_payload}")
        
        # Check if it ends with PRP suffix
        if raw_payload.endswith(PRP_SUFFIX):
            logger.info(f"✓ Payload DOES end with PRP suffix: {PRP_SUFFIX.hex()}")
            if len(raw_payload) >= PRP_TRAILER_LENGTH:
                trailer_part = raw_payload[-PRP_TRAILER_LENGTH:]
                logger.info(f"✓ Last {PRP_TRAILER_LENGTH} bytes (PRP trailer): {trailer_part.hex()}")
            else:
                logger.warning(f"⚠ Payload too short for full trailer")
        else:
            logger.info(f"✗ Payload does NOT end with PRP suffix")
            if len(raw_payload) >= 2:
                last_2_bytes = raw_payload[-2:]
                logger.info(f"Last 2 bytes are: {last_2_bytes.hex()} (expected: {PRP_SUFFIX.hex()})")
    else:
        logger.warning("Packet has no Raw layer!")
    
    logger.info("--- End packet details ---\n")

def send_test_packet_with_trailer(dest_ip="127.0.0.1", dest_port=8080, data_payload=b"Hello, World!"):
    """
    Sends a TCP packet from source port 102 with a PRP trailer.
    
    Args:
        dest_ip (str): Destination IP address
        dest_port (int): Destination port
        data_payload (bytes): The main data payload
    """
    try:
        from scapy.all import IP, TCP, Raw, send
        
        # Create the full payload: data + PRP trailer
        prp_trailer = create_prp_trailer()
        full_payload = data_payload + prp_trailer
        
        logger.info(f"Sending packet to {dest_ip}:{dest_port}")
        logger.info(f"Original data payload: {data_payload}")
        logger.info(f"PRP trailer: {prp_trailer.hex()}")
        logger.info(f"Full payload: {full_payload.hex()}")
        logger.info(f"Full payload length: {len(full_payload)} bytes")
        
        # Create the packet
        packet = IP(dst=dest_ip) / TCP(sport=102, dport=dest_port, flags="PA") / Raw(load=full_payload)
        
        # Display detailed packet info for debugging
        display_packet_details(packet, "Packet WITH PRP trailer (before sending)")
        
        # Send the packet
        send(packet, verbose=False)
        logger.info("✓ Packet sent successfully")
        
    except ImportError:
        logger.error("scapy library not found. Please install with: pip install scapy")
        raise
    except Exception as e:
        logger.error(f"Error sending packet: {e}")

def send_test_packet_without_trailer(dest_ip="127.0.0.1", dest_port=8080, data_payload=b"Hello, World!"):
    """
    Sends a TCP packet from source port 102 without a PRP trailer (control test).
    
    Args:
        dest_ip (str): Destination IP address
        dest_port (int): Destination port
        data_payload (bytes): The main data payload
    """
    try:
        from scapy.all import IP, TCP, Raw, send
        
        logger.info(f"Sending control packet (no trailer) to {dest_ip}:{dest_port}")
        logger.info(f"Data payload: {data_payload}")
        logger.info(f"Data payload (hex): {data_payload.hex()}")
        logger.info(f"Payload length: {len(data_payload)} bytes")
        
        # Create the packet without trailer
        packet = IP(dst=dest_ip) / TCP(sport=102, dport=dest_port, flags="PA") / Raw(load=data_payload)
        
        # Display detailed packet info for debugging
        display_packet_details(packet, "Control packet WITHOUT PRP trailer (before sending)")
        
        # Send the packet
        send(packet, verbose=False)
        logger.info("✓ Control packet sent successfully")
        
    except ImportError:
        logger.error("scapy library not found. Please install with: pip install scapy")
        raise
    except Exception as e:
        logger.error(f"Error sending control packet: {e}")

def send_test_packet_wrong_port(dest_ip="127.0.0.1", dest_port=8080, data_payload=b"Hello, World!"):
    """
    Sends a TCP packet from a different source port (should be ignored by trailerremover.py).
    
    Args:
        dest_ip (str): Destination IP address
        dest_port (int): Destination port
        data_payload (bytes): The main data payload
    """
    try:
        from scapy.all import IP, TCP, Raw, send
        
        # Create the full payload: data + PRP trailer
        prp_trailer = create_prp_trailer()
        full_payload = data_payload + prp_trailer
        
        logger.info(f"Sending packet from wrong port (443) to {dest_ip}:{dest_port}")
        logger.info(f"This packet should be ignored by trailerremover.py")
        logger.info(f"Full payload length: {len(full_payload)} bytes")
        logger.info(f"Full payload (hex): {full_payload.hex()}")
        
        # Create the packet from wrong source port
        packet = IP(dst=dest_ip) / TCP(sport=443, dport=dest_port, flags="PA") / Raw(load=full_payload)
        
        # Display detailed packet info for debugging
        display_packet_details(packet, "Packet from WRONG port (443) with PRP trailer")
        
        # Send the packet
        send(packet, verbose=False)
        logger.info("✓ Wrong port packet sent successfully")
        
    except ImportError:
        logger.error("scapy library not found. Please install with: pip install scapy")
        raise
    except Exception as e:
        logger.error(f"Error sending wrong port packet: {e}")

def test_trailer_creation():
    """
    Test the PRP trailer creation function to make sure it works correctly.
    """
    logger.info("\n" + "="*50)
    logger.info("TESTING PRP TRAILER CREATION")
    logger.info("="*50)
    
    for i in range(3):
        trailer = create_prp_trailer()
        logger.info(f"Test {i+1}:")
        logger.info(f"  Trailer: {trailer.hex()}")
        logger.info(f"  Length: {len(trailer)} bytes")
        logger.info(f"  Ends with PRP suffix ({PRP_SUFFIX.hex()}): {trailer.endswith(PRP_SUFFIX)}")
        logger.info(f"  Last 2 bytes: {trailer[-2:].hex()}")
    
    logger.info("="*50 + "\n")

def run_test_sequence():
    """
    Runs a sequence of test packets to validate trailerremover.py functionality.
    """
    logger.info("Starting PRP trailer removal test sequence")
    logger.info("Make sure trailerremover.py is running to see the trailer removal in action!")
    logger.info("="*60)
    
    # Test trailer creation first
    test_trailer_creation()
    
    dest_ip = "192.168.8.153"
    dest_port = 8080
    
    logger.info(f"Target: {dest_ip}:{dest_port}")
    logger.info(f"Expected PRP suffix: {PRP_SUFFIX.hex()}")
    logger.info("")
    
    test_payloads = [
        b"Test message 1",
        b"Short",
        b"Longer test message with more data to verify PRP trailer removal"
    ]
    
    for i, payload in enumerate(test_payloads, 1):
        logger.info(f"\n{'='*60}")
        logger.info(f"TEST SET {i}")
        logger.info(f"{'='*60}")
        
        # First send packet WITH trailer
        logger.info(f"\n--- Test {i}A: Packet WITH PRP trailer ---")
        send_test_packet_with_trailer(dest_ip, dest_port, payload)
        time.sleep(2)  # Increased sleep time
        
        # Then send control packet WITHOUT trailer
        logger.info(f"\n--- Test {i}B: Control packet WITHOUT PRP trailer ---")
        send_test_packet_without_trailer(dest_ip, dest_port, payload)
        time.sleep(2)  # Increased sleep time
    
    # Test with wrong source port
    logger.info(f"\n{'='*60}")
    logger.info(f"WRONG PORT TEST")
    logger.info(f"{'='*60}")
    logger.info(f"\n--- Test: Packet from wrong source port (should be ignored) ---")
    send_test_packet_wrong_port(dest_ip, dest_port, b"This should be ignored")
    time.sleep(2)
    
    logger.info(f"\n{'='*60}")
    logger.info("TEST SEQUENCE COMPLETED!")
    logger.info("Check trailerremover.py logs to see which packets had trailers stripped.")
    logger.info("In Wireshark, filter by: tcp.srcport == 102 or tcp.srcport == 443")
    logger.info(f"Look for packets to {dest_ip}:{dest_port}")
    logger.info(f"PRP trailers should end with: {PRP_SUFFIX.hex()}")
    logger.info("="*60)

def main():
    """
    Main function to run the test packet sender.
    """
    logger.info("PRP Trailer Test Packet Sender")
    logger.info("This script sends test packets to validate trailerremover.py")
    logger.info("Make sure you have:")
    logger.info("1. Installed scapy: pip install scapy")
    logger.info("2. Running this script as Administrator")
    logger.info("3. trailerremover.py is running in another terminal")
    logger.info("")
    
    try:
        # Import and configure scapy
        from scapy.all import conf
        
        # Disable scapy verbose output but enable our detailed logging
        conf.verb = 0
        
        # Set debug level for more details
        logger.setLevel(logging.DEBUG)
        
        # Run the test sequence
        run_test_sequence()
        
    except ImportError as e:
        logger.error("Failed to import required libraries.")
        logger.error("Please install scapy: pip install scapy")
        logger.error(f"Error: {e}")
        return 1
    except Exception as e:
        logger.error(f"An unexpected error occurred: {e}")
        logger.error("Please ensure you are running as Administrator.")
        return 1
    
    return 0

if __name__ == "__main__":
    exit(main()) 