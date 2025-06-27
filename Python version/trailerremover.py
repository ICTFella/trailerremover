import signal
import sys
import logging
import pydivert

# Configure logging with timestamps
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

# Set debug mode - change to DEBUG for detailed packet logging
logger.setLevel(logging.INFO)

# The PRP Suffix is a 16-bit field with the value 0x88FB.
# This is the most reliable marker for the end of a PRP trailer.
PRP_SUFFIX = b'\x88\xfb'
PRP_TRAILER_LENGTH = 6

# A flag to control the main loop
running = True

def signal_handler(sig, frame):
    """
    Handles Ctrl+C to gracefully shut down the packet processing loop.
    """
    global running
    logger.info("Shutdown signal received. Stopping packet diversion...")
    running = False

def strip_prp_trailer(packet):
    """
    Checks for and strips the 6-byte PRP trailer from a packet payload.
    Only processes packets from TCP source port 102.

    Args:
        packet (pydivert.Packet): The captured packet.

    Returns:
        pydivert.Packet: The packet, potentially with a modified payload.
    """
    # Check if payload exists
    payload = packet.payload
    if payload is None:
        logger.debug("Packet has no payload, skipping")
        return packet
    
    # Check if packet has source port and it's from TCP source port 102
    if not hasattr(packet, 'src_port') or packet.src_port is None:
        logger.debug("Packet has no source port information, skipping")
        return packet
        
    if packet.src_port != 102:
        logger.debug(f"Packet not from TCP port 102 (source port: {packet.src_port}), skipping")
        return packet
    
    # Optimize condition checking: Move the length check before accessing payload properties
    # Check if the payload is long enough to contain the trailer and if it
    # ends with the specific PRP Suffix.
    if len(payload) > PRP_TRAILER_LENGTH and payload.endswith(PRP_SUFFIX):
        
        # Log packet details only in debug mode
        logger.debug(f"PRP trailer detected on packet to {packet.dst_addr}:{packet.dst_port}. Stripping {PRP_TRAILER_LENGTH} bytes.")
        
        # The trailer is likely present. Truncate the payload by the trailer length.
        # This is the core logic of the script.
        packet.payload = payload[:-PRP_TRAILER_LENGTH]
        
        # Recalculate checksums after modifying payload
        packet.recalculate_checksums()
        
        logger.info(f"PRP trailer stripped from packet {packet.dst_addr}:{packet.dst_port}")
        
    return packet

def main():
    """
    Main function to capture, process, and re-inject network packets.
    """
    logger.info("Starting PRP trailer stripping script.")
    logger.info("This script will intercept inbound TCP traffic from port 102.")
    logger.info("Ensure WinDivert is installed and run this script as an Administrator.")
    logger.info("Press Ctrl+C to stop.")
    
    # Register the signal handler for graceful shutdown
    signal.signal(signal.SIGINT, signal_handler)

    try:
        # Create a WinDivert handle with specific filter:
        # - inbound: only incoming traffic
        # - tcp.SrcPort == 102: only from TCP source port 102
        # - tcp.PayloadLength > 0: only packets with payload
        filter_string = "inbound and tcp.SrcPort == 102 and tcp.PayloadLength > 0"
        logger.info(f"Using filter: {filter_string}")
        
        with pydivert.WinDivert(filter_string) as w:
            # Set a timeout to make recv() non-blocking so Ctrl+C works better
            w.set_param(pydivert.Param.QUEUE_TIME, 1000)  # 1 second timeout
            
            # Keep processing packets as long as the 'running' flag is True
            while running:
                try:
                    # Read a packet from the divert handle with timeout
                    packet = w.recv(timeout=1000)  # 1 second timeout
                except OSError as e:
                    # This can happen if the handle is closed while recv is waiting
                    # or on timeout - check if we're still supposed to be running
                    if running:
                        # Only log actual errors, not timeouts
                        error_msg = str(e).lower()
                        if "timeout" not in error_msg and "timed out" not in error_msg:
                            logger.debug(f"Error receiving packet: {e}")
                    continue
                except Exception as e:
                    # Handle timeout or other exceptions
                    if running:
                        logger.debug(f"Exception receiving packet: {e}")
                    continue

                if packet:
                    # Process the packet to strip the trailer if it exists
                    modified_packet = strip_prp_trailer(packet)
                    
                    # Re-inject the (potentially modified) packet back into the network stack
                    w.send(modified_packet)

    except Exception as e:
        logger.error(f"An unexpected error occurred: {e}")
        logger.error("Please ensure WinDivert is installed and you are running as Administrator.")
    finally:
        logger.info("Script has been stopped.")

if __name__ == "__main__":
    # Check for admin rights is complex in python, so we just inform the user.
    # On Windows, you can check ctypes.windll.shell32.IsUserAnAdmin() but for simplicity,
    # we'll just rely on the user running it correctly.
    main()

