/*
 * PRP Trailer Remover - Direct WinDivert Implementation
 * 
 * This program intercepts inbound TCP packets from port 102 and removes
 * 6-byte PRP trailers that end with the suffix 0x88FB.
 * 
 * Compile with: cl trailerremover.c windivert.lib
 * Or with MinGW: gcc -o trailerremover.exe trailerremover.c -lwindivert
 * 
 * Requirements:
 * - WinDivert library and headers
 * - Run as Administrator
 */

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <time.h>
#include <string.h>
#include <limits.h>

// Include WinDivert header
#include "windivert.h"

// PRP Trailer constants
static const UINT8 PRP_SUFFIX[] = {0x88, 0xFB};
static const size_t PRP_SUFFIX_LEN = 2;
static const size_t PRP_TRAILER_LENGTH = 6;

// Global flag for graceful shutdown
static volatile BOOL g_running = TRUE;

/**
 * Signal handler for Ctrl+C
 */
static volatile BOOL g_shutdown_initiated = FALSE;

BOOL WINAPI ConsoleCtrlHandler(DWORD dwCtrlType) {
    if (dwCtrlType == CTRL_C_EVENT || dwCtrlType == CTRL_BREAK_EVENT) {
        if (g_shutdown_initiated) {
            // Force exit if Ctrl+C is pressed again
            printf("\n[INFO] Force exit requested...\n");
            fflush(stdout);
            fflush(stderr);
            ExitProcess(0);
        }
        
        printf("\n[INFO] Shutdown signal received. Stopping packet diversion...\n");
        printf("[INFO] Press Ctrl+C again to force exit if hung.\n");
        g_shutdown_initiated = TRUE;
        g_running = FALSE;
        return TRUE;
    }
    return FALSE;
}

/**
 * Get current timestamp string
 */
void GetTimestamp(char* buffer, size_t size) {
    time_t now = time(NULL);
    struct tm* timeinfo = localtime(&now);
    if (timeinfo != NULL) {
        strftime(buffer, size, "%Y-%m-%d %H:%M:%S", timeinfo);
    } else {
        snprintf(buffer, size, "Unknown Time");
    }
}

/**
 * Log message with timestamp
 */
void LogInfo(const char* message) {
    char timestamp[32];
    GetTimestamp(timestamp, sizeof(timestamp));
    printf("[%s] [INFO] %s\n", timestamp, message);
    fflush(stdout);
}

void LogError(const char* message) {
    char timestamp[32];
    GetTimestamp(timestamp, sizeof(timestamp));
    fprintf(stderr, "[%s] [ERROR] %s\n", timestamp, message);
    fflush(stderr);
}

void LogDebug(const char* message, BOOL debug_enabled) {
    if (debug_enabled) {
        char timestamp[32];
        GetTimestamp(timestamp, sizeof(timestamp));
        printf("[%s] [DEBUG] %s\n", timestamp, message);
        fflush(stdout);
    }
}

/**
 * Print hex dump of data
 */
void PrintHexDump(const UINT8* data, size_t len, const char* prefix) {
    printf("%s", prefix);
    for (size_t i = 0; i < len; ++i) {
        printf("%02X", data[i]);
        if (i < len - 1) printf(" ");
    }
    printf("\n");
    fflush(stdout);
}

/**
 * Check if data ends with PRP suffix
 */
BOOL EndsWithPRPSuffix(const UINT8* data, size_t len) {
    if (len < PRP_SUFFIX_LEN) {
        return FALSE;
    }
    
    const UINT8* end = data + len - PRP_SUFFIX_LEN;
    return memcmp(end, PRP_SUFFIX, PRP_SUFFIX_LEN) == 0;
}

/**
 * Process a packet and remove PRP trailer if present
 */
BOOL ProcessPacket(UINT8* packet, UINT packet_len, WINDIVERT_ADDRESS* addr, UINT* new_packet_len, BOOL debug_enabled) {
    PWINDIVERT_IPHDR ip_header = NULL;
    PWINDIVERT_TCPHDR tcp_header = NULL;
    UINT8* payload = NULL;
    UINT payload_len = 0;
    char debug_msg[256];
    
    // Parse the packet
    if (!WinDivertHelperParsePacket(packet, packet_len, &ip_header, NULL, NULL, NULL, 
                                   NULL, &tcp_header, NULL, &payload, &payload_len, NULL, NULL)) {
        LogDebug("Failed to parse packet", debug_enabled);
        *new_packet_len = packet_len;
        return FALSE;
    }
    
    // Check if it's a TCP packet with payload
    if (!tcp_header || !payload || payload_len == 0) {
        LogDebug("Not a TCP packet with payload", debug_enabled);
        *new_packet_len = packet_len;
        return FALSE;
    }
    
    // Check if source port is 102
    if (ntohs(tcp_header->SrcPort) != 102) {
        if (debug_enabled) {
            sprintf_s(debug_msg, sizeof(debug_msg), "Source port is not 102: %u", (unsigned int)ntohs(tcp_header->SrcPort));
            LogDebug(debug_msg, debug_enabled);
        }
        *new_packet_len = packet_len;
        return FALSE;
    }
    
    // Check if payload is long enough and ends with PRP suffix
    if (payload_len < PRP_TRAILER_LENGTH || !EndsWithPRPSuffix(payload, payload_len)) {
        if (debug_enabled) {
            sprintf_s(debug_msg, sizeof(debug_msg), "No PRP trailer detected (length: %u)", payload_len);
            LogDebug(debug_msg, debug_enabled);
        }
        *new_packet_len = packet_len;
        return FALSE;
    }
    
    // Log packet details
    char info_msg[256];
    sprintf_s(info_msg, sizeof(info_msg), "PRP trailer detected on packet to %u.%u.%u.%u:%u. Stripping %u bytes.",
            (unsigned int)(ip_header->DstAddr & 0xFF),
            (unsigned int)((ip_header->DstAddr >> 8) & 0xFF),
            (unsigned int)((ip_header->DstAddr >> 16) & 0xFF),
            (unsigned int)((ip_header->DstAddr >> 24) & 0xFF),
            (unsigned int)ntohs(tcp_header->DstPort),
            (unsigned int)PRP_TRAILER_LENGTH);
    LogInfo(info_msg);
    
    if (debug_enabled) {
        sprintf_s(debug_msg, sizeof(debug_msg), "Original payload (%u bytes):", payload_len);
        printf("%s ", debug_msg);
        PrintHexDump(payload, payload_len, "");
        printf("PRP trailer: ");
        PrintHexDump(payload + payload_len - PRP_TRAILER_LENGTH, PRP_TRAILER_LENGTH, "");
    }
    
    // Remove the trailer by reducing the payload length (use size_t for x64 consistency)
    size_t new_payload_len = (size_t)payload_len - PRP_TRAILER_LENGTH;
    
    // Calculate header length using proper x64 types
    size_t header_len = (size_t)(payload - packet);
    
    // Validate header length is reasonable
    if (header_len > (size_t)packet_len) {
        LogError("Invalid header length detected, packet corrupted");
        *new_packet_len = packet_len;
        return FALSE;
    }
    
    // Calculate new packet length (header + reduced payload) - all size_t for x64
    size_t new_packet_len_64 = header_len + new_payload_len;
    
    // Validate final packet length fits in UINT (WinDivert API requirement)
    if (new_packet_len_64 > UINT_MAX) {
        LogError("Packet too large after processing");
        *new_packet_len = packet_len;
        return FALSE;
    }
    
    *new_packet_len = (UINT)new_packet_len_64;
    
    // Update IP header length
    if (ip_header) {
        // Validate IP header length fits in u_short
        if (new_packet_len_64 > USHRT_MAX) {
            LogError("Packet too large for IP header length field");
            *new_packet_len = packet_len;
            return FALSE;
        }
        ip_header->Length = htons((u_short)new_packet_len_64);
    }
    
    // Recalculate checksums
    WinDivertHelperCalcChecksums(packet, *new_packet_len, addr, 0);
    
    sprintf_s(info_msg, sizeof(info_msg), "PRP trailer stripped from packet %u.%u.%u.%u:%u",
            (unsigned int)(ip_header->DstAddr & 0xFF),
            (unsigned int)((ip_header->DstAddr >> 8) & 0xFF),
            (unsigned int)((ip_header->DstAddr >> 16) & 0xFF),
            (unsigned int)((ip_header->DstAddr >> 24) & 0xFF),
            (unsigned int)ntohs(tcp_header->DstPort));
    LogInfo(info_msg);
    
    if (debug_enabled) {
        sprintf_s(debug_msg, sizeof(debug_msg), "New payload (%zu bytes):", new_payload_len);
        printf("%s ", debug_msg);
        PrintHexDump(payload, new_payload_len, "");
    }
    
    return TRUE;
}

/**
 * Main function
 */
int main(int argc, char* argv[]) {
    LogInfo("Starting PRP Trailer Remover (Direct WinDivert Implementation)");
    LogInfo("This program will intercept inbound TCP traffic from port 102.");
    LogInfo("Ensure WinDivert driver is installed and run as Administrator.");
    LogInfo("Press Ctrl+C to stop.");
    
    // Parse command line arguments
    BOOL debug_enabled = FALSE;
    if (argc > 1 && strcmp(argv[1], "--debug") == 0) {
        debug_enabled = TRUE;
        LogInfo("Debug mode enabled");
    }
    
    // Register console control handler
    if (!SetConsoleCtrlHandler(ConsoleCtrlHandler, TRUE)) {
        LogError("Could not set console control handler");
    }
    
    // WinDivert filter: inbound TCP packets from port 102 with payload
    const char* filter = "inbound and tcp.SrcPort == 102 and tcp.PayloadLength > 0";
    char info_msg[256];
    sprintf_s(info_msg, sizeof(info_msg), "Using filter: %s", filter);
    LogInfo(info_msg);
    
    // Initialize WinDivert
    HANDLE handle = WinDivertOpen(filter, WINDIVERT_LAYER_NETWORK, 0, 0);
    if (handle == INVALID_HANDLE_VALUE) {
        DWORD error = GetLastError();
        sprintf_s(info_msg, sizeof(info_msg), "Failed to open WinDivert handle. Error: %lu", error);
        LogError(info_msg);
        LogError("Make sure you are running as Administrator and WinDivert driver is installed.");
        return 1;
    }
    
    LogInfo("WinDivert handle opened successfully. Monitoring packets...");
    
    // Set timeout to make the loop responsive to Ctrl+C
    if (!WinDivertSetParam(handle, WINDIVERT_PARAM_QUEUE_TIME, 1000)) {
        LogError("Failed to set queue timeout");
    }
    
    // Packet buffer - using larger buffer to handle jumbo frames
    UINT8 packet[65535];
    UINT packet_len;
    WINDIVERT_ADDRESS addr;
    
    UINT64 packet_count = 0;
    UINT64 modified_count = 0;
    
    // Main processing loop
    while (g_running) {
        // Receive packet with timeout
        if (!WinDivertRecv(handle, packet, sizeof(packet), &packet_len, &addr)) {
            DWORD error = GetLastError();
            if (error == ERROR_INSUFFICIENT_BUFFER) {
                LogError("Packet too large for buffer");
                continue;
            } else if (error == ERROR_NO_DATA) {
                // Timeout - continue loop to check g_running
                continue;
            } else if (g_running) {
                sprintf_s(info_msg, sizeof(info_msg), "Failed to receive packet. Error: %lu", error);
                LogError(info_msg);
            }
            continue;
        }
        
        packet_count++;
        if (debug_enabled) {
            sprintf_s(info_msg, sizeof(info_msg), "Received packet #%llu", packet_count);
            LogDebug(info_msg, debug_enabled);
        }
        
        // Process the packet
        UINT new_packet_len;
        BOOL modified = ProcessPacket(packet, packet_len, &addr, &new_packet_len, debug_enabled);
        
        if (modified) {
            modified_count++;
        }
        
        // Re-inject the (potentially modified) packet
        if (!WinDivertSend(handle, packet, new_packet_len, NULL, &addr)) {
            DWORD error = GetLastError();
            sprintf_s(info_msg, sizeof(info_msg), "Failed to send packet. Error: %lu", error);
            LogError(info_msg);
        }
    }
    
    // Cleanup
    LogInfo("Closing WinDivert handle...");
    
    // Give WinDivert a moment to finish processing any pending packets
    Sleep(100);
    
    if (handle != INVALID_HANDLE_VALUE) {
        WinDivertClose(handle);
        LogInfo("WinDivert handle closed successfully.");
    }
    
    LogInfo("Packet processing stopped.");
    sprintf_s(info_msg, sizeof(info_msg), "Total packets processed: %llu", packet_count);
    LogInfo(info_msg);
    sprintf_s(info_msg, sizeof(info_msg), "Packets with PRP trailers removed: %llu", modified_count);
    LogInfo(info_msg);
    LogInfo("Program terminated.");
    
    // Force exit if cleanup takes too long
    fflush(stdout);
    fflush(stderr);
    
    return 0;
} 