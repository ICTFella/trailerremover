# PRP Trailer Remover

A high-performance network tool that removes PRP (Parallel Redundancy Protocol) trailers from TCP packets on Windows using [WinDivert](https://github.com/basil00/WinDivert).

## Overview

This tool intercepts inbound TCP traffic from port 102 and removes 6-byte PRP trailers that end with the suffix `0x88FB`. It's designed for industrial networking environments that need to strip PRP redundancy information from network packets.

## Features

- **High Performance**: Native C implementation using WinDivert directly
- **Real-time Processing**: Intercepts and modifies packets in real-time
- **Debug Mode**: Detailed packet analysis and hex dumps
- **Graceful Shutdown**: Proper Ctrl+C handling with force-exit option
- **Production Ready**: Comprehensive error handling and logging

## Requirements

- Windows 7/8/10/11 (64-bit)
- Administrator privileges
- Visual Studio Build Tools or MinGW compiler
- WinDivert 2.2.2-A (included as dependency)

## Installation

1. **Download WinDivert**: Download [WinDivert 2.2.2-A](https://github.com/basil00/WinDivert/releases) and extract to `WinDivert-2.2.2-A/` folder
2. **Build**: Run `build.bat` to compile
3. **Copy DLL**: Copy `WinDivert.dll` from `WinDivert-2.2.2-A\x64\` to the project directory

## Usage

### Basic Mode
```cmd
# Run as Administrator
.\trailerremover.exe
```

### Debug Mode
```cmd
# Run with detailed logging
.\trailerremover.exe --debug
```

### Shutdown
- **Graceful**: Press `Ctrl+C` once and wait for cleanup
- **Force Exit**: Press `Ctrl+C` twice if cleanup hangs

## Implementation

### C Version (Recommended)
- **File**: `trailerremover.c`
- **Performance**: 10-100x faster than Python
- **Deployment**: Single executable with DLL dependency
- **Build**: Use `build.bat` script

### Python Version (Legacy)
- **Location**: `Python version/` folder
- **Dependencies**: Python 3.7+, pydivert, scapy
- **Use Case**: Testing and development

## Network Filter

The tool uses this WinDivert filter:
```
inbound and tcp.SrcPort == 102 and tcp.PayloadLength > 0
```

This captures:
- **Inbound** TCP packets only
- **Source port 102** (typical for industrial protocols)
- **Non-empty payload** (ignores ACKs, etc.)

## PRP Trailer Detection

Packets are processed if they:
1. Have payload length ≥ 6 bytes
2. End with PRP suffix: `0x88FB`
3. Come from source port 102

The last 6 bytes are stripped and checksums recalculated.

## Testing

Use `test_packet_sender.py` on a Linux machine to send test packets:
```bash
python3 test_packet_sender.py
```

## Dependencies

- **WinDivert 2.2.2-A**: Network packet interception ([basil00/WinDivert](https://github.com/basil00/WinDivert))
- **Windows SDK**: For `ws2_32.lib` (networking functions)

## Build Requirements

### Visual Studio
- Visual Studio Build Tools
- Windows 10/11 SDK
- MSVC compiler

### MinGW (Alternative)
- MinGW-w64
- GCC compiler

## License

GPL-3.0 License - see LICENSE file for details.

## Author

Created for industrial network environments requiring PRP trailer removal.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch  
5. Create a Pull Request 