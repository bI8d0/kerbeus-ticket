# Kerbeus-Ticket

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Go Version](https://img.shields.io/badge/Go-1.24+-blue.svg)](https://golang.org/)
[![Platform](https://img.shields.io/badge/Platform-Linux-green.svg)](https://www.kernel.org/)

```
  ╔═══════════════════════════════════════════════════════════════╗
  ║                                                               ║
  ║   ██╗  ██╗███████╗██████╗ ██████╗ ███████╗██╗   ██╗███████╗   ║
  ║   ██║ ██╔╝██╔════╝██╔══██╗██╔══██╗██╔════╝██║   ██║██╔════╝   ║
  ║   █████╔╝ █████╗  ██████╔╝██████╔╝█████╗  ██║   ██║███████╗   ║
  ║   ██╔═██╗ ██╔══╝  ██╔══██╗██╔══██╗██╔══╝  ██║   ██║╚════██║   ║
  ║   ██║  ██╗███████╗██║  ██║██████╔╝███████╗╚██████╔╝███████║   ║
  ║   ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═════╝ ╚══════╝ ╚═════╝ ╚══════╝   ║
  ║                                                               ║
  ║           Kerberos ticket TGT ccache Generator v1.0           ║
  ║                           By bI8d0                            ║
  ╚═══════════════════════════════════════════════════════════════╝
```

A lightweight command-line tool written in Go that generates Kerberos TGT (Ticket Granting Ticket) ccache files from user credentials. Useful for penetration testing, red team operations, and Kerberos authentication scenarios.

## Features

- 🔐 Generate MIT Kerberos ccache files from domain credentials
- 🚀 Standalone binary with no external dependencies
- 🐧 Native Linux support
- 📦 Compatible with standard Kerberos tools (kinit, klist, etc.)
- 🔧 Works with popular security tools (NetExec, Impacket, etc.)

## Installation

### From Source

```bash
# Clone the repository
git clone https://github.com/yourusername/kerbeus-ticket.git
cd kerbeus-ticket

# Build the binary
go build -o kerbeus-ticket main.go

# Or use the build script
go run build.go
```

### Requirements

- Go 1.20 or higher
- Linux operating system

## Usage

```bash
./kerbeus-ticket -host <kdc_host> -domain <domain> -user <username> -pass <password> [-o <output_dir>]
```

### Parameters

| Parameter | Description | Required |
|-----------|-------------|----------|
| `-host` | IP address or hostname of the KDC server | Yes |
| `-domain` | Kerberos domain/realm name | Yes |
| `-user` | Username for authentication | Yes |
| `-pass` | Password for authentication | Yes |
| `-o` | Output directory for ccache file (default: `./ccache`) | No |

### Examples

**Basic usage:**
```bash
./kerbeus-ticket -host 192.168.1.10 -domain CORP.LOCAL -user administrator -pass 'P@ssw0rd!'
```

**Specify custom output directory:**
```bash
./kerbeus-ticket -host dc01.corp.local -domain CORP.LOCAL -user john.doe -pass 'MyPassword123' -o /tmp/tickets
```

**Use the generated ticket:**
```bash
# Export the ccache file path
export KRB5CCNAME=/path/to/ccache/username.ccache

# Use with NetExec
nxc ldap 192.168.1.10 -u administrator -k --use-kcache

# Use with Impacket tools
secretsdump.py -k -no-pass CORP.LOCAL/administrator@dc01.corp.local
```

## Output

The tool generates a ccache file in MIT Kerberos format (version 0x0504) that can be used with:

- **klist** - View ticket contents
- **NetExec (nxc)** - Network authentication
- **Impacket** - Python security tools
- **Any Kerberos-aware application**

## How It Works

1. Connects to the specified KDC server on port 88
2. Performs AS-REQ/AS-REP exchange with provided credentials
3. Extracts the TGT and session key from the response
4. Builds a MIT-compatible ccache file
5. Saves the ccache to the specified output directory

## Supported Encryption Types

- AES256-CTS-HMAC-SHA1-96
- AES128-CTS-HMAC-SHA1-96
- RC4-HMAC

## Security Considerations

⚠️ **Warning:** This tool is intended for authorized security testing and educational purposes only.

- Never use this tool against systems without explicit permission
- Credentials are transmitted over the network to the KDC
- Generated ccache files contain sensitive authentication material
- Store ccache files securely and delete them after use

## Dependencies

This project uses the following Go libraries:

- [gokrb5](https://github.com/jcmturner/gokrb5) - Pure Go Kerberos library

## Building for Different Architectures

```bash
# Linux AMD64
GOOS=linux GOARCH=amd64 go build -o kerbeus-ticket-linux-amd64 main.go

# Linux ARM64
GOOS=linux GOARCH=arm64 go build -o kerbeus-ticket-linux-arm64 main.go
```

## Troubleshooting

### Common Issues

**"error in AS Exchange"**
- Verify the KDC host is reachable on port 88
- Check that the domain name is correct
- Ensure credentials are valid

**"error creating directory"**
- Check write permissions for the output directory

**Connection timeout**
- Verify network connectivity to the KDC
- Check firewall rules allowing port 88/TCP

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Author

**bI8d0**

## Acknowledgments

- [jcmturner/gokrb5](https://github.com/jcmturner/gokrb5) for the excellent Kerberos library
- The security research community for inspiration and feedback

---

<p align="center">
  Made with ❤️ for the security community
</p>

