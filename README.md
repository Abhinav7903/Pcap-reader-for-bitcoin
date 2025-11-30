# Bitcoin PCAP Transaction Parser

This Go program reads Bitcoin P2P network traffic from a PCAP file, extracts transactions (`tx` messages), and prints detailed information about each transaction including:

- **Transaction ID (TXID)**
- **Raw transaction hex**
- **Output addresses and their satoshi values**

---

## Features

- Reads `.pcap` files captured from Bitcoin mainnet traffic.
- Reassembles TCP streams to handle transactions split across multiple packets.
- Parses Bitcoin P2P messages to extract transaction data.
- Supports SegWit and legacy transaction outputs.
- Prints transactions with clear separation for readability.

---

## Requirements

- Go 1.20+
- Bitcoin PCAP file (`.pcap`) captured from port `8333`.
- `btcd` and `gopacket` libraries.

### Go Modules

```bash
go mod tidy
