
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
````

Required modules:

```text
github.com/btcsuite/btcd v0.24.0
github.com/btcsuite/btcutil v1.0.3
github.com/google/gopacket v1.1.19
```

---

## Capturing Bitcoin Network Traffic

You need to capture traffic from your Bitcoin node. For Linux:

1. Identify your active network interface:

```bash
ip link
```

2. Capture Bitcoin P2P traffic:

```bash
sudo tcpdump -i <interface> port 8333 -w bitcoin.pcap -s 0
```

* Replace `<interface>` with your active interface (e.g., `enp5s0`).
* `-s 0` ensures full packet capture.
* This will generate a PCAP file (`bitcoin.pcap`) for analysis.

---

## Usage

```bash
go run main.go bitcoin.pcap
```

Output example:

```
===========================================
BITCOIN TX
TXID: 3f1b8c5e3c3d8f4f2b1a0a8b6c5d9e7f123456789abcdef0123456789abcdef0
TX HEX: 02000000000104683806818b30b574e0600...
Outputs:
  [0] Address: bc1pxqkz7... | Value: 1200 sats
  [1] Address: bc1pxqkz7... | Value: 330 sats
  [2] Address: bc1pq33da... | Value: 45314 sats
===========================================
```

---

## How It Works

1. **Read PCAP file** using `gopacket`.
2. **Filter TCP packets** on Bitcoin mainnet port 8333.
3. **Reassemble TCP streams** per connection to reconstruct full Bitcoin messages.
4. **Parse P2P messages**, detecting `tx` commands.
5. **Deserialize transactions** (`btcd/wire.MsgTx`) to extract:

   * Transaction ID (TXID)
   * Output addresses and values
   * Raw transaction hex
6. **Print each transaction** clearly separated for readability.

---

## Functions Overview

* `parseTx(b []byte)`: Deserializes a transaction, prints TXID, hex, and outputs.
* `extractAddresses(pkScript []byte)`: Extracts receiving addresses from output scripts.
* `processStream(stream []byte)`: Processes TCP stream data, extracts Bitcoin messages.
* TCP reassembly is done per connection (`srcIP:srcPort-dstIP:dstPort`) to handle split packets.

---

## Notes

* Only works on **Bitcoin mainnet (port 8333)** by default.

