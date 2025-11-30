package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"
	"os"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)	

func main() {
	if len(os.Args) < 2 {
		log.Fatal("Usage: go run main.go <file.pcap>")
	}

	file := os.Args[1]
	handle, err := pcap.OpenOffline(file)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	streams := make(map[string][]byte)

	for pkt := range packetSource.Packets() {
		tcpLayer := pkt.Layer(layers.LayerTypeTCP)
		if tcpLayer == nil {
			continue
		}

		tcp := tcpLayer.(*layers.TCP)
		if tcp.SrcPort != 8333 && tcp.DstPort != 8333 {
			continue
		}

		if len(tcp.Payload) == 0 {
			continue
		}

		// Identify connection by srcIP:srcPort-dstIP:dstPort
		netLayer := pkt.NetworkLayer()
		if netLayer == nil {
			continue
		}
		src := netLayer.NetworkFlow().Src().String()
		dst := netLayer.NetworkFlow().Dst().String()
		connKey := fmt.Sprintf("%s:%d-%s:%d", src, tcp.SrcPort, dst, tcp.DstPort)

		// Append payload to the stream for this connection
		streams[connKey] = append(streams[connKey], tcp.Payload...)
	}

	// Process all streams
	for _, data := range streams {
		processStream(data)
	}
}

func processStream(stream []byte) {
	buffer := stream

	for {
		if len(buffer) < 24 { // Minimum Bitcoin message header
			break
		}

		// Bitcoin magic bytes + command
		command := string(bytes.Trim(buffer[4:16], "\x00"))
		msgLen := binary.LittleEndian.Uint32(buffer[16:20])
		fullLen := int(24 + msgLen)

		if len(buffer) < fullLen {
			break // wait for more data (or ignore incomplete message)
		}

		payload := buffer[24:fullLen]

		if command == "tx" {
			parseTx(payload)
		}

		buffer = buffer[fullLen:]
	}
}

func parseTx(b []byte) {
	var tx wire.MsgTx
	err := tx.Deserialize(bytes.NewReader(b))
	if err != nil {
		return
	}

	// Compute TXID
	txHash := tx.TxHash() // excludes witness
	fmt.Println("===========================================")
	fmt.Println("BITCOIN TX")
	fmt.Println("TXID:", txHash.String())
	fmt.Println("TX HEX:", hex.EncodeToString(b))
	fmt.Println("Outputs:")

	for i, out := range tx.TxOut {
		addresses, err := extractAddresses(out.PkScript)
		if err == nil && len(addresses) > 0 {
			for _, addr := range addresses {
				fmt.Printf("  [%d] Address: %s | Value: %d sats\n", i, addr, out.Value)
			}
		} else {
			fmt.Printf("  [%d] Unparseable or unknown script | Value: %d sats\n", i, out.Value)
		}
	}

	fmt.Println("===========================================\n")
}

func extractAddresses(pkScript []byte) ([]string, error) {
	_, addrs, _, err := txscript.ExtractPkScriptAddrs(pkScript, &chaincfg.MainNetParams)
	if err != nil {
		return nil, err
	}
	list := []string{}
	for _, a := range addrs {
		list = append(list, a.EncodeAddress())
	}
	return list, nil
}
