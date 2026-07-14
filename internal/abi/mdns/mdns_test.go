package mdns

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net/netip"
	"testing"

	abicore "github.com/wago-org/net/internal/abi/core"
	mdnsns "github.com/wago-org/net/internal/namespace/mdns"
)

func TestCheckedQueryAnnouncementAndAtomicRecords(t *testing.T) {
	memory := make([]byte, 1400)
	request := mdnsns.Request{Name: "_demo._udp.local", Types: mdnsns.RecordsPTR | mdnsns.RecordsSRV}
	if !EncodeQueryV1(memory, 0, request) {
		t.Fatal("encode query")
	}
	if decoded, ok := DecodeQueryV1(memory, 0); !ok || decoded != request {
		t.Fatalf("decode query = %+v, %v", decoded, ok)
	}
	if CheckQueryV1(memory, 0, 264) || !CheckQueryV1(memory, 0, 300) {
		t.Fatal("query range overlap validation failed")
	}
	if !EncodeAnnouncementV1(memory, 600, 7) {
		t.Fatal("encode announcement")
	}
	if service, ok := DecodeAnnouncementV1(memory, 600); !ok || service != 7 {
		t.Fatalf("decode announcement = %d, %v", service, ok)
	}

	records := []mdnsns.Record{
		{Name: "device.local", Type: mdnsns.RecordA, TTLSeconds: 120, Address: netip.MustParseAddr("192.0.2.2"), CacheFlush: true},
		{Name: "_demo._udp.local", Type: mdnsns.RecordPTR, TTLSeconds: 120, Target: "device._demo._udp.local"},
		{Name: "device._demo._udp.local", Type: mdnsns.RecordSRV, TTLSeconds: 120, Target: "device.local", Port: 9000},
		{Name: "device._demo._udp.local", Type: mdnsns.RecordTXT, TTLSeconds: 120, TXTLength: 4},
	}
	copy(records[3].TXT[:], []byte{3, 'k', '=', 'v'})
	for _, record := range records {
		before := bytes.Repeat([]byte{0xa5}, int(RecordV1Size))
		copy(memory[0:RecordV1Size], before)
		if !EncodeRecordV1(memory, 0, record) || bytes.Equal(memory[0:RecordV1Size], before) {
			t.Fatalf("record encode failed: %+v", record)
		}
	}
	before := append([]byte(nil), memory...)
	if EncodeRecordV1(memory, uint32(len(memory))-RecordV1Size+1, records[0]) || !bytes.Equal(before, memory) {
		t.Fatal("short record output mutated memory")
	}
}

func TestQueryAndNameLayoutsRejectMalformedInput(t *testing.T) {
	request := mdnsns.Request{Name: "_demo._udp.local", Types: mdnsns.RecordsPTR | mdnsns.RecordsSRV}
	memory := bytes.Repeat([]byte{0xa5}, int(QueryV1Size)+2)
	if !EncodeQueryV1(memory, 1, request) {
		t.Fatal("encode query")
	}
	if memory[0] != 0xa5 || memory[len(memory)-1] != 0xa5 {
		t.Fatal("query encode mutated guard bytes")
	}
	encoded := memory[1 : 1+QueryV1Size]
	if got := binary.LittleEndian.Uint16(encoded[0:2]); got != uint16(len(request.Name)) || binary.LittleEndian.Uint16(encoded[2:4]) != 0 {
		t.Fatalf("name header = %d, %#x", got, binary.LittleEndian.Uint16(encoded[2:4]))
	}
	if string(encoded[nameBytesOffset:nameBytesOffset+len(request.Name)]) != request.Name {
		t.Fatalf("name bytes = %q", encoded[nameBytesOffset:nameBytesOffset+len(request.Name)])
	}
	if !allZero(encoded[nameBytesOffset+len(request.Name) : NameV1Size]) {
		t.Fatal("query name padding was not zero")
	}
	if got := binary.LittleEndian.Uint32(encoded[queryTypesOffset : queryTypesOffset+4]); got != uint32(request.Types) {
		t.Fatalf("query types = %#x", got)
	}
	if binary.LittleEndian.Uint32(encoded[queryReserved:queryReserved+4]) != 0 {
		t.Fatal("query reserved field was not zero")
	}
	if decoded, ok := DecodeNameV1(encoded, 0); !ok || decoded != request.Name {
		t.Fatalf("decode name = %q, %v", decoded, ok)
	}

	base := append([]byte(nil), encoded...)
	for _, test := range []struct {
		name   string
		mutate func([]byte)
	}{
		{name: "zero length", mutate: func(b []byte) { binary.LittleEndian.PutUint16(b[0:2], 0) }},
		{name: "oversize length", mutate: func(b []byte) { binary.LittleEndian.PutUint16(b[0:2], nameBytesCapacity+1) }},
		{name: "name reserved", mutate: func(b []byte) { b[2] = 1 }},
		{name: "noncanonical", mutate: func(b []byte) { b[nameBytesOffset] = '_' + 1 }},
		{name: "nonzero padding", mutate: func(b []byte) { b[nameBytesOffset+len(request.Name)] = 1 }},
		{name: "zero types", mutate: func(b []byte) { binary.LittleEndian.PutUint32(b[queryTypesOffset:queryTypesOffset+4], 0) }},
		{name: "unknown types", mutate: func(b []byte) { binary.LittleEndian.PutUint32(b[queryTypesOffset:queryTypesOffset+4], 1<<31) }},
		{name: "query reserved", mutate: func(b []byte) { b[queryReserved] = 1 }},
	} {
		t.Run(test.name, func(t *testing.T) {
			malformed := append([]byte(nil), base...)
			test.mutate(malformed)
			if _, ok := DecodeQueryV1(malformed, 0); ok {
				t.Fatal("malformed query accepted")
			}
		})
	}

	before := append([]byte(nil), memory...)
	if EncodeQueryV1(memory, ^uint32(0)-QueryV1Size+1, request) || !bytes.Equal(memory, before) {
		t.Fatal("overflowing query output mutated memory")
	}
	if _, ok := DecodeNameV1(base, ^uint32(0)-NameV1Size+1); ok {
		t.Fatal("overflowing name range accepted")
	}
	if CheckQueryV1(make([]byte, 1024), ^uint32(0)-QueryV1Size+1, 0) {
		t.Fatal("overflowing query range accepted")
	}
}

func TestRecordV1CompleteTypeLayoutsAndAtomicFailures(t *testing.T) {
	records := []mdnsns.Record{
		{Name: "host.local", Type: mdnsns.RecordA, TTLSeconds: 120, Address: netip.MustParseAddr("192.0.2.9"), CacheFlush: true},
		{Name: "_demo._udp.local", Type: mdnsns.RecordPTR, TTLSeconds: 121, Target: "host._demo._udp.local"},
		{Name: "host._demo._udp.local", Type: mdnsns.RecordSRV, TTLSeconds: 122, Target: "host.local", Port: 8080, Priority: 3, Weight: 7, CacheFlush: true},
		{Name: "host._demo._udp.local", Type: mdnsns.RecordTXT, TTLSeconds: 123, TXTLength: 5},
	}
	copy(records[3].TXT[:], []byte{4, 'k', '=', 'v', '1'})
	for _, record := range records {
		t.Run(fmt.Sprintf("type-%d", record.Type), func(t *testing.T) {
			memory := bytes.Repeat([]byte{0x6b}, int(RecordV1Size)+2)
			if !EncodeRecordV1(memory, 1, record) {
				t.Fatal("encode record")
			}
			if memory[0] != 0x6b || memory[len(memory)-1] != 0x6b {
				t.Fatal("record encode mutated guard bytes")
			}
			encoded := memory[1 : 1+RecordV1Size]
			if name, ok := DecodeNameV1(encoded, 0); !ok || name != record.Name {
				t.Fatalf("record name = %q, %v", name, ok)
			}
			if got := binary.LittleEndian.Uint32(encoded[recordTTLOffset : recordTTLOffset+4]); got != record.TTLSeconds {
				t.Fatalf("TTL = %d", got)
			}
			flags := binary.LittleEndian.Uint32(encoded[recordFlags : recordFlags+4])
			if flags != map[bool]uint32{false: 0, true: RecordFlagCacheFlush}[record.CacheFlush] || !allZero(encoded[recordReserved:]) {
				t.Fatalf("flags/reserved = %#x, %x", flags, encoded[recordReserved:])
			}
			switch record.Type {
			case mdnsns.RecordA:
				if got := binary.LittleEndian.Uint32(encoded[recordTypeOffset : recordTypeOffset+4]); got != RecordTypeA {
					t.Fatalf("type = %d", got)
				}
				endpoint, ok := decodeRecordAddress(encoded)
				if !ok || endpoint != record.Address || !allZero(encoded[recordTarget:recordFlags]) {
					t.Fatalf("A payload = %v, %v, unused=%x", endpoint, ok, encoded[recordTarget:recordFlags])
				}
			case mdnsns.RecordPTR:
				if got := binary.LittleEndian.Uint32(encoded[recordTypeOffset : recordTypeOffset+4]); got != RecordTypePTR || !allZero(encoded[recordAddress:recordTarget]) {
					t.Fatalf("PTR type/address = %d, %x", got, encoded[recordAddress:recordTarget])
				}
				if target, ok := DecodeNameV1(encoded, recordTarget); !ok || target != record.Target || !allZero(encoded[recordPort:recordFlags]) {
					t.Fatalf("PTR target = %q, %v, unused=%x", target, ok, encoded[recordPort:recordFlags])
				}
			case mdnsns.RecordSRV:
				if got := binary.LittleEndian.Uint32(encoded[recordTypeOffset : recordTypeOffset+4]); got != RecordTypeSRV || !allZero(encoded[recordAddress:recordTarget]) {
					t.Fatalf("SRV type/address = %d, %x", got, encoded[recordAddress:recordTarget])
				}
				if target, ok := DecodeNameV1(encoded, recordTarget); !ok || target != record.Target {
					t.Fatalf("SRV target = %q, %v", target, ok)
				}
				if binary.LittleEndian.Uint16(encoded[recordPort:recordPort+2]) != record.Port || binary.LittleEndian.Uint16(encoded[recordPriority:recordPriority+2]) != record.Priority || binary.LittleEndian.Uint16(encoded[recordWeight:recordWeight+2]) != record.Weight || !allZero(encoded[recordTXTLength:recordFlags]) {
					t.Fatalf("SRV numeric/unused = %x", encoded[recordPort:recordFlags])
				}
			case mdnsns.RecordTXT:
				if got := binary.LittleEndian.Uint32(encoded[recordTypeOffset : recordTypeOffset+4]); got != RecordTypeTXT || !allZero(encoded[recordAddress:recordTXTLength]) {
					t.Fatalf("TXT type/unused = %d, %x", got, encoded[recordAddress:recordTXTLength])
				}
				if got := binary.LittleEndian.Uint16(encoded[recordTXTLength : recordTXTLength+2]); got != record.TXTLength || !bytes.Equal(encoded[recordTXT:recordTXT+int(record.TXTLength)], record.TXT[:record.TXTLength]) || !allZero(encoded[recordTXT+int(record.TXTLength):recordFlags]) {
					t.Fatalf("TXT payload = %x", encoded[recordTXT:recordFlags])
				}
			}
		})
	}

	memory := bytes.Repeat([]byte{0xa5}, int(RecordV1Size))
	before := append([]byte(nil), memory...)
	invalid := records[0]
	invalid.TTLSeconds = 0
	if EncodeRecordV1(memory, 0, invalid) || !bytes.Equal(memory, before) {
		t.Fatal("invalid record mutated output")
	}
	if EncodeRecordV1(memory, ^uint32(0)-RecordV1Size+1, records[0]) || !bytes.Equal(memory, before) {
		t.Fatal("overflowing record output mutated memory")
	}
}

func FuzzEncodeRecordV1Atomic(f *testing.F) {
	f.Add(uint8(0), uint32(120), uint32(0), uint8(0), []byte("txt"))
	f.Add(uint8(2), uint32(1), ^uint32(0), uint8(0), []byte{})
	f.Add(uint8(3), uint32(0), uint32(1), uint8(7), bytes.Repeat([]byte{0xff}, mdnsns.MaxTXTBytes+1))
	f.Fuzz(func(t *testing.T, kind uint8, ttl, ptr uint32, invalid uint8, txt []byte) {
		record := mdnsns.Record{Name: "host.local", TTLSeconds: ttl, CacheFlush: kind&1 != 0}
		switch kind % 4 {
		case 0:
			record.Type = mdnsns.RecordA
			record.Address = netip.MustParseAddr("192.0.2.9")
		case 1:
			record.Type = mdnsns.RecordPTR
			record.Target = "host._demo._udp.local"
		case 2:
			record.Type = mdnsns.RecordSRV
			record.Target, record.Port, record.Priority, record.Weight = "host.local", 8080, uint16(kind), uint16(ttl)
		case 3:
			record.Type = mdnsns.RecordTXT
			record.TXTLength = uint16(min(len(txt), mdnsns.MaxTXTBytes))
			copy(record.TXT[:], txt[:record.TXTLength])
		}
		switch invalid % 9 {
		case 1:
			record.Name = ""
		case 2:
			record.TTLSeconds = 0
		case 3:
			record.Address = netip.Addr{}
		case 4:
			record.Target = "unused.local"
		case 5:
			record.Target = "not-local.example"
		case 6:
			record.Port = 0
		case 7:
			record.TXTLength = mdnsns.MaxTXTBytes + 1
		case 8:
			record.Type = 0xff
		}
		memory := bytes.Repeat([]byte{kind ^ invalid ^ 0xa5}, 900)
		before := append([]byte(nil), memory...)
		ok := EncodeRecordV1(memory, ptr, record)
		want := record.Valid() && uint64(ptr)+uint64(RecordV1Size) <= uint64(len(memory))
		if ok != want {
			t.Fatalf("encode = %v, want %v; record=%+v ptr=%d", ok, want, record, ptr)
		}
		if !ok {
			if !bytes.Equal(memory, before) {
				t.Fatal("failed encode mutated memory")
			}
			return
		}
		if !bytes.Equal(memory[:ptr], before[:ptr]) || !bytes.Equal(memory[ptr+RecordV1Size:], before[ptr+RecordV1Size:]) {
			t.Fatal("successful encode mutated outside output")
		}
	})
}

func decodeRecordAddress(encoded []byte) (netip.Addr, bool) {
	endpoint, ok := abicore.DecodeEndpointV1(encoded, recordAddress)
	return endpoint.Address, ok && endpoint.Port == 0 && endpoint.ScopeID == 0 && endpoint.FlowInfo == 0
}

func allZero(data []byte) bool {
	for _, value := range data {
		if value != 0 {
			return false
		}
	}
	return true
}
