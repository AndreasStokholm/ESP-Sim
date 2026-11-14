// Command golden runs the upstream Go DASH pod simulator's own code on
// fixed inputs and prints the results as a C header, so the C port can be
// checked byte for byte against the implementation it was ported from.
//
// Usage: tools/golden/gen.sh  (writes test/host/golden_dash.h)
package main

import (
	"bytes"
	"crypto/aes"
	"encoding/binary"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/avereha/pod/pkg/bluetooth"
	"github.com/avereha/pod/pkg/command"
	"github.com/avereha/pod/pkg/eap"
	"github.com/avereha/pod/pkg/encrypt"
	"github.com/avereha/pod/pkg/message"
	"github.com/avereha/pod/pkg/pair"
	"github.com/avereha/pod/pkg/response"

	"github.com/jacobsa/crypto/cmac"
	aesccm "github.com/pschlump/AesCCM"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/curve25519"
)

var out strings.Builder

func arr(name string, b []byte) {
	fmt.Fprintf(&out, "static const uint8_t %s[%d] = {", name, len(b))
	for i, v := range b {
		if i%16 == 0 {
			out.WriteString("\n    ")
		}
		fmt.Fprintf(&out, "0x%02x,", v)
	}
	out.WriteString("\n};\n")
}

func num(name string, v uint64) { fmt.Fprintf(&out, "#define %s %dULL\n", name, v) }

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func seqBytes(n int, start byte) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = start + byte(i)
	}
	return b
}

func lv(name string, v []byte) []byte {
	b := []byte(name)
	b = append(b, byte(len(v)>>8), byte(len(v)))
	return append(b, v...)
}

func cmacOf(key, data []byte) []byte {
	h, err := cmac.New(key)
	must(err)
	h.Write(data)
	return h.Sum(nil)
}

// ---- pairing ----------------------------------------------------------

func goldenPair() []byte {
	podID := []byte{0xff, 0xff, 0xff, 0xfe}
	pdmID := []byte{0x00, 0x00, 0x10, 0x24}
	pdmPriv := seqBytes(32, 0x41)
	pdmPub, err := curve25519.X25519(pdmPriv, curve25519.Basepoint)
	must(err)
	pdmNonce := seqBytes(16, 0x90)

	p := &pair.Pair{}
	m := message.NewMessage(message.MessageTypePairing, pdmID, podID)
	m.Payload = append(lv("SP1=", []byte{0, 0, 0x10, 0x24}), lv(",SP2=", []byte{0, 0, 0, 0x0a})...)
	must(p.ParseSP1SP2(m))

	m = message.NewMessage(message.MessageTypePairing, pdmID, podID)
	m.Payload = lv("SPS1=", append(append([]byte{}, pdmPub...), pdmNonce...))
	must(p.ParseSPS1(m))
	sps1, err := p.GenerateSPS1()
	must(err)

	// The PDM's confirmation value, derived the way the phone does.
	podPub := sps1.Payload[7 : 7+32]
	podNonce := sps1.Payload[7+32 : 7+48]
	shared, err := curve25519.X25519(make([]byte, 32), pdmPub) // pod private key is all zero (clamped)
	_ = shared
	podPrivClamped := make([]byte, 32)
	podPrivClamped[31] = 64
	shared, err = curve25519.X25519(podPrivClamped, pdmPub)
	must(err)
	first := append(append(append(append([]byte{}, podPub[28:]...), pdmPub[28:]...), podNonce[12:]...), pdmNonce[12:]...)
	inter := cmacOf(first, shared)
	bb := append(append(append([]byte{0x01}, "TWIt"...), podNonce...), pdmNonce...)
	bb = append(bb, 0, 1)
	confKey := cmacOf(inter, bb)
	pdmConf := cmacOf(confKey, append(append([]byte("KC_2_U"), pdmNonce...), podNonce...))

	m = message.NewMessage(message.MessageTypePairing, pdmID, podID)
	m.Payload = lv("SPS2=", pdmConf)
	must(p.ParseSPS2(m)) // proves pdmConf above is what the pod expects
	sps2, err := p.GenerateSPS2()
	must(err)
	p0, err := p.GenerateP0()
	must(err)
	ltk, err := p.LTK()
	must(err)

	arr("G_PAIR_POD_ID", podID)
	arr("G_PAIR_PDM_ID", pdmID)
	arr("G_PAIR_PDM_PUB", pdmPub)
	arr("G_PAIR_PDM_NONCE", pdmNonce)
	arr("G_PAIR_PDM_CONF", pdmConf)
	sps1Raw, _ := sps1.Marshal()
	sps2Raw, _ := sps2.Marshal()
	p0Raw, _ := p0.Marshal()
	arr("G_PAIR_SPS1_RAW", sps1Raw)
	arr("G_PAIR_SPS2_RAW", sps2Raw)
	arr("G_PAIR_P0_RAW", p0Raw)
	arr("G_PAIR_LTK", ltk)
	return ltk
}

// ---- EAP-AKA ------------------------------------------------------------

func goldenEap(ltk []byte) ([]byte, []byte) {
	rnd := seqBytes(16, 0x20)
	autn := seqBytes(16, 0x60)
	pdmIV := []byte{0x11, 0x22, 0x33, 0x44}
	req := []byte{1, 0x2a, 0, 0, 0x17, 1, 0, 0}
	req = append(req, 1, 5, 0, 0)
	req = append(req, rnd...)
	req = append(req, 2, 5, 0, 0)
	req = append(req, autn...)
	req = append(req, 126, 2, 0, 0)
	req = append(req, pdmIV...)
	req[3] = byte(len(req))

	const sqn = 6
	s := eap.NewEapAkaChallenge(ltk, sqn)
	m := message.NewMessage(message.MessageTypeSessionEstablishment, []byte{0, 0, 0x10, 0x24}, []byte{0xff, 0xff, 0xff, 0xfe})
	m.Payload = req
	reqRaw, _ := m.Marshal()
	m2, err := message.Unmarshal(reqRaw)
	must(err)
	must(s.ParseChallenge(m2))
	rsp, err := s.GenerateChallengeResponse()
	must(err)
	parsed, err := eap.Unmarshal(rsp.Payload)
	must(err)
	ck, nonce := s.CKNoncePrefix()

	arr("G_EAP_REQ_RAW", reqRaw)
	num("G_EAP_SQN_IN", sqn)
	num("G_EAP_SQN_OUT", s.Sqn)
	arr("G_EAP_RES", parsed.Attributes[eap.AT_RES].Data)
	arr("G_EAP_POD_IV", parsed.Attributes[eap.AT_CUSTOM_IV].Data)
	fmt.Fprintf(&out, "#define G_EAP_RSP_IDENTIFIER 0x%02x\n", parsed.Identifier)
	fmt.Fprintf(&out, "#define G_EAP_RSP_LEN %d\n", len(rsp.Payload))
	arr("G_EAP_CK", ck)
	arr("G_EAP_NONCE_PREFIX", nonce)
	return ck, nonce
}

// ---- command/response session ------------------------------------------

func cmdPayload(id []byte, seq uint8, body []byte) []byte {
	inner := append([]byte{}, id...)
	lsf := uint16(seq&0xf)<<10 | uint16(len(body))
	inner = append(inner, byte(lsf>>8), byte(lsf))
	inner = append(inner, body...)
	inner = append(inner, 0, 0) // crc (unchecked)
	p := []byte("S0.0=")
	p = append(p, byte(len(inner)>>8), byte(len(inner)))
	p = append(p, inner...)
	return append(p, ",G0.0"...)
}

// phoneEncrypt is what the phone sends: the nonce's direction bit clear.
func phoneEncrypt(ck, prefix []byte, seq uint64, m *message.Message) []byte {
	raw, _ := m.Marshal()
	nonce := append(append([]byte{}, prefix...), byte(seq>>32)&127, byte(seq>>24), byte(seq>>16), byte(seq>>8), byte(seq))
	blk, _ := aes.NewCipher(ck)
	c, _ := aesccm.NewCCM(blk, 8, len(nonce))
	return append(append([]byte{}, raw[:16]...), c.Seal(nil, nonce, raw[16:], raw[:16])...)
}

func goldenCrypto(ck, prefix []byte) {
	// A phone command, as the pod receives and decrypts it.
	m := message.NewMessage(message.MessageTypeEncrypted, []byte{0, 0, 0x10, 0x24}, []byte{0xff, 0xff, 0xff, 0xfe})
	m.SequenceNumber = 2
	m.Payload = cmdPayload([]byte{0xff, 0xff, 0xff, 0xfe}, 0, []byte{0x07, 0x04, 0x00, 0x00, 0x10, 0x24})
	raw := phoneEncrypt(ck, prefix, 1, m)
	arr("G_CMD_GETVERSION_ENC", raw)
	arr("G_CMD_GETVERSION_PLAIN", m.Payload)
	got, err := message.Unmarshal(raw)
	must(err)
	got, err = encrypt.DecryptMessage(ck, prefix, 1, got)
	must(err)
	if !bytes.Equal(got.Payload, m.Payload) {
		panic("decrypt mismatch")
	}

	// The pod's version response to it, encrypted at nonce seq 2.
	cmd, err := command.Unmarshal(got.Payload)
	must(err)
	rsp, err := cmd.GetResponse()
	must(err)
	_, reqID, _ := cmd.GetHeaderData()
	rm, err := response.Marshal(rsp, &response.ResponseMetadata{
		Dst: got.Source, Src: got.Destination, CmdSeq: 1, MsgSeq: 2, RequestID: reqID, AckSeq: 3,
	})
	must(err)
	plain, _ := rm.Marshal()
	arr("G_RSP_VERSION_PLAIN", plain)
	enc, err := encrypt.EncryptMessage(ck, prefix, 2, rm)
	must(err)
	arr("G_RSP_VERSION_ENC", enc.Raw)
}

// ---- status responses ------------------------------------------------------

func goldenResponses() {
	type gs = response.GeneralStatusResponse
	cases := []struct {
		name string
		r    response.Response
	}{
		{"G_RSP_GENERAL_DEFAULT", &gs{}},
		{"G_RSP_GENERAL_RUNNING", &gs{Alerts: 0x82, BolusActive: true, BasalActive: true, PodProgress: 8,
			Delivered: 0x1ab, BolusRemaining: 0x123, MinutesActive: 0x0abc, Reservoir: 3000, LastProgSeqNum: 9}},
		{"G_RSP_GENERAL_LOW", &gs{TempBasalActive: true, ExtendedBolusActive: true, PodProgress: 9,
			Delivered: 0x7ff, MinutesActive: 4799, Reservoir: 0x2a5, LastProgSeqNum: 15}},
		{"G_RSP_DETAILED_OK", &response.DetailedStatusResponse{PodProgress: 8, BasalActive: true, BolusActive: true,
			BolusRemaining: 0x0102, LastProgSeqNum: 5, Delivered: 0x0345, Reservoir: 900, MinutesActive: 0x0607, Alerts: 0x10}},
		{"G_RSP_DETAILED_FAULT", &response.DetailedStatusResponse{PodProgress: 8, BolusActive: true, FaultEvent: 0x14,
			FaultEventTime: 0x0222, Delivered: 0x0345, Reservoir: 5000, MinutesActive: 0x0607}},
		{"G_RSP_TYPE1", &response.Type1StatusResponse{TriggeredAlerts: [8]uint16{1, 0x203, 0, 0, 0, 0, 0, 0xfffe}}},
		{"G_RSP_TYPE3", &response.Type3StatusResponse{FaultEvent: 0x1c, FaultEventTime: 0x1234, MinutesActive: 0x5678}},
		{"G_RSP_TYPE5", &response.Type5StatusResponse{FaultEvent: 0x1c, FaultEventTime: 0x12c0, Year: 26, Month: 11, Day: 14, Hour: 10, Minute: 55}},
		{"G_RSP_TYPE46", &response.Type46StatusResponse{}},
		{"G_RSP_TYPE50", &response.Type50StatusResponse{}},
		{"G_RSP_TYPE51", &response.Type51StatusResponse{}},
		{"G_RSP_NACK", &response.NackResponse{}},
		{"G_RSP_SETUNIQUEID", &response.SetUniqueID{}},
	}
	for _, c := range cases {
		b, err := c.r.Marshal()
		must(err)
		arr(c.name, b)
	}
}

// ---- link layer fragmentation ------------------------------------------------

type capture struct {
	mu   sync.Mutex
	cmd  [][]byte
	data [][]byte
	pod  *bluetooth.Ble
}

func (c *capture) NotifyCmd(p bluetooth.Packet) error {
	c.mu.Lock()
	c.cmd = append(c.cmd, append([]byte{}, p...))
	c.mu.Unlock()
	return nil
}
func (c *capture) NotifyData(p bluetooth.Packet) error {
	c.mu.Lock()
	c.data = append(c.data, append([]byte{}, p...))
	c.mu.Unlock()
	return nil
}
func (c *capture) Advertise([]byte) error                     { return nil }
func (c *capture) AdvertiseState(bluetooth.AdvertState) error { return nil }
func (c *capture) Disconnect()                                {}

func goldenFragments() {
	sizes := []int{0, 2, 6, 7, 10, 20, 30, 37, 40, 50, 55, 56, 75, 100}
	fmt.Fprintf(&out, "#define G_FRAG_COUNT %d\n", len(sizes))
	var names []string
	for _, n := range sizes {
		c := &capture{}
		b, err := bluetooth.New(func(*bluetooth.Ble) (bluetooth.Radio, error) { return c, nil })
		must(err)
		b.Connected()
		b.StartMessageLoop()
		m := message.NewMessage(message.MessageTypeClear, []byte{1, 2, 3, 4}, []byte{5, 6, 7, 8})
		m.Payload = seqBytes(n, 0x30)
		b.WriteMessage(m)
		time.Sleep(20 * time.Millisecond)
		b.CmdWritten(bluetooth.CmdCTS)
		time.Sleep(30 * time.Millisecond)
		b.CmdWritten(bluetooth.CmdSuccess)
		time.Sleep(20 * time.Millisecond)
		c.mu.Lock()
		var flat []byte
		for _, p := range c.data {
			flat = append(flat, byte(len(p)))
			flat = append(flat, p...)
		}
		c.mu.Unlock()
		raw, _ := m.Marshal()
		name := fmt.Sprintf("G_FRAG_%d", n)
		arr(name+"_MSG", raw)
		arr(name+"_PKTS", flat) // each packet: length byte, then the packet
		names = append(names, name)
	}
	out.WriteString("static const struct { const uint8_t *msg; size_t msg_len; const uint8_t *pkts; size_t pkts_len; } G_FRAGS[] = {\n")
	for _, n := range names {
		fmt.Fprintf(&out, "    {%s_MSG, sizeof %s_MSG, %s_PKTS, sizeof %s_PKTS},\n", n, n, n, n)
	}
	out.WriteString("};\n")
}

// ---- message header round-trips ---------------------------------------------

func goldenMessages() {
	m := message.NewMessage(message.MessageTypeEncrypted, []byte{1, 2, 3, 4}, []byte{5, 6, 7, 8})
	m.Payload = []byte{0xaa, 0xbb}
	m.SequenceNumber = 7
	m.AckNumber = 9
	m.Ack = true
	m.Eqos = 1
	b, _ := m.Marshal()
	arr("G_MSG_ACK_EQOS1", b)

	m = message.NewMessage(message.MessageTypeSessionEstablishment, []byte{1, 2, 3, 4}, []byte{5, 6, 7, 8})
	m.Sas, m.Tfs, m.Priority, m.LastMessage, m.Gateway = true, true, true, true, true
	m.Eqos = 5
	m.Payload = seqBytes(300, 0) // > 255: the 11-bit length field
	b, _ = m.Marshal()
	arr("G_MSG_FLAGS_LONG", b)

	binary.BigEndian.PutUint16(b[6:], 0) // silence vet
}

func main() {
	log.SetLevel(log.PanicLevel)
	out.WriteString("/* Generated by tools/golden from upstream jeremybarnum/pod. Do not edit. */\n")
	out.WriteString("#pragma once\n#include <stdint.h>\n#include <stddef.h>\n\n")
	ltk := goldenPair()
	ck, prefix := goldenEap(ltk)
	goldenCrypto(ck, prefix)
	goldenResponses()
	goldenMessages()
	goldenFragments()
	os.Stdout.WriteString(out.String())
}
