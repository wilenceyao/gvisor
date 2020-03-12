// Copyright 2018 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package stack_test

import (
	"bytes"
	"math"
	"math/rand"
	"testing"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

const (
	stackV6Addr = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01"
	testV6Addr  = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02"

	testSrcAddr = "\x0a\x00\x00\x01"
	testDstAddr = "\x0a\x00\x00\x02"

	stackPort = 1234
	testPort  = 4096
)

type testContext struct {
	linkEps map[tcpip.NICID]*channel.Endpoint
	s       *stack.Stack
	wq      waiter.Queue
}

// newDualTestContextMultiNIC creates the testing context and also linkEpIDs NICs.
func newDualTestContextMultiNIC(t *testing.T, mtu uint32, linkEpIDs []tcpip.NICID) *testContext {
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocol{ipv4.NewProtocol(), ipv6.NewProtocol()},
		TransportProtocols: []stack.TransportProtocol{udp.NewProtocol()},
	})
	linkEps := make(map[tcpip.NICID]*channel.Endpoint)
	for _, linkEpID := range linkEpIDs {
		channelEp := channel.New(256, mtu, "")
		if err := s.CreateNIC(linkEpID, channelEp); err != nil {
			t.Fatalf("CreateNIC failed: %v", err)
		}
		linkEps[linkEpID] = channelEp

		if err := s.AddAddress(linkEpID, ipv6.ProtocolNumber, stackV6Addr); err != nil {
			t.Fatalf("AddAddress IPv6 failed: %v", err)
		}
	}
	s.SetRouteTable([]tcpip.Route{
		{Destination: header.IPv4EmptySubnet, NIC: 1},
		{Destination: header.IPv6EmptySubnet, NIC: 1},
	})
	return &testContext{
		s:       s,
		linkEps: linkEps,
	}
}

type headers struct {
	srcPort, dstPort uint16
}

func newPayload() []byte {
	b := make([]byte, 30+rand.Intn(100))
	for i := range b {
		b[i] = byte(rand.Intn(256))
	}
	return b
}

func (c *testContext) sendV4Packet(payload []byte, h *headers, linkEpID tcpip.NICID, to tcpip.Address) {
	buf := buffer.NewView(header.UDPMinimumSize + header.IPv4MinimumSize + len(payload))
	payloadStart := len(buf) - len(payload)
	copy(buf[payloadStart:], payload)

	// Initialize the IP header.
	ip := header.IPv4(buf)
	ip.Encode(&header.IPv4Fields{
		IHL:         header.IPv4MinimumSize,
		TOS:         0x80,
		TotalLength: uint16(len(buf)),
		TTL:         65,
		Protocol:    uint8(udp.ProtocolNumber),
		SrcAddr:     testSrcAddr,
		DstAddr:     to,
	})
	ip.SetChecksum(^ip.CalculateChecksum())

	// Initialize the UDP header.
	u := header.UDP(buf[header.IPv4MinimumSize:])
	u.Encode(&header.UDPFields{
		SrcPort: h.srcPort,
		DstPort: h.dstPort,
		Length:  uint16(header.UDPMinimumSize + len(payload)),
	})

	// Calculate the UDP pseudo-header checksum.
	xsum := header.PseudoHeaderChecksum(udp.ProtocolNumber, testSrcAddr, to, uint16(len(u)))

	// Calculate the UDP checksum and set it.
	xsum = header.Checksum(payload, xsum)
	u.SetChecksum(^u.CalculateChecksum(xsum))

	// Inject packet.
	c.linkEps[linkEpID].InjectInbound(ipv4.ProtocolNumber, tcpip.PacketBuffer{
		Data:            buf.ToVectorisedView(),
		NetworkHeader:   buffer.View(ip),
		TransportHeader: buffer.View(u),
	})
}

func (c *testContext) sendV6Packet(payload []byte, h *headers, linkEpID tcpip.NICID) {
	// Allocate a buffer for data and headers.
	buf := buffer.NewView(header.UDPMinimumSize + header.IPv6MinimumSize + len(payload))
	copy(buf[len(buf)-len(payload):], payload)

	// Initialize the IP header.
	ip := header.IPv6(buf)
	ip.Encode(&header.IPv6Fields{
		PayloadLength: uint16(header.UDPMinimumSize + len(payload)),
		NextHeader:    uint8(udp.ProtocolNumber),
		HopLimit:      65,
		SrcAddr:       testV6Addr,
		DstAddr:       stackV6Addr,
	})

	// Initialize the UDP header.
	u := header.UDP(buf[header.IPv6MinimumSize:])
	u.Encode(&header.UDPFields{
		SrcPort: h.srcPort,
		DstPort: h.dstPort,
		Length:  uint16(header.UDPMinimumSize + len(payload)),
	})

	// Calculate the UDP pseudo-header checksum.
	xsum := header.PseudoHeaderChecksum(udp.ProtocolNumber, testV6Addr, stackV6Addr, uint16(len(u)))

	// Calculate the UDP checksum and set it.
	xsum = header.Checksum(payload, xsum)
	u.SetChecksum(^u.CalculateChecksum(xsum))

	// Inject packet.
	c.linkEps[linkEpID].InjectInbound(ipv6.ProtocolNumber, tcpip.PacketBuffer{
		Data: buf.ToVectorisedView(),
	})
}

func TestTransportDemuxerRegister(t *testing.T) {
	for _, test := range []struct {
		name  string
		proto tcpip.NetworkProtocolNumber
		want  *tcpip.Error
	}{
		{"failure", ipv6.ProtocolNumber, tcpip.ErrUnknownProtocol},
		{"success", ipv4.ProtocolNumber, nil},
	} {
		t.Run(test.name, func(t *testing.T) {
			s := stack.New(stack.Options{
				NetworkProtocols:   []stack.NetworkProtocol{ipv4.NewProtocol()},
				TransportProtocols: []stack.TransportProtocol{udp.NewProtocol()},
			})
			var wq waiter.Queue
			ep, err := s.NewEndpoint(udp.ProtocolNumber, ipv4.ProtocolNumber, &wq)
			if err != nil {
				t.Fatal(err)
			}
			tEP, ok := ep.(stack.TransportEndpoint)
			if !ok {
				t.Fatalf("%T does not implement stack.TransportEndpoint", ep)
			}
			if got, want := s.RegisterTransportEndpoint(0, []tcpip.NetworkProtocolNumber{test.proto}, udp.ProtocolNumber, stack.TransportEndpointID{}, tEP, false, 0), test.want; got != want {
				t.Fatalf("s.RegisterTransportEndpoint(...) = %v, want %v", got, want)
			}
		})
	}
}

// TestReuseBindToDevice injects varied packets on input devices and checks that
// the distribution of packets received matches expectations.
func TestDistribution(t *testing.T) {
	type endpointSockopts struct {
		reuse        int
		bindToDevice tcpip.NICID
	}
	for _, test := range []struct {
		name string
		// endpoints will received the inject packets.
		endpoints []endpointSockopts
		// wantedDistribution is the wanted ratio of packets received on each
		// endpoint for each NIC on which packets are injected.
		wantDistributions map[tcpip.NICID][]float64
	}{
		{
			name: "BindPortReuse",
			// 5 endpoints that all have reuse set.
			endpoints: []endpointSockopts{
				{1, 0},
				{1, 0},
				{1, 0},
				{1, 0},
				{1, 0},
			},
			wantDistributions: map[tcpip.NICID][]float64{
				// Injected packets on dev0 get distributed evenly.
				1: {0.2, 0.2, 0.2, 0.2, 0.2},
			},
		},
		{
			name: "BindToDevice",
			// 3 endpoints with various bindings.
			endpoints: []endpointSockopts{
				{0, 1},
				{0, 2},
				{0, 3},
			},
			wantDistributions: map[tcpip.NICID][]float64{
				// Injected packets on dev0 go only to the endpoint bound to dev0.
				1: {1, 0, 0},
				// Injected packets on dev1 go only to the endpoint bound to dev1.
				2: {0, 1, 0},
				// Injected packets on dev2 go only to the endpoint bound to dev2.
				3: {0, 0, 1},
			},
		},
		{
			name: "ReuseAndBindToDevice",
			// 6 endpoints with various bindings.
			endpoints: []endpointSockopts{
				{1, 1},
				{1, 1},
				{1, 2},
				{1, 2},
				{1, 2},
				{1, 0},
			},
			wantDistributions: map[tcpip.NICID][]float64{
				// Injected packets on dev0 get distributed among endpoints bound to
				// dev0.
				1: {0.5, 0.5, 0, 0, 0, 0},
				// Injected packets on dev1 get distributed among endpoints bound to
				// dev1 or unbound.
				2: {0, 0, 1. / 3, 1. / 3, 1. / 3, 0},
				// Injected packets on dev999 go only to the unbound.
				1000: {0, 0, 0, 0, 0, 1},
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			for device, wantedDistribution := range test.wantDistributions {
				t.Run(string(device), func(t *testing.T) {
					var devices []tcpip.NICID
					for d := range test.wantDistributions {
						devices = append(devices, d)
					}
					c := newDualTestContextMultiNIC(t, defaultMTU, devices)

					eps := make(map[tcpip.Endpoint]int)

					pollChannel := make(chan tcpip.Endpoint)
					for i, endpoint := range test.endpoints {
						// Try to receive the data.
						wq := waiter.Queue{}
						we, ch := waiter.NewChannelEntry(nil)
						wq.EventRegister(&we, waiter.EventIn)
						defer wq.EventUnregister(&we)
						defer close(ch)

						var err *tcpip.Error
						ep, err := c.s.NewEndpoint(udp.ProtocolNumber, ipv6.ProtocolNumber, &wq)
						if err != nil {
							t.Fatalf("NewEndpoint failed: %v", err)
						}
						eps[ep] = i

						go func(ep tcpip.Endpoint) {
							for range ch {
								pollChannel <- ep
							}
						}(ep)

						defer ep.Close()
						reusePortOption := tcpip.ReusePortOption(endpoint.reuse)
						if err := ep.SetSockOpt(reusePortOption); err != nil {
							t.Fatalf("SetSockOpt(%#v) on endpoint %d failed: %v", reusePortOption, i, err)
						}
						bindToDeviceOption := tcpip.BindToDeviceOption(endpoint.bindToDevice)
						if err := ep.SetSockOpt(bindToDeviceOption); err != nil {
							t.Fatalf("SetSockOpt(%#v) on endpoint %d failed: %v", bindToDeviceOption, i, err)
						}
						if err := ep.Bind(tcpip.FullAddress{Addr: stackV6Addr, Port: stackPort}); err != nil {
							t.Fatalf("ep.Bind(...) on endpoint %d failed: %v", i, err)
						}
					}

					npackets := 100000
					nports := 10000
					if got, want := len(test.endpoints), len(wantedDistribution); got != want {
						t.Fatalf("got len(test.endpoints) = %d, want %d", got, want)
					}
					ports := make(map[uint16]tcpip.Endpoint)
					stats := make(map[tcpip.Endpoint]int)
					for i := 0; i < npackets; i++ {
						// Send a packet.
						port := uint16(i % nports)
						payload := newPayload()
						c.sendV6Packet(payload,
							&headers{
								srcPort: testPort + port,
								dstPort: stackPort},
							device)

						ep := <-pollChannel
						if _, _, err := ep.Read(nil); err != nil {
							t.Fatalf("Read on endpoint %d failed: %v", eps[ep], err)
						}
						stats[ep]++
						if i < nports {
							ports[uint16(i)] = ep
						} else {
							// Check that all packets from one client are handled by the same
							// socket.
							if want, got := ports[port], ep; want != got {
								t.Fatalf("Packet sent on port %d expected on endpoint %d but received on endpoint %d", port, eps[want], eps[got])
							}
						}
					}

					// Check that a packet distribution is as expected.
					for ep, i := range eps {
						wantedRatio := wantedDistribution[i]
						wantedRecv := wantedRatio * float64(npackets)
						actualRecv := stats[ep]
						actualRatio := float64(stats[ep]) / float64(npackets)
						// The deviation is less than 10%.
						if math.Abs(actualRatio-wantedRatio) > 0.05 {
							t.Errorf("wanted about %.0f%% (%.0f of %d) packets to arrive on endpoint %d, got %.0f%% (%d of %d)", wantedRatio*100, wantedRecv, npackets, i, actualRatio*100, actualRecv, npackets)
						}
					}
				})
			}
		})
	}
}

func TestReceiveOnIPv4Any(t *testing.T) {
	testNICID := tcpip.NICID(1)
	devices := []tcpip.NICID{testNICID}
	c := newDualTestContextMultiNIC(t, defaultMTU, devices)

	for _, addr := range []tcpip.Address{header.IPv4Any, testDstAddr} {
		if err := c.s.AddAddress(testNICID, ipv4.ProtocolNumber, addr); err != nil {
			t.Fatalf("Failed to add %s to stack: %s", addr, err)
		}
	}

	for _, v := range []struct {
		desc         string
		bindToDevice bool
		dstAddr      tcpip.Address
	}{
		{desc: "unicast", dstAddr: testDstAddr},
		{desc: "broadcast", dstAddr: header.IPv4Broadcast},
		{desc: "any", dstAddr: header.IPv4Any},
		{desc: "bindtodevice unicast", bindToDevice: true, dstAddr: testDstAddr},
		{desc: "bindtodevice broadcast", bindToDevice: true, dstAddr: header.IPv4Broadcast},
		{desc: "bindtodevice any", bindToDevice: true, dstAddr: header.IPv4Any},
	} {
		t.Run(v.desc, func(t *testing.T) {
			t.Logf("Endpoint bound to %s should receive packets sent to %s, bindToDevice=%t", header.IPv4Any, v.dstAddr, v.bindToDevice)

			receiver, err := c.s.NewEndpoint(udp.ProtocolNumber, ipv4.ProtocolNumber, &c.wq)
			if err != nil {
				t.Fatalf("Failed to create new endpont: %s", err)
			}
			defer receiver.Close()

			if v.bindToDevice {
				if err := receiver.SetSockOpt(tcpip.BindToDeviceOption(testNICID)); err != nil {
					t.Fatalf("Failed to bind to device %d: %s", testNICID, err)
				}
			}

			fullAddr := tcpip.FullAddress{Addr: header.IPv4Any, Port: stackPort}
			if err := receiver.Bind(fullAddr); err != nil {
				t.Fatalf("Failed to bind to address %#v: %s", fullAddr, err)
			}

			want := newPayload()
			c.sendV4Packet(want, &headers{
				srcPort: testPort,
				dstPort: stackPort,
			}, testNICID, v.dstAddr)

			got, _, err := receiver.Read(nil)
			if err != nil {
				t.Fatalf("Read on endpoint failed: %s", err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("Payload mismatch, got: %x, want: %x", got, want)
			}
		})
	}

	t.Run("difffernt port", func(t *testing.T) {
		t.Logf("Endpoint bound to %s should not receive packets sent to other ports", header.IPv4Any)

		receiver, err := c.s.NewEndpoint(udp.ProtocolNumber, ipv4.ProtocolNumber, &c.wq)
		if err != nil {
			t.Fatalf("Failed to create new endpont: %s", err)
		}
		defer receiver.Close()

		if err := receiver.Bind(tcpip.FullAddress{Addr: header.IPv4Any, Port: stackPort}); err != nil {
			t.Fatalf("ep.Bind failed: %s", err)
		}

		want := newPayload()
		c.sendV4Packet(want, &headers{
			srcPort: testPort,
			dstPort: stackPort + 1,
		}, testNICID, testDstAddr)

		if _, _, err := receiver.Read(nil); err != tcpip.ErrWouldBlock {
			t.Fatalf("Got unexpected error: %s, want: %s", err, tcpip.ErrWouldBlock)
		}
	})
}
