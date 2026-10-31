package ipsec

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/1239t/swu-go/pkg/ikev2"
	"github.com/1239t/swu-go/pkg/logger"
)

type SocketRole uint8

const (
	SocketRoleDNS SocketRole = iota + 1
	SocketRoleOuter
)

type SocketPhase uint8

const (
	SocketPhaseDial SocketPhase = iota + 1
	SocketPhaseWrite
	SocketPhaseRead
)

type SocketResult uint8

const (
	SocketResultStarted SocketResult = iota + 1
	SocketResultSuccess
	SocketResultFailure
)

// SocketCause is a fixed classification, never an error message or protocol data.
type SocketCause uint8

const (
	SocketCauseNone SocketCause = iota
	SocketCauseCanceled
	SocketCauseTimeout
	SocketCauseClosed
	SocketCausePermission
	SocketCauseRefused
	SocketCauseUnreachable
	SocketCauseAddressInUse
	SocketCauseAddressUnavailable
	SocketCauseOther
)

// SocketEvent contains only transport metadata. Invalid addresses mean unknown;
// DNS response receipt does not establish a valid answer or protocol acceptance.
type SocketEvent struct {
	Role   SocketRole
	Phase  SocketPhase
	Result SocketResult
	Remote netip.AddrPort
	Source netip.Addr
	Bytes  int
	Cause  SocketCause
}

// SocketObserver runs synchronously on the calling I/O goroutine, may be called
// concurrently, and must return promptly. The library never logs these events.
// Consumers must de-identify addresses before any persistence or transmission.
type SocketObserver func(context.Context, SocketEvent)

func socketCause(err error) SocketCause {
	if err == nil {
		return SocketCauseNone
	}
	switch {
	case errors.Is(err, context.Canceled):
		return SocketCauseCanceled
	case errors.Is(err, net.ErrClosed):
		return SocketCauseClosed
	case errors.Is(err, context.DeadlineExceeded):
		return SocketCauseTimeout
	case errors.Is(err, syscall.EPERM), errors.Is(err, syscall.EACCES):
		return SocketCausePermission
	case errors.Is(err, syscall.ECONNREFUSED):
		return SocketCauseRefused
	case errors.Is(err, syscall.ENETUNREACH), errors.Is(err, syscall.EHOSTUNREACH):
		return SocketCauseUnreachable
	case errors.Is(err, syscall.EADDRINUSE):
		return SocketCauseAddressInUse
	case errors.Is(err, syscall.EADDRNOTAVAIL):
		return SocketCauseAddressUnavailable
	}
	var timeout net.Error
	if errors.As(err, &timeout) && timeout.Timeout() {
		return SocketCauseTimeout
	}
	return SocketCauseOther
}

func socketEndpoint(addr net.Addr) netip.AddrPort {
	var endpoint netip.AddrPort
	switch addr := addr.(type) {
	case *net.UDPAddr:
		if addr != nil {
			endpoint = addr.AddrPort()
		}
	case *net.TCPAddr:
		if addr != nil {
			endpoint = addr.AddrPort()
		}
	}
	if !endpoint.IsValid() {
		return netip.AddrPort{}
	}
	return netip.AddrPortFrom(endpoint.Addr().Unmap(), endpoint.Port())
}

func observeSocket(ctx context.Context, observer SocketObserver, role SocketRole, phase SocketPhase, result SocketResult, remote netip.AddrPort, source netip.Addr, n int, err error) {
	if observer != nil {
		observer(ctx, SocketEvent{Role: role, Phase: phase, Result: result, Remote: remote, Source: source, Bytes: n, Cause: socketCause(err)})
	}
}

func observeSocketIO(ctx context.Context, observer SocketObserver, role SocketRole, phase SocketPhase, remote, local net.Addr, n int, err error) {
	if observer == nil || (n == 0 && err == nil) {
		return
	}
	result := SocketResultSuccess
	if err != nil {
		result = SocketResultFailure
	}
	observeSocket(ctx, observer, role, phase, result, socketEndpoint(remote), socketEndpoint(local).Addr(), n, err)
}

type observedDNSConn struct {
	net.Conn
	ctx      context.Context
	observer SocketObserver
}

func (c *observedDNSConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	observeSocketIO(c.ctx, c.observer, SocketRoleDNS, SocketPhaseRead, c.Conn.RemoteAddr(), c.Conn.LocalAddr(), n, err)
	return n, err
}

func (c *observedDNSConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	observeSocketIO(c.ctx, c.observer, SocketRoleDNS, SocketPhaseWrite, c.Conn.RemoteAddr(), c.Conn.LocalAddr(), n, err)
	return n, err
}

// Resolver.exchange uses the presence of net.PacketConn to select UDP framing.
// Preserve that capability only when the original connection implements it.
type observedDNSPacketConn struct {
	*observedDNSConn
	packet net.PacketConn
}

func (c *observedDNSPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, remote, err := c.packet.ReadFrom(b)
	observeSocketIO(c.ctx, c.observer, SocketRoleDNS, SocketPhaseRead, remote, c.Conn.LocalAddr(), n, err)
	return n, remote, err
}

func (c *observedDNSPacketConn) WriteTo(b []byte, remote net.Addr) (int, error) {
	n, err := c.packet.WriteTo(b, remote)
	observeSocketIO(c.ctx, c.observer, SocketRoleDNS, SocketPhaseWrite, remote, c.Conn.LocalAddr(), n, err)
	return n, err
}

func observeDNSConn(ctx context.Context, conn net.Conn, observer SocketObserver) net.Conn {
	if observer == nil {
		return conn
	}
	wrapped := &observedDNSConn{Conn: conn, ctx: ctx, observer: observer}
	if packet, ok := conn.(net.PacketConn); ok {
		return &observedDNSPacketConn{observedDNSConn: wrapped, packet: packet}
	}
	return wrapped
}

type SocketManager struct {
	Conn         *net.UDPConn
	LocalAddr    *net.UDPAddr
	RemoteAddr   *net.UDPAddr
	remoteIPs    []net.IP
	remoteMu     sync.Mutex
	remoteIdx    uint32
	ikeEnvelopes chan IKEEnvelope
	useEnvelopes atomic.Bool
	ctx          context.Context
	observer     SocketObserver

	IKEChan   chan []byte
	ESPChan   chan []byte
	NetEvents chan NetEvent // 网络底层事件通道 (PMTU / ICMP Error)

	closeChan chan struct{}
	wg        sync.WaitGroup

	receivedIKE uint64
	receivedESP uint64
	droppedIKE  uint64
	droppedESP  uint64
}

func (s *SocketManager) IKEPackets() <-chan []byte {
	return s.IKEChan
}

func (s *SocketManager) OutputMark() (uint32, error) {
	raw, err := s.Conn.SyscallConn()
	if err != nil {
		return 0, err
	}
	var mark int
	var socketErr error
	if err := raw.Control(func(fd uintptr) {
		mark, socketErr = syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK)
	}); err != nil {
		return 0, err
	}
	return uint32(mark), socketErr
}

// IKEEnvelope carries an uncommitted source through the validation boundary.
type IKEEnvelope struct {
	Data []byte
	Peer *net.UDPAddr
}

func (s *SocketManager) IKEEnvelopes() <-chan IKEEnvelope {
	s.useEnvelopes.Store(true)
	return s.ikeEnvelopes
}

// CommitIKEPeer is called only after Session validation. Initial responses must
// use the requested port; protected packets may prove a NAT mapping change.
func (s *SocketManager) CommitIKEPeer(peer *net.UDPAddr, protected bool) error {
	s.remoteMu.Lock()
	defer s.remoteMu.Unlock()
	select {
	case <-s.closeChan:
		return net.ErrClosed
	default:
	}
	if peer == nil || peer.Port <= 0 || peer.Port > 65535 || s.RemoteAddr == nil {
		return errors.New("invalid IKE peer")
	}
	allowed := false
	for _, ip := range s.remoteIPs {
		if peer.IP.Equal(ip) {
			allowed = true
			break
		}
	}
	if !allowed || (!protected && peer.Port != s.RemoteAddr.Port) {
		return errors.New("IKE peer outside bound endpoint")
	}
	old := s.RemoteAddr.Port
	s.RemoteAddr = &net.UDPAddr{IP: append(net.IP(nil), peer.IP...), Port: peer.Port, Zone: peer.Zone}
	s.remoteIPs = []net.IP{append(net.IP(nil), peer.IP...)}
	s.remoteIdx = 0
	if old != peer.Port {
		select {
		case s.NetEvents <- NetEvent{Type: EventNATPortChanged, OldPort: old, NewPort: peer.Port}:
		default:
		}
	}
	return nil
}

func (s *SocketManager) ESPPackets() <-chan []byte {
	return s.ESPChan
}

func (s *SocketManager) NetEventsChan() <-chan NetEvent {
	return s.NetEvents
}

func NewSocketManager(local, remote string, dnsServer string) (*SocketManager, error) {
	return NewSocketManagerWithControl(context.Background(), local, remote, dnsServer, nil)
}

func NewSocketManagerWithControl(ctx context.Context, local, remote, dnsServer string, control func(string, string, syscall.RawConn) error) (*SocketManager, error) {
	return NewSocketManagerWithSource(ctx, local, remote, dnsServer, control, nil)
}

// NewSocketManagerWithSource keeps network control on every socket while
// selecting DNS and ePDG sources independently within that same network.
func NewSocketManagerWithSource(ctx context.Context, local, remote, dnsServer string, control func(string, string, syscall.RawConn) error, sourceIP func(net.IP) (net.IP, error)) (*SocketManager, error) {
	return NewSocketManagerWithObserver(ctx, local, remote, dnsServer, control, sourceIP, nil)
}

// NewSocketManagerWithObserver adds optional, context-bound transport observation.
func NewSocketManagerWithObserver(ctx context.Context, local, remote, dnsServer string, control func(string, string, syscall.RawConn) error, sourceIP func(net.IP) (net.IP, error), observer SocketObserver) (*SocketManager, error) {
	return NewSocketManagerWithAddressFamily(ctx, local, remote, dnsServer, control, sourceIP, observer, "")
}

// NewSocketManagerWithAddressFamily chooses only compatible remote candidates;
// DNS binding, observation, cancellation and same-socket rotation stay separate.
func NewSocketManagerWithAddressFamily(ctx context.Context, local, remote, dnsServer string, control func(string, string, syscall.RawConn) error, sourceIP func(net.IP) (net.IP, error), observer SocketObserver, family AddressFamilyPolicy) (*SocketManager, error) {
	localHost, localPort, err := net.SplitHostPort(local)
	if err != nil {
		return nil, err
	}
	remoteHost, _, err := net.SplitHostPort(remote)
	if err != nil {
		return nil, err
	}
	if err := family.ValidateAddress(remoteHost); err != nil {
		return nil, err
	}
	localIP := net.ParseIP(localHost)
	rAddr, remoteIPs, err := resolveUDPAddrAllWithFamily(ctx, remote, dnsServer, localIP, control, sourceIP, observer, family)
	if err != nil {
		return nil, err
	}
	selected, err := selectSourceIP(localIP, rAddr.IP, sourceIP)
	if err != nil {
		return nil, err
	}
	if sourceIP != nil {
		local = net.JoinHostPort(selected.String(), localPort)
	}
	// A single UDP socket cannot rotate onto the other address family.
	compatible := remoteIPs[:0]
	for _, ip := range remoteIPs {
		if (ip.To4() != nil) == (rAddr.IP.To4() != nil) {
			compatible = append(compatible, ip)
		}
	}
	remoteIPs = compatible
	if len(remoteIPs) == 0 && rAddr.IP != nil {
		remoteIPs = []net.IP{rAddr.IP}
	}

	network := "udp6"
	if rAddr.IP != nil && rAddr.IP.To4() != nil {
		network = "udp4"
	}

	lAddr, err := net.ResolveUDPAddr(network, local)
	if err != nil {
		return nil, err
	}

	listener := net.ListenConfig{Control: control}
	observeSocket(ctx, observer, SocketRoleOuter, SocketPhaseDial, SocketResultStarted, socketEndpoint(rAddr), netip.Addr{}, 0, nil)
	packet, err := listener.ListenPacket(ctx, network, lAddr.String())
	if err != nil {
		observeSocket(ctx, observer, SocketRoleOuter, SocketPhaseDial, SocketResultFailure, socketEndpoint(rAddr), netip.Addr{}, 0, err)
		return nil, err
	}
	conn := packet.(*net.UDPConn)

	if actual, ok := conn.LocalAddr().(*net.UDPAddr); ok {
		lAddr = actual
	}
	observeSocket(ctx, observer, SocketRoleOuter, SocketPhaseDial, SocketResultSuccess, socketEndpoint(rAddr), socketEndpoint(conn.LocalAddr()).Addr(), 0, nil)

	return &SocketManager{
		Conn:         conn,
		LocalAddr:    lAddr,
		RemoteAddr:   rAddr,
		remoteIPs:    remoteIPs,
		ctx:          ctx,
		observer:     observer,
		IKEChan:      make(chan []byte, 100),
		ikeEnvelopes: make(chan IKEEnvelope, 100),
		ESPChan:      make(chan []byte, 1000), // 数据平面的更高缓冲区
		NetEvents:    make(chan NetEvent, 10),
		closeChan:    make(chan struct{}),
	}, nil
}

func resolveUDPAddrAll(addr string, dnsServer string) (*net.UDPAddr, []net.IP, error) {
	return resolveUDPAddrAllControlled(context.Background(), addr, dnsServer, nil, nil)
}

func resolveUDPAddrAllControlled(parent context.Context, addr, dnsServer string, localIP net.IP, control func(string, string, syscall.RawConn) error) (*net.UDPAddr, []net.IP, error) {
	return resolveUDPAddrAllWithSource(parent, addr, dnsServer, localIP, control, nil)
}

func resolveUDPAddrAllWithSource(parent context.Context, addr, dnsServer string, localIP net.IP, control func(string, string, syscall.RawConn) error, sourceIP func(net.IP) (net.IP, error)) (*net.UDPAddr, []net.IP, error) {
	return resolveUDPAddrAllWithObserver(parent, addr, dnsServer, localIP, control, sourceIP, nil)
}

func resolveUDPAddrAllWithObserver(parent context.Context, addr, dnsServer string, localIP net.IP, control func(string, string, syscall.RawConn) error, sourceIP func(net.IP) (net.IP, error), observer SocketObserver) (*net.UDPAddr, []net.IP, error) {
	return resolveUDPAddrAllWithFamily(parent, addr, dnsServer, localIP, control, sourceIP, observer, "")
}

func resolveUDPAddrAllWithFamily(parent context.Context, addr, dnsServer string, localIP net.IP, control func(string, string, syscall.RawConn) error, sourceIP func(net.IP) (net.IP, error), observer SocketObserver, family AddressFamilyPolicy) (*net.UDPAddr, []net.IP, error) {
	if dnsServer == "" {
		if control != nil || sourceIP != nil {
			host, _, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, nil, err
			}
			if net.ParseIP(host) == nil {
				return nil, nil, errors.New("selected network requires an explicit DNS endpoint")
			}
		}
		if family == "" {
			r, err := net.ResolveUDPAddr("udp", addr)
			if err != nil {
				return nil, nil, err
			}
			if r.IP != nil {
				return r, []net.IP{r.IP}, nil
			}
			return r, nil, nil
		}
	}

	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, nil, err
	}
	port, err := net.LookupPort("udp", portStr)
	if err != nil {
		return nil, nil, err
	}

	if ip := net.ParseIP(host); ip != nil {
		return &net.UDPAddr{IP: ip, Port: port}, []net.IP{ip}, nil
	}

	res := net.DefaultResolver
	if dnsServer != "" {
		res = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{Control: control}
				if control != nil || sourceIP != nil {
					host, _, err := net.SplitHostPort(dnsServer)
					if err != nil || net.ParseIP(host) == nil {
						return nil, errors.New("selected network requires a literal DNS endpoint")
					}
					selected, err := selectSourceIP(localIP, net.ParseIP(host), sourceIP)
					if err != nil {
						return nil, err
					}
					if strings.HasPrefix(network, "tcp") {
						d.LocalAddr = &net.TCPAddr{IP: selected}
					} else {
						d.LocalAddr = &net.UDPAddr{IP: selected}
					}
				}
				if observer == nil {
					return d.DialContext(ctx, network, dnsServer)
				}
				// Do not use Resolver's address argument: it can be a system-resolver
				// placeholder, unrelated to the endpoint actually passed to DialContext.
				remote, _ := netip.ParseAddrPort(dnsServer)
				if remote.IsValid() {
					remote = netip.AddrPortFrom(remote.Addr().Unmap(), remote.Port())
				}
				// Resolver may detach deadlines and discard values after cancellation.
				// Keep observation bound to the original caller, not that internal ctx;
				// the actual DialContext and its deadlines remain entirely unchanged.
				observeSocket(parent, observer, SocketRoleDNS, SocketPhaseDial, SocketResultStarted, remote, netip.Addr{}, 0, nil)
				conn, err := d.DialContext(ctx, network, dnsServer)
				if err != nil {
					observeSocket(parent, observer, SocketRoleDNS, SocketPhaseDial, SocketResultFailure, remote, netip.Addr{}, 0, err)
					return conn, err
				}
				observeSocket(parent, observer, SocketRoleDNS, SocketPhaseDial, SocketResultSuccess, socketEndpoint(conn.RemoteAddr()), socketEndpoint(conn.LocalAddr()).Addr(), 0, nil)
				return observeDNSConn(parent, conn, observer), nil
			},
		}
	}
	ctx, cancel := context.WithTimeout(parent, 3*time.Second)
	defer cancel()

	ips, err := res.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, nil, err
	}
	if len(ips) == 0 {
		return nil, nil, errors.New("DNS 未返回 IP")
	}

	var remoteIPs []net.IP
	for _, cand := range ips {
		if cand.IP == nil || !family.permits(cand.IP) {
			continue
		}
		if _, err := selectSourceIP(localIP, cand.IP, sourceIP); err != nil {
			continue
		}
		remoteIPs = append(remoteIPs, cand.IP)
	}
	if len(remoteIPs) == 0 {
		if family == AddressFamilyIPv4Only || family == AddressFamilyIPv6Only {
			return nil, nil, ErrAddressFamilyMismatch
		}
		return nil, nil, errors.New("DNS returned no address matching selected local network family")
	}

	ip := remoteIPs[0]
	preferIPv4 := family != AddressFamilyPreferIPv6 && family != AddressFamilyIPv6Only
	for _, cand := range remoteIPs {
		if (cand.To4() != nil) == preferIPv4 {
			ip = cand
			break
		}
	}

	return &net.UDPAddr{IP: ip, Port: port}, remoteIPs, nil
}

func (s *SocketManager) Start() {
	s.wg.Add(1)
	go s.readLoop()

	// 启动 ICMP MSG_ERRQUEUE 错误监听
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.startErrorListener()
	}()
}

func (s *SocketManager) Stop() {
	select {
	case <-s.closeChan:
	default:
		close(s.closeChan)
	}
	s.Conn.Close()
	s.wg.Wait()
	close(s.IKEChan)
	close(s.ikeEnvelopes)
	close(s.ESPChan)
	s.remoteMu.Lock()
	close(s.NetEvents)
	s.remoteMu.Unlock()
}

func (s *SocketManager) readLoop() {
	defer s.wg.Done()
	buf := make([]byte, 4096) // Max MTU usually 1500

	for {
		n, addr, err := s.Conn.ReadFromUDP(buf)
		observeSocketIO(s.ctx, s.observer, SocketRoleOuter, SocketPhaseRead, addr, s.Conn.LocalAddr(), n, err)
		if err != nil {
			// Log checking if closed
			return
		}

		s.remoteMu.Lock()
		allowed := false
		port := s.RemoteAddr.Port
		for _, rip := range s.remoteIPs {
			if addr.IP.Equal(rip) {
				allowed = true
				break
			}
		}
		s.remoteMu.Unlock()
		if !allowed {
			continue
		}

		data := make([]byte, n)
		copy(data, buf[:n])

		if n == 1 && data[0] == 0xff {
			continue
		}

		if ikeData, ok := parseIKEPayload(data); ok {
			// SA_INIT is unauthenticated and cannot prove a remote port change.
			if ikeData[18] == byte(ikev2.IKE_SA_INIT) && addr.Port != port {
				continue
			}
			if s.useEnvelopes.Load() {
				select {
				case s.ikeEnvelopes <- IKEEnvelope{Data: ikeData, Peer: addr}:
					atomic.AddUint64(&s.receivedIKE, 1)
				default:
					atomic.AddUint64(&s.droppedIKE, 1)
				}
				continue
			}
			select {
			case s.IKEChan <- ikeData:
				atomic.AddUint64(&s.receivedIKE, 1)
			default:
				drops := atomic.AddUint64(&s.droppedIKE, 1)
				if drops == 1 || drops%100 == 0 {
					logger.Warn("IKE Channel 已满，丢弃数据包", logger.Uint64("dropped", drops))
				}
			}
			continue
		}

		if len(data) >= 4 && binary.BigEndian.Uint32(data[:4]) == 0 {
			data = data[4:]
		}
		if len(data) == 0 {
			continue
		}

		select {
		case s.ESPChan <- data:
			atomic.AddUint64(&s.receivedESP, 1)
		default:
			drops := atomic.AddUint64(&s.droppedESP, 1)
			if drops == 1 || drops%100 == 0 {
				logger.Warn("ESP Channel 已满，丢弃数据包", logger.Uint64("dropped", drops))
			}
		}
	}
}

func (s *SocketManager) SendIKE(data []byte) error {
	s.remoteMu.Lock()
	if len(s.remoteIPs) > 1 {
		idx := int(s.remoteIdx % uint32(len(s.remoteIPs)))
		s.remoteIdx++
		s.RemoteAddr.IP = s.remoteIPs[idx]
		logger.Debug("切换 ePDG 目标", logger.String("ip", s.RemoteAddr.IP.String()))
	}
	dst := *s.RemoteAddr
	s.remoteMu.Unlock()

	packet := data
	if dst.Port == 4500 {
		packet = append([]byte{0, 0, 0, 0}, data...)
	}
	n, err := s.Conn.WriteToUDP(packet, &dst)
	observeSocketIO(s.ctx, s.observer, SocketRoleOuter, SocketPhaseWrite, &dst, s.Conn.LocalAddr(), n, err)
	return err
}

func (s *SocketManager) SendESP(data []byte) error {
	s.remoteMu.Lock()
	dst := *s.RemoteAddr
	s.remoteMu.Unlock()
	packet := data
	// ESP over UDP 不添加 Non-ESP Marker (RFC 3948)
	// 接收方通过 SPI != 0 来区分 ESP 和 IKE
	n, err := s.Conn.WriteToUDP(packet, &dst)
	observeSocketIO(s.ctx, s.observer, SocketRoleOuter, SocketPhaseWrite, &dst, s.Conn.LocalAddr(), n, err)
	if err != nil {
		logger.Warn("ESP 发送失败", logger.Err(err), logger.String("dst", dst.String()), logger.Int("len", len(packet)))
	} else if n != len(packet) {
		logger.Warn("ESP 发送不完整", logger.Int("sent", n), logger.Int("expected", len(packet)))
	}
	return err
}

func (s *SocketManager) SendNATKeepalive() error {
	s.remoteMu.Lock()
	dst := *s.RemoteAddr
	s.remoteMu.Unlock()
	n, err := s.Conn.WriteToUDP([]byte{0xff}, &dst)
	observeSocketIO(s.ctx, s.observer, SocketRoleOuter, SocketPhaseWrite, &dst, s.Conn.LocalAddr(), n, err)
	if err != nil {
		// 捕捉 operation not permitted 这类 OS 级阻塞
		logger.Warn("NAT keepalive 发送遭遇操作系统级拦截/拒绝", logger.Err(err), logger.String("dst", dst.String()), logger.String("local", s.LocalAddrString()))
	}
	return err
}

// ReceiveIKE 从 IKE 通道接收数据 (阻塞)
func (s *SocketManager) ReceiveIKE() ([]byte, error) {
	data, ok := <-s.IKEChan
	if !ok {
		return nil, fmt.Errorf("IKE 通道已关闭")
	}
	return data, nil
}

func (s *SocketManager) SetRemotePort(port int) {
	s.remoteMu.Lock()
	defer s.remoteMu.Unlock()
	s.RemoteAddr.Port = port
}

func (s *SocketManager) LocalPort() uint16 {
	if s.LocalAddr == nil {
		return 0
	}
	return uint16(s.LocalAddr.Port)
}

func (s *SocketManager) LocalIP() net.IP {
	if s.LocalAddr == nil {
		return nil
	}
	return s.LocalAddr.IP
}

func (s *SocketManager) RemoteIP() net.IP {
	s.remoteMu.Lock()
	defer s.remoteMu.Unlock()
	if s.RemoteAddr == nil {
		return nil
	}
	return append(net.IP(nil), s.RemoteAddr.IP...)
}

func (s *SocketManager) RemotePort() int {
	s.remoteMu.Lock()
	defer s.remoteMu.Unlock()
	if s.RemoteAddr == nil {
		return 0
	}
	return s.RemoteAddr.Port
}

func (s *SocketManager) LocalAddrString() string {
	if s.LocalAddr == nil {
		return ""
	}
	return s.LocalAddr.String()
}

func (s *SocketManager) RemoteAddrString() string {
	s.remoteMu.Lock()
	defer s.remoteMu.Unlock()
	if s.RemoteAddr == nil {
		return ""
	}
	return s.RemoteAddr.String()
}

func parseIKEPayload(data []byte) ([]byte, bool) {
	if len(data) < 4 {
		return nil, false
	}
	if binary.BigEndian.Uint32(data[:4]) == 0 {
		if len(data) < 4+ikev2.IKE_HEADER_LEN {
			return nil, false
		}
		ikeData := data[4:]
		if looksLikeIKE(ikeData) {
			return ikeData, true
		}
		return nil, false
	}

	if len(data) < ikev2.IKE_HEADER_LEN {
		return nil, false
	}
	if looksLikeIKE(data) {
		return data, true
	}
	return nil, false
}

func looksLikeIKE(data []byte) bool {
	if len(data) < ikev2.IKE_HEADER_LEN {
		return false
	}
	if data[17]>>4 != 2 {
		return false
	}
	ex := ikev2.ExchangeType(data[18])
	switch ex {
	case ikev2.IKE_SA_INIT, ikev2.IKE_AUTH, ikev2.CREATE_CHILD_SA, ikev2.INFORMATIONAL:
		return true
	default:
		return false
	}
}

type SocketStats struct {
	ReceivedIKE uint64
	ReceivedESP uint64
	DroppedIKE  uint64
	DroppedESP  uint64
}

func (s *SocketManager) Stats() SocketStats {
	return SocketStats{
		ReceivedIKE: atomic.LoadUint64(&s.receivedIKE),
		ReceivedESP: atomic.LoadUint64(&s.receivedESP),
		DroppedIKE:  atomic.LoadUint64(&s.droppedIKE),
		DroppedESP:  atomic.LoadUint64(&s.droppedESP),
	}
}

// RawFD 返回底层 UDP socket 的文件描述符
// 用于 XFRM SA 的 ESP-in-UDP encap 配置
func (s *SocketManager) RawFD() (int, error) {
	rawConn, err := s.Conn.SyscallConn()
	if err != nil {
		return -1, fmt.Errorf("获取 SyscallConn 失败: %v", err)
	}

	var fd int
	var fdErr error
	err = rawConn.Control(func(f uintptr) {
		fd = int(f)
	})
	if err != nil {
		return -1, fmt.Errorf("获取 FD 失败: %v", err)
	}
	return fd, fdErr
}

// SetUDPEncap 在 socket 上设置 UDP_ENCAP_ESPINUDP
// 使内核 XFRM 通过此 socket 收发 ESP-in-UDP 包
// 设置后，内核会自动处理 ESP 包的 UDP 封装/解封装
func (s *SocketManager) SetUDPEncap() error {
	rawConn, err := s.Conn.SyscallConn()
	if err != nil {
		return fmt.Errorf("获取 SyscallConn 失败: %v", err)
	}

	var setErr error
	err = rawConn.Control(func(fd uintptr) {
		// UDP_ENCAP = 100, UDP_ENCAP_ESPINUDP = 2
		const (
			solUDP           = 17 // SOL_UDP
			udpEncap         = 100
			udpEncapESPInUDP = 2
		)
		setErr = syscall.SetsockoptInt(int(fd), solUDP, udpEncap, udpEncapESPInUDP)
	})
	if err != nil {
		return fmt.Errorf("Control 调用失败: %v", err)
	}
	if setErr != nil {
		return fmt.Errorf("设置 UDP_ENCAP_ESPINUDP 失败: %v", setErr)
	}

	logger.Info("已在 socket 上设置 UDP_ENCAP_ESPINUDP",
		logger.String("local", s.LocalAddr.String()))
	return nil
}
