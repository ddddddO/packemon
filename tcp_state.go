package packemon

type TCPState int

const (
	TCP_STATE_INIT TCPState = iota
	TCP_STATE_3WAY_HANDSHAKE_SEND_SYN
	TCP_STATE_3WAY_HANDSHAKE_PASSIVE_SYNACK
	TCP_STATE_3WAY_HANDSHAKE_SEND_ACK // = established tcp connection
	TCP_STATE_PASSIVE_PSHACK          // = データ受信
	TCP_STATE_SEND_FINACK             // = tcp connection を終えたい
	TCP_STATE_PASSIVE_FINACK
	TCP_STATE_SEND_ACK
)

type TCPConnection struct {
	currentState TCPState
	SrcPort      uint16
	DstPort      uint16
	established  bool
}

func NewTCPConnection(SrcPort uint16, DstPort uint16) *TCPConnection {
	return &TCPConnection{
		currentState: TCP_STATE_INIT,
		SrcPort:      SrcPort,
		DstPort:      DstPort,
	}
}

func (conn *TCPConnection) SetState(state TCPState) {
	conn.currentState = state
}

func (conn *TCPConnection) IsPassiveSynAckForHandshake(tcp *TCP) bool {
	if conn.established {
		return false
	}
	if conn.currentState != TCP_STATE_3WAY_HANDSHAKE_SEND_SYN {
		return false
	}
	if tcp.DstPort != conn.SrcPort {
		return false
	}
	if tcp.Flags == TCP_FLAGS_SYN_ACK {
		conn.currentState = TCP_STATE_3WAY_HANDSHAKE_PASSIVE_SYNACK
		return true
	}
	return false
}

func (conn *TCPConnection) EstablishedConnection() {
	conn.established = true
}

func (conn *TCPConnection) Close() {
	conn.established = false
}

func (conn *TCPConnection) IsPassiveAck(tcp *TCP) bool {
	if !conn.established {
		return false
	}
	if tcp.DstPort != conn.SrcPort {
		return false
	}
	if tcp.Flags == TCP_FLAGS_ACK {
		// TODO: ここでACK送りましたstateセットしても意味がある？
		//       state セットするの意味あるのは初めと終わりの時のハンドシェイクくらい？
		return true
	}
	return false
}

func (conn *TCPConnection) IsPassivePshAck(tcp *TCP) bool {
	if !conn.established {
		return false
	}
	if tcp.DstPort != conn.SrcPort {
		return false
	}
	if tcp.Flags == TCP_FLAGS_PSH_ACK {
		conn.currentState = TCP_STATE_PASSIVE_PSHACK
		return true
	}
	return false
}

func (conn *TCPConnection) IsPassiveFinAck(tcp *TCP) bool {
	if !conn.established {
		return false
	}
	if tcp.DstPort != conn.SrcPort {
		return false
	}
	if tcp.Flags == TCP_FLAGS_FIN_ACK {
		conn.currentState = TCP_STATE_PASSIVE_FINACK
		return true
	}
	return false
}
