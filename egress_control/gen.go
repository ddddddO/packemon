package egress_control

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go egress_packet egress_packet.bpf.c
