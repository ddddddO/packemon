package generator

import (
	"github.com/cilium/ebpf"
	tc "github.com/ddddddO/packemon/tc_program"
)

type analyzer struct {
	ingress *ebpf.Map
	egress  *ebpf.Map
}

func (a *analyzer) AnalysisIngress() (*tc.AnalyzedPackets, error) {
	return tc.GetAnalyzedPackets(a.ingress)
}

func (a *analyzer) AnalysisEgress() (*tc.AnalyzedPackets, error) {
	return tc.GetAnalyzedPackets(a.egress)
}
