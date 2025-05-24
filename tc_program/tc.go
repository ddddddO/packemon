package tc_program

import (
	"fmt"

	"github.com/cilium/ebpf"
)

type AnalyzedPackets struct {
	Sum uint64
}

const (
	// ebpfプログラム側と合わせること。ただ、現状のWSL2だと同一mapに複数のkey指定できない？みたいだった
	SUM_COUNT_KEY = uint32(0)
)

func GetAnalyzedPackets(analysisMap *ebpf.Map) (*AnalyzedPackets, error) {
	if analysisMap == nil {
		return nil, fmt.Errorf("nil analysisMap")
	}

	analyzed := &AnalyzedPackets{}
	err := analysisMap.Lookup(SUM_COUNT_KEY, &analyzed.Sum)
	return analyzed, err
}
