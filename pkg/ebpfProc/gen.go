package ebpfProc

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go  -target amd64 container container.bpf.c -- -I/root/goProject/flare/pkg/include
