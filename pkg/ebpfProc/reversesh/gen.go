package reversesh

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go  -target amd64 reverse reverse.bpf.c -- -I/root/goProject/flare/pkg/include
