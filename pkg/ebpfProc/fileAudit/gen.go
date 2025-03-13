package fileAudit

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go  -target amd64 fileAudit fileAudit.bpf.c -- -I/root/goProject/flare/pkg/include
