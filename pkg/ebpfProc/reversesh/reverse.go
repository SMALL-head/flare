package reversesh

import (
	"bytes"
	"encoding/binary"
	"errors"
	"flare/pkg/utils/bpfgo"
	"log"
	"os"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
)

func AuditReverseSh() {
	var obj reverseObjects
	if err := loadReverseObjects(&obj, nil); err != nil {
		log.Fatalf("load ebpf object fail: %v", err)
	}

	kprobeProg, err := link.Kprobe("fd_install", obj.reversePrograms.KprobeFdInstall, nil)
	if err != nil {
		log.Fatalf("attach kprobe prog to fd_install failed, err = %v", err)
	}
	defer kprobeProg.Close()

	dup2TP, err := link.Tracepoint("syscalls", "sys_enter_dup2", obj.reversePrograms.TracepointSyscallsSysEnterDup2, nil)
	if err != nil {
		log.Fatalf("attach dup2 tp failed, err = %v", err)
	}
	defer dup2TP.Close()

	dup3TP, err := link.Tracepoint("syscalls", "sys_enter_dup3", obj.reversePrograms.TracepointSyscallsSysEnterDup3, nil)
	if err != nil {
		log.Fatalf("attach dup3 tp failed, err = %v", err)
	}
	defer dup3TP.Close()

	closeTP, err := link.Tracepoint("syscalls", "sys_enter_close", obj.reversePrograms.TracepointSyscallsSysEnterClose, nil)
	if err != nil {
		log.Fatalf("attach close tp failed, err = %v", err)
	}
	defer closeTP.Close()

	// 监控perf事件并打印
	var event reverseEventT
	perfReader, err := perf.NewReader(obj.Events, os.Getpagesize())
	if err != nil {
		log.Fatalf("get perf event reader failed, err = %v", err)
	}
	for {
		record, err := perfReader.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				return
			}
			log.Fatalf("reading record from perf reader, err = %v", err)
		}

		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
			log.Printf("parsing perf event: %s", err)
			continue
		}
		log.Printf("pid:%d ppid: %d:%s redirect %d -> %d:%s", event.Pid, event.Ppid, bpfgo.GoString(event.Comm[:]),
			event.SrcFd, event.DstFd, bpfgo.GoString(event.DstFdFilename[:]))
	}
}
