package reversesh

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"flare/grpc/reversesh"
	"flare/pkg/client"
	"flare/pkg/shared"
	"flare/pkg/utils/bpfgo"
	"flare/pkg/utils/delay"
	"fmt"
	"log"
	"os"

	"github.com/sirupsen/logrus"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
)

var (
	perfReaderRecordCh chan perf.Record
	grpcCallCh         chan reverseEventT
)

type ctxKey string

const (
	NodeNameKey    ctxKey = "nodeName"
	GrpcDelayKey   ctxKey = "grpcDelay"
	SharedStateKey ctxKey = "sharedState"
)

func init() {
	perfReaderRecordCh = make(chan perf.Record, 100)
	grpcCallCh = make(chan reverseEventT, 100)
}

func AuditReverseSh(ctx context.Context) {
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
	//var event reverseEventT
	perfReader, err := perf.NewReader(obj.Events, os.Getpagesize())
	if err != nil {
		log.Fatalf("get perf event reader failed, err = %v", err)
	}
	defer perfReader.Close()

	// 从ctx中获取nodeName
	v := ctx.Value(NodeNameKey)
	nodeName, ok := v.(string)
	if !ok {
		logrus.Errorf("failed to get nodeName from context, using default 'unknown-node'")
		nodeName = "unknown-node"
	}

	up := true
	go func() {
		for up {
			record, err := perfReader.Read()
			if err != nil {
				if errors.Is(err, perf.ErrClosed) {
					break
				}
				logrus.Errorf("reading record from perf reader, err = %v", err)
				continue
			}

			perfReaderRecordCh <- record
		}
		logrus.Infof("shutdown goroutine from AuditReverseSh plugin")
	}()

	delayScheduler := delay.NewDelayScheduler()
	defer delayScheduler.Shutdown()

	for {
		select {
		case <-ctx.Done():
			logrus.Println("🔴 Stopping AuditReverseSh()...")
			up = false
			return
		case record := <-perfReaderRecordCh:
			var event reverseEventT
			if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
				logrus.Printf("parsing perf event: %s", err)
				continue
			}
			printEvent(event)
			// 2min后调度
			delayScheduler.Schedule(
				context.Background(),
				fmt.Sprintf("%d", event.TriggerTime),
				shared.GrpcDelay.Get(),
				func() {
					r, err := grpcReversesh(event, nodeName)
					if err != nil {
						logrus.Errorf("[grpcReversesh] failed to get mal ctid request, err = %v", err)
						return
					}
					// 请求flare-admin的存储信息
					_ = client.GetWebClientSet().FlareAdmin.ReverseShRecord(r.CTIDs, r.Message, r.Syscall, nodeName)
					// 零信任引擎申请下降
					if len(r.CTIDs) > 0 {
						err = client.GetWebClientSet().ZeroTrustNotifyReversesh(r.CTIDs[0], "")
						if err != nil {
							logrus.Errorf("[ZeroTrustNotifyReversesh] notify zerotrust engine reversesh record failed, err = %v", err)
						}
					}
				},
			)
		}
	}

}

func printEvent(event reverseEventT) {
	logrus.Printf("pid:%d ppid: %d:%s redirect %d -> %d:%s, time %d", event.Pid, event.Ppid, bpfgo.GoString(event.Comm[:]),
		event.SrcFd, event.DstFd, bpfgo.GoString(event.DstFdFilename[:]), event.TriggerTime)
}

func grpcReversesh(event reverseEventT, nodeName string) (reversesh.Reply, error) {
	logrus.Infof("[grpcReversesh] sending grpc request for pid: %d, time: %d, nodeName: %s", event.Pid, event.TriggerTime, nodeName)
	r, err := reversesh.GetInstance().GetMalCTIDRequest(nodeName, event.Pid, event.TriggerTime)
	if err != nil {
		logrus.Errorf("[grpcReversesh] get mal ctid request failed, err = %v", err)
		return reversesh.Reply{}, err
	}
	logrus.Infof("[grpcReversesh] get mal ctid request success, ctid = %v, message = %s, syscall = %s",
		r.CTIDs, r.Message, r.Syscall)

	return r, nil
}
