package ebpfProc

import (
	"bytes"
	"encoding/binary"
	"errors"
	"flare/pkg/singleton/ebpf/chann"
	"flare/pkg/utils/bpfgo"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/sirupsen/logrus"
	"os"
)

var obj containerObjects

func init() {
	// ebpf的所有组件应该只load一次，因此这里使用单例模式是非常合适的
	if err := loadContainerObjects(&obj, nil); err != nil {
		logrus.Fatalf("load ebpf object fail, err = %v", err)
	}
}

func RunContainerEbpf() {
	tailTP, err := link.Tracepoint("syscalls", "sys_enter_execve", obj.containerPrograms.TracepointSyscallsInteractWithUserspace, nil)
	if err != nil {
		logrus.Fatalf("load tail tp program fail, err = %v", err)
	}
	defer tailTP.Close()

	// 监控perf事件并打印
	var event containerEventT
	perfReader, err := perf.NewReader(obj.Events, os.Getpagesize())
	if err != nil {
		logrus.Fatalf("get perf event reader failed, err = %v", err)
	}
	for {
		record, err := perfReader.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				return
			}
			logrus.Fatalf("reading record from perf reader, err = %v", err)
		}

		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
			logrus.Printf("parsing perf event: %s", err)
			continue
		}
		logrus.Printf("[tail]-pid=%d, ppid=%d, event_filename=%s,event_comm=%s",
			event.Pid, event.Ppid, bpfgo.GoString(event.Filename[:]), bpfgo.GoString(event.Comm[:]))
	}
}

func AddMapInfo(key uint32, info *containerInfo) error {
	if obj.containerMaps.Infos == nil {
		return errors.New("map is nil")
	}
	err := obj.containerMaps.Infos.Put(&key, info)
	if err != nil {
		return err
	}
	return nil
}

func DeleteMapInfo(key uint32) error {
	if obj.containerMaps.Infos == nil {
		return errors.New("map is nil")
	}
	err := obj.containerMaps.Infos.Delete(&key)
	if err != nil {
		return err
	}
	return nil
}

func NewInfo(msg string, number int) *containerInfo {
	return &containerInfo{
		Msg:    bpfgo.GoString2BpfCharArray16(msg),
		Number: int32(number),
	}
}

func NewContainerInfo(msg string, n uint32) *containerInfo {
	if len(msg) > 16 {
		return nil
	}
	return &containerInfo{
		Msg:    bpfgo.GoString2BpfCharArray16(msg),
		Number: int32(n),
	}
}

func HandleChan() {
	for {
		select {
		case e := <-chann.GetAddAuditFileChan():
			// TODO: 新增审计文件
			logrus.Infof("receive add audit file event, filename = %s", e.Filename)
		case e := <-chann.GetDeleteAuditFileChan():
			// TODO: 删除审计文件
			logrus.Infof("receive delete audit file event, filename = %s", e.Filename)
		}
	}
}
