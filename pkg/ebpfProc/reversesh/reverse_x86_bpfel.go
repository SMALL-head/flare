// Code generated by bpf2go; DO NOT EDIT.
//go:build 386 || amd64

package reversesh

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

type reverseEventT struct {
	Pid           uint32
	Ppid          uint32
	SrcFd         uint32
	DstFd         uint32
	TriggerTime   uint64
	Comm          [16]int8
	DstFdFilename [16]int8
}

type reverseFdKeyT struct {
	Pid uint32
	Fd  uint32
}

type reverseFdValueT struct{ Filename [256]int8 }

// loadReverse returns the embedded CollectionSpec for reverse.
func loadReverse() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_ReverseBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load reverse: %w", err)
	}

	return spec, err
}

// loadReverseObjects loads reverse and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*reverseObjects
//	*reversePrograms
//	*reverseMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func loadReverseObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadReverse()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// reverseSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type reverseSpecs struct {
	reverseProgramSpecs
	reverseMapSpecs
	reverseVariableSpecs
}

// reverseProgramSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type reverseProgramSpecs struct {
	KprobeFdInstall                 *ebpf.ProgramSpec `ebpf:"kprobe__fd_install"`
	TracepointSyscallsSysEnterClose *ebpf.ProgramSpec `ebpf:"tracepoint_syscalls__sys_enter_close"`
	TracepointSyscallsSysEnterDup2  *ebpf.ProgramSpec `ebpf:"tracepoint_syscalls__sys_enter_dup2"`
	TracepointSyscallsSysEnterDup3  *ebpf.ProgramSpec `ebpf:"tracepoint_syscalls__sys_enter_dup3"`
}

// reverseMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type reverseMapSpecs struct {
	Dummy  *ebpf.MapSpec `ebpf:"dummy"`
	Events *ebpf.MapSpec `ebpf:"events"`
	FdMap  *ebpf.MapSpec `ebpf:"fd_map"`
	FdMap2 *ebpf.MapSpec `ebpf:"fd_map2"`
}

// reverseVariableSpecs contains global variables before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type reverseVariableSpecs struct {
}

// reverseObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to loadReverseObjects or ebpf.CollectionSpec.LoadAndAssign.
type reverseObjects struct {
	reversePrograms
	reverseMaps
	reverseVariables
}

func (o *reverseObjects) Close() error {
	return _ReverseClose(
		&o.reversePrograms,
		&o.reverseMaps,
	)
}

// reverseMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to loadReverseObjects or ebpf.CollectionSpec.LoadAndAssign.
type reverseMaps struct {
	Dummy  *ebpf.Map `ebpf:"dummy"`
	Events *ebpf.Map `ebpf:"events"`
	FdMap  *ebpf.Map `ebpf:"fd_map"`
	FdMap2 *ebpf.Map `ebpf:"fd_map2"`
}

func (m *reverseMaps) Close() error {
	return _ReverseClose(
		m.Dummy,
		m.Events,
		m.FdMap,
		m.FdMap2,
	)
}

// reverseVariables contains all global variables after they have been loaded into the kernel.
//
// It can be passed to loadReverseObjects or ebpf.CollectionSpec.LoadAndAssign.
type reverseVariables struct {
}

// reversePrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadReverseObjects or ebpf.CollectionSpec.LoadAndAssign.
type reversePrograms struct {
	KprobeFdInstall                 *ebpf.Program `ebpf:"kprobe__fd_install"`
	TracepointSyscallsSysEnterClose *ebpf.Program `ebpf:"tracepoint_syscalls__sys_enter_close"`
	TracepointSyscallsSysEnterDup2  *ebpf.Program `ebpf:"tracepoint_syscalls__sys_enter_dup2"`
	TracepointSyscallsSysEnterDup3  *ebpf.Program `ebpf:"tracepoint_syscalls__sys_enter_dup3"`
}

func (p *reversePrograms) Close() error {
	return _ReverseClose(
		p.KprobeFdInstall,
		p.TracepointSyscallsSysEnterClose,
		p.TracepointSyscallsSysEnterDup2,
		p.TracepointSyscallsSysEnterDup3,
	)
}

func _ReverseClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//
//go:embed reverse_x86_bpfel.o
var _ReverseBytes []byte
