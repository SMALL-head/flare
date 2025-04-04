// Code generated by bpf2go; DO NOT EDIT.
//go:build 386 || amd64

package container

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

type containerEventT struct {
	Ppid       int32
	Pid        int32
	MntNsInode uint32
	Comm       [16]int8
	Filename   [160]int8
}

type containerFilesInode struct{ FileInode [10]uint32 }

type containerInfo struct {
	Msg    [16]int8
	Number int32
}

// loadContainer returns the embedded CollectionSpec for container.
func loadContainer() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_ContainerBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load container: %w", err)
	}

	return spec, err
}

// loadContainerObjects loads container and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*containerObjects
//	*containerPrograms
//	*containerMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func loadContainerObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadContainer()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// containerSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type containerSpecs struct {
	containerProgramSpecs
	containerMapSpecs
	containerVariableSpecs
}

// containerProgramSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type containerProgramSpecs struct {
	TracepointSyscallsInteractWithUserspace *ebpf.ProgramSpec `ebpf:"tracepoint_syscalls_interact_with_userspace"`
}

// containerMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type containerMapSpecs struct {
	AuditFiles *ebpf.MapSpec `ebpf:"audit_files"`
	Events     *ebpf.MapSpec `ebpf:"events"`
	Execs      *ebpf.MapSpec `ebpf:"execs"`
	Infos      *ebpf.MapSpec `ebpf:"infos"`
}

// containerVariableSpecs contains global variables before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type containerVariableSpecs struct {
}

// containerObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to loadContainerObjects or ebpf.CollectionSpec.LoadAndAssign.
type containerObjects struct {
	containerPrograms
	containerMaps
	containerVariables
}

func (o *containerObjects) Close() error {
	return _ContainerClose(
		&o.containerPrograms,
		&o.containerMaps,
	)
}

// containerMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to loadContainerObjects or ebpf.CollectionSpec.LoadAndAssign.
type containerMaps struct {
	AuditFiles *ebpf.Map `ebpf:"audit_files"`
	Events     *ebpf.Map `ebpf:"events"`
	Execs      *ebpf.Map `ebpf:"execs"`
	Infos      *ebpf.Map `ebpf:"infos"`
}

func (m *containerMaps) Close() error {
	return _ContainerClose(
		m.AuditFiles,
		m.Events,
		m.Execs,
		m.Infos,
	)
}

// containerVariables contains all global variables after they have been loaded into the kernel.
//
// It can be passed to loadContainerObjects or ebpf.CollectionSpec.LoadAndAssign.
type containerVariables struct {
}

// containerPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadContainerObjects or ebpf.CollectionSpec.LoadAndAssign.
type containerPrograms struct {
	TracepointSyscallsInteractWithUserspace *ebpf.Program `ebpf:"tracepoint_syscalls_interact_with_userspace"`
}

func (p *containerPrograms) Close() error {
	return _ContainerClose(
		p.TracepointSyscallsInteractWithUserspace,
	)
}

func _ContainerClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//
//go:embed container_x86_bpfel.o
var _ContainerBytes []byte
