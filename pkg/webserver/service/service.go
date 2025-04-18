package service

import (
	"context"
	"flare/pkg/ebpfProc/reversesh"
	"sync/atomic"

	"github.com/sirupsen/logrus"
)

const (
	reverseShPlugin = "reverseSh"
	fileAuditPlugin = "fileAudit"
)

var (
	PluginFuncMap = map[string]func(ctx context.Context){}
)

type SvcRuntimeData struct {
	// 插件是否被开启
	pluginStatus map[string]*atomic.Bool

	// 插件取消的函数指针
	pluginDisableContext map[string]context.CancelFunc
}

var (
	Svc *SvcRuntimeData
)

func init() {
	status := map[string]*atomic.Bool{}
	status[reverseShPlugin] = &atomic.Bool{}
	status[fileAuditPlugin] = &atomic.Bool{}
	PluginFuncMap[reverseShPlugin] = reversesh.AuditReverseSh
	Svc = &SvcRuntimeData{
		pluginStatus:         status,
		pluginDisableContext: make(map[string]context.CancelFunc),
	}
}

func (s *SvcRuntimeData) EnableNamedPlugin(name string) bool {
	if enabled, ok := s.pluginStatus[name]; ok {
		// 插件名存在，就可以进行下面的操作
		if enabled.Load() {
			return true
		} else if enabled.CompareAndSwap(false, true) {
			// 开启插件
			ctx, cancel := context.WithCancel(context.Background())
			// 保证只在这里进行写操作
			s.pluginDisableContext[name] = cancel
			go PluginFuncMap[name](ctx)
			logrus.Infof("reverse sh plugin %s enabled", name)
			return true
		} else {
			return false
		}
	} else {
		// 插件名不存在
		return false
	}
}

func (s *SvcRuntimeData) DisableNamedPlugin(name string) bool {
	if cancelFunc, exists := s.pluginDisableContext[name]; !exists {
		logrus.Errorf("plugin %s does not exist", name)
		return false
	} else {
		cancelFunc()
		delete(s.pluginDisableContext, name)
		s.pluginStatus[name].Store(false)
		logrus.Infof("reverse sh plugin %s disabled", name)
		return true
	}
}

func (s *SvcRuntimeData) CloseAllPlugins() {
	for name, cancelFunc := range s.pluginDisableContext {
		cancelFunc()
		delete(s.pluginDisableContext, name)
		s.pluginStatus[name].Store(false)
		logrus.Infof("plugin %s disabled", name)
	}
}
