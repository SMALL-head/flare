package service

import (
	"context"
	"errors"
	"flare/pkg/ebpfProc/reversesh"
	"flare/pkg/shared"
	"os"
	"regexp"
	"strconv"
	"sync/atomic"
	"time"

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

	nodeName string
}

var (
	Svc *SvcRuntimeData
)

func init() {
	status := map[string]*atomic.Bool{}
	status[reverseShPlugin] = &atomic.Bool{}
	status[fileAuditPlugin] = &atomic.Bool{}
	PluginFuncMap[reverseShPlugin] = reversesh.AuditReverseSh
	// 从env中获取nodeName
	nodeName := os.Getenv("NODE_NAME")
	logrus.Infof("[service] init 获取到NODE_NAME: %s", nodeName)
	Svc = &SvcRuntimeData{
		pluginStatus:         status,
		pluginDisableContext: make(map[string]context.CancelFunc),
		nodeName:             nodeName,
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
			ctx = context.WithValue(ctx, reversesh.NodeNameKey, s.nodeName)
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

func (s *SvcRuntimeData) SetGrpcDelay(delay string) error {
	// 正则表达式
	if delay == "" {
		return errors.New("grpc delay cannot be empty")
	}
	pattern := `^(\d+)(m|s)$`
	regex := regexp.MustCompile(pattern)
	matches := regex.FindStringSubmatch(delay)
	if len(matches) != 3 {
		return errors.New("grpc delay format is invalid, should be like '2s' or '5m'")
	}
	value, err := strconv.Atoi(matches[1])
	if err != nil {
		return errors.New("grpc delay value is not a valid integer")
	}
	unit := matches[2]
	var d time.Duration
	switch unit {
	case "s":
		d = time.Duration(value) * time.Second
	case "m":
		d = time.Duration(value) * time.Minute
	default:
		return errors.New("grpc delay unit must be 's' or 'm'")
	}
	shared.GrpcDelay.Set(d)
	return nil
}
