package service

import "sync/atomic"

type SvcRuntimeData struct {
	// true: 反弹shell审计打开； false：反弹shell审计关闭
	reverseShPluginStatus atomic.Bool
}

var (
	Svc *SvcRuntimeData
)

func init() {
	Svc = &SvcRuntimeData{}
}
