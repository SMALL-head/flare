package delay

import (
	"context"
	"sync"
	"time"
)

type Task struct {
	timer  *time.Timer
	cancel context.CancelFunc
}

type DelayScheduler struct {
	mu    sync.Mutex
	tasks map[string]*Task
}

func NewDelayScheduler() *DelayScheduler {
	return &DelayScheduler{
		tasks: make(map[string]*Task),
	}
}

func (ds *DelayScheduler) Schedule(ctx context.Context, key string, delay time.Duration, taskFunc func()) bool {
	ds.mu.Lock()
	defer ds.mu.Unlock()
	if _, exists := ds.tasks[key]; exists {
		return false
	}
	ctx, cancel := context.WithCancel(ctx)
	timer := time.AfterFunc(delay, func() {
		select {
		case <-ctx.Done():
			return // 任务被取消，不执行
		default:
			taskFunc() // 执行任务
		}

		ds.mu.Lock()
		delete(ds.tasks, key)
		ds.mu.Unlock()
	})

	ds.tasks[key] = &Task{
		timer:  timer,
		cancel: cancel,
	}
	return true
}

func (ds *DelayScheduler) Cancel(key string) bool {
	ds.mu.Lock()
	defer ds.mu.Unlock()
	task, exists := ds.tasks[key]
	if !exists {
		return false
	}
	task.timer.Stop()     // 停止定时器
	task.cancel()         // 取消上下文
	delete(ds.tasks, key) // 从任务列表中删除
	return true
}

func (ds *DelayScheduler) Shutdown() {
	ds.mu.Lock()
	defer ds.mu.Unlock()
	for key, task := range ds.tasks {
		task.timer.Stop()     // 停止所有定时器
		task.cancel()         // 取消所有上下文
		delete(ds.tasks, key) // 从任务列表中删除
	}
}
