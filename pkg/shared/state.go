package shared

import (
	"sync"
	"time"
)

var (
	GrpcDelay = NewState(2 * time.Minute)
)

type State[T any] struct {
	mu    sync.Mutex
	value T
}

func NewState[T any](value T) *State[T] {
	return &State[T]{value: value}
}

func (s *State[T]) Get() T {
	return s.value
}

func (s *State[T]) Set(value T) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.value = value
}
