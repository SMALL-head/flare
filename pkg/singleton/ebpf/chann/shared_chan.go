package chann

import (
	"flare/model/event"
	"sync"
)

var (
	addAuditFileChan     chan *event.FileNameEvent
	addAuditFileChanOnce sync.Once

	deleteAuditFileChan     chan *event.FileNameEvent
	deleteAuditFileChanOnce sync.Once
)

func GetAddAuditFileChan() chan *event.FileNameEvent {
	addAuditFileChanOnce.Do(func() {
		addAuditFileChan = make(chan *event.FileNameEvent, 100)
	})
	return addAuditFileChan
}

func GetDeleteAuditFileChan() chan *event.FileNameEvent {
	deleteAuditFileChanOnce.Do(func() {
		deleteAuditFileChan = make(chan *event.FileNameEvent, 100)
	})
	return deleteAuditFileChan
}
