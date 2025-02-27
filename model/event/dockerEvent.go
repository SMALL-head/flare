package event

type PodInfo struct {
	PodName   string
	Pid       int
	ImageName string
}

type EventAction string

const (
	AddAction    EventAction = "add"
	DeleteAction EventAction = "delete"
)

type FileNameEvent struct {
	Action   EventAction
	Filename string
}
