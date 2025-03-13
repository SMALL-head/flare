package status

var (
	PodNameMntInode map[string]uint32
)

func init() {
	PodNameMntInode = make(map[string]uint32)
}
