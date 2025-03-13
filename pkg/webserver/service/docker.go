package docker
import (
	dclient "github.com/docker/docker/client"
)
var (
	DockerClient *dclient.Client
)

func init() {
	DockerClient, _ = dclient.NewClientWithOpts(dclient.WithVersion("1.47"))
}