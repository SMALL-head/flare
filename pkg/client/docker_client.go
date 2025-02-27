package client

import (
	dclient "github.com/docker/docker/client"
)

func NewDockerClient() (*dclient.Client, error) {
	return dclient.NewClientWithOpts(dclient.WithVersion("1.47"))
}
