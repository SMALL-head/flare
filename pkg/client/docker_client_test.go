package client_test

import (
	"context"
	"flare/pkg/client"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

func TestClient(t *testing.T) {
	c, _ := client.NewDockerClient()
	resp, err := c.ContainerInspect(context.TODO(), "u2")
	require.NoError(t, err)
	logrus.Info(resp.State.Pid)
}
