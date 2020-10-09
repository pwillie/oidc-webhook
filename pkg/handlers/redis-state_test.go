package handlers

import (
	"strings"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/go-redis/redis/v7"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func TestSaveRedirectURIForClient(t *testing.T) {
	logger := logrus.New()
	mr, err := miniredis.Run()
	if err != nil {
		panic(err)
	}
	defer mr.Close()

	ss := NewRedisStateStorer(mr.Addr(), logger)
	ss.SaveRedirectURIForClient("testClient", "https://boo.finbourne.com")
	list := mr.Keys()
	assert.Equal(t, 1, len(list))
	value, _ := mr.Get(list[0])
	assert.Equal(t, "testClient|https://boo.finbourne.com", value)
}

func TestGetRedirectURI(t *testing.T) {
	logger := logrus.New()
	mr, err := miniredis.Run()
	if err != nil {
		panic(err)
	}
	defer mr.Close()

	ss := NewRedisStateStorer(mr.Addr(), logger)
	ss.SaveRedirectURIForClient("testClient", "https://boo.finbourne.com")
	list := mr.Keys()
	assert.Equal(t, 1, len(list))
	value1, value2, _ := ss.GetRedirectURI(strings.Split(list[0], "/")[2])
	assert.Equal(t, "testClient", value1)
	assert.Equal(t, "https://boo.finbourne.com", value2)
}

func TestGetRedirectURIFailsIfNotPresent(t *testing.T) {
	logger := logrus.New()
	mr, err := miniredis.Run()
	if err != nil {
		panic(err)
	}
	defer mr.Close()

	ss := NewRedisStateStorer(mr.Addr(), logger)
	value1, value2, err := ss.GetRedirectURI("token1234")
	assert.Equal(t, "", value1)
	assert.Equal(t, "", value2)
	assert.Equal(t, redis.Nil, err)
}
