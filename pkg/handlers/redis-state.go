package handlers

import (
	"fmt"
	"strings"
	"time"

	"github.com/go-redis/redis/v7"
	"github.com/rs/xid"
	"github.com/sirupsen/logrus"
)

// RedisState represents a state object for the redis state storer.
type RedisState struct {
	redisClusterAddress string
	logger              *logrus.Logger
}

// NewRedisStateStorer creates a new state storage engine based on redis.
func NewRedisStateStorer(address string, logger *logrus.Logger) *RedisState {
	return &RedisState{
		redisClusterAddress: address,
		logger:              logger,
	}
}

// SaveRedirectURIForClient stores the redirect uri for later retrieval.
func (s RedisState) SaveRedirectURIForClient(clientID string, redirect string) (string, error) {
	// use redis as the key value store for holding the redirect uri.
	cli := redis.NewClient(&redis.Options{
		Addr:       s.redisClusterAddress,
		Password:   "", // no password set
		DB:         0,  // use default DB
		MaxRetries: 3,
	})
	defer cli.Close()

	token := xid.New().String()
	key := fmt.Sprintf("/oidc/%v", token)
	value := fmt.Sprintf("%v|%v", clientID, redirect)

	// Lease for this request is 10 minutes, at which point the information will disappear.
	expirey := 10 * time.Minute

	// save the clientid for the token
	err := cli.Set(key, value, expirey).Err()
	if err != nil {
		s.logger.Errorf("Error saving entry: %s - %s. [%s]", key, redirect, err)
		return "", err
	}

	return token, nil
}

// GetRedirectURI returns the previously stored redirect uri based on the state token supplied.
func (s RedisState) GetRedirectURI(token string) (string, string, error) {
	cli := redis.NewClient(&redis.Options{
		Addr:     s.redisClusterAddress,
		Password: "", // no password set
		DB:       0,  // use default DB
	})
	defer cli.Close()

	key := fmt.Sprintf("/oidc/%v", token)

	val, err := cli.Get(key).Result()
	if err == redis.Nil {
		s.logger.Errorf("Entry not found for entry: %s.  Most likely expired [%s].", key, err)
		return "", "", err
	} else if err != nil {
		s.logger.Errorf("Error retrieving entry for id: %s. [%s]", key, err)
		return "", "", err
	}

	values := strings.Split(string(val), "|")
	clientID, redirect := values[0], values[1]

	return clientID, redirect, nil
}
