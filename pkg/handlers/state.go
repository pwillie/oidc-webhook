package handlers

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/Sirupsen/logrus"
	"github.com/coreos/etcd/clientv3"
	"github.com/rs/xid"
)

// EtcdState represents a state object for the etcd state storer.
type EtcdState struct {
	etcdClusterAddress []string
	logger             *logrus.Logger
}

// NewEtcdStateStorer creates a new state storage engine based on etcd.
func NewEtcdStateStorer(addresses []string, logger *logrus.Logger) *EtcdState {
	return &EtcdState{
		etcdClusterAddress: addresses,
		logger:             logger,
	}
}

// SaveRedirectURI stores the redirect uri for later retrieval.
func (s EtcdState) SaveRedirectURIForClient(clientID string, redirect string) (string, error) {
	// use etcd as the key value store for holding the redirect uri.
	cli, err := clientv3.New(clientv3.Config{
		Endpoints:   s.etcdClusterAddress,
		DialTimeout: 2 * time.Second,
	})
	if err != nil {
		s.logger.Errorf("Error creating client: %v", err)
		s.logger.Errorf("ETCD cluster: %v", s.etcdClusterAddress)
		return "", err
	}
	defer cli.Close()

	token := xid.New().String()
	key := fmt.Sprintf("/oidc/%v", token)
	value := fmt.Sprintf("%v|%v", clientID, redirect)

	// Lease for this request is 10 minutes, at which point the information will disappear.
	lease, err := cli.Grant(context.TODO(), 600)
	if err != nil {
		log.Fatal(err)
	}

	timeout := 2 * time.Second

	// save the clientid for the token
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	_, err = cli.Put(ctx, key, value, clientv3.WithLease(lease.ID))
	cancel()
	if err != nil {
		s.logger.Errorf("Error saving entry.", err, key, redirect)
		return "", err
	}

	return token, nil
}

// GetRedirectURI returns the previously stored redirect uri based on the state token supplied.
func (s EtcdState) GetRedirectURI(token string) (string, string, error) {
	cli, err := clientv3.New(clientv3.Config{
		Endpoints:   s.etcdClusterAddress,
		DialTimeout: 2 * time.Second,
	})
	if err != nil {
		s.logger.Errorf("Error creating client.", err)
		return "", "", err
	}
	defer cli.Close()

	key := fmt.Sprintf("/oidc/%v", token)

	timeout := 2 * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	resp, err := cli.Get(ctx, key)
	cancel()
	if err != nil {
		s.logger.Errorf("Error retrieving entry for id.", err, key)
		return "", "", err
	}
	if len(resp.Kvs) == 0 {
		s.logger.Errorf("Entry not found for entry.  Most likely expired.", err, key)
		return "", "", err
	}

	values := strings.Split(string(resp.Kvs[0].Value), "|")
	clientID, redirect := values[0], values[1]

	return clientID, redirect, nil
}
