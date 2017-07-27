package kvstore

import (
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"strconv"
	"strings"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/cilium/cilium/common"
	"github.com/cilium/cilium/common/types"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/samuel/go-zookeeper/zk"
)

const (
	defaultTimeout = time.Second
	zAddr          = "zookeeper.address"
)

var ZkOpts = map[string]bool{
	zAddr: true,
}

type ZkConfig struct {
	Endpoints []string
}

type ZkClient struct {
	conn    *zk.Conn
	servers []string
}

func newZkClient() (KVClient, error) {
	endpoints := zkConfig.Endpoints

	conn, _, err := zk.Connect(endpoints, defaultTimeout)

	if err != nil {
		return nil, err
	}

	return &ZkClient{
		conn:    conn,
		servers: endpoints,
	}, nil
}

func (c *ZkClient) LockPath(path string) (KVLocker, error) {
	log.Debugf("Creating lock for %s", path)
	lock := zk.NewLock(c.conn, path, zk.WorldACL(zk.PermAll))
	err := lock.Lock()

	if err != nil {
		return lock, err
	}

	return lock, err
}

func (c *ZkClient) GetValue(k string) (bytes json.RawMessage, err error) {
	bytes, _, err = c.conn.Get(k)

	if err == zk.ErrNoNode || len(bytes) == 0 {
		return nil, nil
	}

	return bytes, err
}

func (c *ZkClient) SetValue(k string, v interface{}) error {
	vByte, err := json.Marshal(v)
	if err != nil {
		return err
	}
	_, err = c.conn.Set(k, vByte, int32(-1))

	if err == zk.ErrNoNode {
		err = c.ensurePath(k, vByte)
	}
	return err
}

func (c *ZkClient) InitializeFreeID(path string, firstID uint32) error {
	kvLocker, err := c.LockPath(path)
	if err != nil {
		return err
	}
	defer kvLocker.Unlock()

	log.Debug("Trying to acquire free ID...")
	k, err := c.GetValue(path)
	if err != nil {
		return err
	}
	if k != nil {
		// FreeID already set
		return nil
	}
	log.Debugf("Trying to put free ID...")
	err = c.SetValue(path, firstID)
	if err != nil {
		return err
	}
	log.Debugf("Free ID for path %s successfully initialized", path)

	return nil
}

func (c *ZkClient) GetMaxID(key string, firstID uint32) (uint32, error) {
	var (
		attempts = 3
		value    json.RawMessage
		err      error
		freeID   uint32
	)
	for {
		switch value, err = c.GetValue(key); {
		case attempts == 0:
			err = fmt.Errorf("Unable to retrieve last free ID because key is always empty")
			log.Error(err)
			fallthrough
		case err == zk.ErrNoNode || len(value) == 0:
			log.Debugf("Empty FreeID, setting it up with default value %d", firstID)
			if err := c.InitializeFreeID(key, firstID); err != nil {
				return 0, err
			}
			attempts--
		case err != nil:
			return 0, err
		case err == nil:
			if err := json.Unmarshal(value, &freeID); err != nil {
				return 0, err
			}
			log.Debugf("Retrieving max free ID %d", freeID)
			return freeID, nil
		}
	}
}

func (c *ZkClient) SetMaxID(key string, firstID, maxID uint32) error {
	value, err := c.GetValue(key)
	if err != nil {
		return err
	}
	if value == nil {
		// FreeID is empty? We should set it out!
		log.Debugf("Empty FreeID, setting it up with default value %d", firstID)
		if err := c.InitializeFreeID(key, firstID); err != nil {
			return err
		}
		k, err := c.GetValue(key)
		if err != nil {
			return err
		}
		if k == nil {
			// Something is really wrong
			errMsg := "Unable to setting ID because the key is always empty\n"
			log.Errorf(errMsg)
			return fmt.Errorf(errMsg)
		}
	}
	return c.SetValue(key, maxID)
}

func (c *ZkClient) setMaxLabelID(maxID uint32) error {
	return c.SetMaxID(common.LastFreeLabelIDKeyPath, uint32(policy.MinimalNumericIdentity), maxID)
}

func (c *ZkClient) GASNewSecLabelID(baseKeyPath string, baseID uint32, secCtxLabels *policy.Identity) error {
	setID2Label := func(new_id uint32) error {
		secCtxLabels.ID = policy.NumericIdentity(new_id)
		keyPath := path.Join(baseKeyPath, secCtxLabels.ID.StringID())
		if err := c.SetValue(keyPath, secCtxLabels); err != nil {
			return err
		}
		return c.setMaxLabelID(new_id + 1)
	}

	acquireFreeID := func(firstID uint32, incID *uint32) (bool, error) {
		log.Debugf("Trying to acquire a new free ID %d", *incID)
		keyPath := path.Join(baseKeyPath, strconv.FormatUint(uint64(*incID), 10))

		locker, err := c.LockPath(GetLockPath(keyPath))
		if err != nil {
			return false, err
		}
		defer locker.Unlock()

		value, err := c.GetValue(keyPath)
		if err != nil {
			return false, err
		}
		if value == nil {
			return false, setID2Label(*incID)
		}
		var consulLabels policy.Identity
		if err := json.Unmarshal(value, &consulLabels); err != nil {
			return false, err
		}
		if consulLabels.RefCount() == 0 {
			log.Infof("Recycling ID %d", *incID)
			return false, setID2Label(*incID)
		}

		*incID++
		if *incID > common.MaxSetOfLabels {
			*incID = policy.MinimalNumericIdentity.Uint32()
		}
		if firstID == *incID {
			return false, fmt.Errorf("reached maximum set of labels available.")
		}
		return true, nil
	}

	beginning := baseID
	for {
		retry, err := acquireFreeID(beginning, &baseID)
		if err != nil {
			return err
		} else if !retry {
			return nil
		}
	}
}

func (c *ZkClient) setMaxL3n4AddrID(maxID uint32) error {
	return c.SetMaxID(common.LastFreeServiceIDKeyPath, common.FirstFreeServiceID, maxID)
}

func (c *ZkClient) GASNewL3n4AddrID(basePath string, baseID uint32, lAddrID *types.L3n4AddrID) error {
	setIDtoL3n4Addr := func(id uint32) error {
		lAddrID.ID = types.ServiceID(id)
		keyPath := path.Join(basePath, strconv.FormatUint(uint64(lAddrID.ID), 10))
		if err := c.SetValue(keyPath, lAddrID); err != nil {
			return err
		}
		return c.setMaxL3n4AddrID(id + 1)
	}

	acquireFreeID := func(firstID uint32, incID *uint32) error {
		log.Debugf("Trying to acquire a new free ID %d", *incID)
		keyPath := path.Join(basePath, strconv.FormatUint(uint64(*incID), 10))

		locker, err := c.LockPath(GetLockPath(keyPath))
		if err != nil {
			return err
		}
		defer locker.Unlock()

		value, err := c.GetValue(keyPath)
		if err != nil {
			return err
		}
		if value == nil {
			return setIDtoL3n4Addr(*incID)
		}
		var consulL3n4AddrID types.L3n4AddrID
		if err := json.Unmarshal(value, &consulL3n4AddrID); err != nil {
			return err
		}
		if consulL3n4AddrID.ID == 0 {
			log.Infof("Recycling Service ID %d", *incID)
			return setIDtoL3n4Addr(*incID)
		}

		*incID++
		if *incID > common.MaxSetOfServiceID {
			*incID = common.FirstFreeServiceID
		}
		if firstID == *incID {
			return fmt.Errorf("reached maximum set of serviceIDs available.")
		}
		return nil
	}

	var err error
	beginning := baseID
	for {
		if err = acquireFreeID(beginning, &baseID); err != nil {
			return err
		} else if beginning == baseID {
			return nil
		}
	}
}

func (c *ZkClient) DeleteTree(path string) error {
	err := c.conn.Delete(path, -1)
	// Mask if the node does not exist
	if err != nil && err != zk.ErrNoNode {
		return fmt.Errorf("Failed to remove %q: %v", path, err)
	}
	return err
}

func (c *ZkClient) GetWatcher(key string, timeSleep time.Duration) <-chan []policy.NumericIdentity {
	ch := make(chan []policy.NumericIdentity, 100)
	go func(ch chan []policy.NumericIdentity) {
		curSeconds := time.Second
		var events <-chan zk.Event
		var err error
		for {
			_, _, events, err = c.conn.GetW(key)

			if err != nil {
				time.Sleep(curSeconds)

				if curSeconds < timeSleep {
					curSeconds += timeSleep
				}
				continue
			}

			break
		}
		freeID := uint32(0)
		maxFreeID := uint32(0)

		for event := range events {

			val, err := c.GetValue(event.Path)

			if err != nil {
				continue
			}

			if err := json.Unmarshal(val, &freeID); err != nil {
				continue
			}

			if freeID > maxFreeID {
				maxFreeID = freeID
			}
			if maxFreeID != 0 {
				ch <- []policy.NumericIdentity{policy.NumericIdentity(maxFreeID)}
			}
		}
	}(ch)
	return ch
}

func (c *ZkClient) Status() (string, error) {
	stats, ok := zk.FLWSrvr(c.servers, defaultTimeout)

	var leader *zk.ServerStats
	for _, stat := range stats {
		switch stat.Mode {
		case zk.ModeLeader:
			leader = stat
		}
	}

	if !ok || leader == nil {
		return "Cluster unhealthy", errors.New("Cluster unhealthy")
	}

	return "Zookeeper: ", nil
}

// Method was repurposed from https://github.com/hashicorp/vault/blob/master/physical/zookeeper.go#L134
// We avoid calling this optimistically, and invoke it when we get
// an error during an operation
func (c *ZkClient) ensurePath(path string, value []byte) error {
	nodes := strings.Split(path, "/")
	fullPath := ""
	for index, node := range nodes {
		if strings.TrimSpace(node) != "" {
			fullPath += "/" + node
			isLastNode := index+1 == len(nodes)

			// set parent nodes to nil, leaf to value
			// this block reduces round trips by being smart on the leaf create/set
			if exists, _, _ := c.conn.Exists(fullPath); !isLastNode && !exists {
				if _, err := c.conn.Create(fullPath, nil, int32(0), zk.WorldACL(zk.PermAll)); err != nil {
					return err
				}
			} else if isLastNode && !exists {
				if _, err := c.conn.Create(fullPath, value, int32(0), zk.WorldACL(zk.PermAll)); err != nil {
					return err
				}
			} else if isLastNode && exists {
				if _, err := c.conn.Set(fullPath, value, int32(-1)); err != nil {
					return err
				}
			}
		}
	}
	return nil
}
