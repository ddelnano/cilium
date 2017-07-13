// Copyright 2016-2017 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package kvstore

import (
	"time"

	log "github.com/Sirupsen/logrus"
)

var (
	// LeaseTTL is the time-to-live ofthe lease
	LeaseTTL int64 = 60 * 15 // 15 minutes

	// KeepAliveInterval is the internal in which the lease is being
	// renewed. This must be set to a value lesser than the LeaseTTL
	KeepAliveInterval = time.Duration(5) * time.Minute

	// RetryInterval is the interval in which retries occur in the case of
	// errors in communication with the KVstore. THis should be set to a
	// small value to account for temporary errors while communicating with
	// the KVstore.
	RetryInterval = time.Duration(1) * time.Minute
)

// CreateLease creates a new lease with the given ttl
func CreateLease(ttl int64) (interface{}, error) {
	lease, err := Client.CreateLease(ttl)
	trace("CreateLease ttl=%d => %v, err=%v", ttl, lease, err)
	return lease, err
}

// KeepAlive keeps a lease created with CreateLease alive
func KeepAlive(lease interface{}) error {
	err := Client.KeepAlive(lease)
	trace("KeepAlive %v => err=%v", lease, err)
	return err
}

func init() {
	go func() {
		// start with very short interval until client and lease appear
		sleepTime := time.Duration(1) * time.Second
		for {
			if Client != nil && leaseInstance != nil {
				// once we have client and lease, keep alive in regular interval
				sleepTime = KeepAliveInterval
				if err := KeepAlive(leaseInstance); err != nil {
					log.Warningf("Unable to keep lease alive: %s", err)
					sleepTime = RetryInterval
				}
			}
			time.Sleep(sleepTime)
		}
	}()
}
