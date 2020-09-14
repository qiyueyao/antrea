// Copyright 2020 Antrea Authors
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

package openflow

import (
	"github.com/contiv/ofnet/ofctrl"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog"
)

type PacketInHandler interface {
	HandlePacketIn(pktIn *ofctrl.PacketIn) error
}

const (
	// Max packetInQueue size.
	packetInQueueSize int = 256
)

func (c *client) RegisterPacketInHandler(packetHandlerReason uint8, packetHandlerName string, packetInHandler interface{}) {
	handler, ok := packetInHandler.(PacketInHandler)
	if !ok {
		klog.Errorf("Invalid controller.")
		return
	}
	if c.packetInHandlers[packetHandlerReason] == nil {
		c.packetInHandlers[packetHandlerReason] = map[string]PacketInHandler{}
	}
	c.packetInHandlers[packetHandlerReason][packetHandlerName] = handler
}

func (c *client) StartPacketInHandler(packetInStartedReason []uint8, stopCh <-chan struct{}) {
	if len(c.packetInHandlers) == 0 || len(packetInStartedReason) == 0 {
		return
	}
	// Subscribe packetin for with reason 1
	ch := make(chan *ofctrl.PacketIn)
	err := c.SubscribePacketIn(packetInStartedReason[0], ch)
	if err != nil {
		klog.Errorf("Subscribe PacketIn failed %+v", err)
		return
	}
	packetInQueue := workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "tf np")
	go c.parsePacketInRateLimiting(packetInQueue, packetInStartedReason[0])

	for {
		select {
		case pktIn := <-ch:
			// Ensure that the queue doesn't grow too big. This is NOT to provide an exact guarantee.
			if packetInQueue.Len() < packetInQueueSize {
				packetInQueue.Add(pktIn)
			} else {
				klog.Warningf("Max packetInQueue size exceeded.")
			}
		case <-stopCh:
			packetInQueue.ShutDown()
			break
		}
	}
}

func (c *client) parsePacketIn(packetInQueue workqueue.Interface, packetHandlerReason uint8) {
	for {
		obj, quit := packetInQueue.Get()
		if quit {
			break
		}
		packetInQueue.Done(obj)
		pktIn, ok := obj.(*ofctrl.PacketIn)
		if !ok {
			klog.Errorf("Invalid packetin data in queue, skipping.")
			continue
		}
		// Use corresponding handlers subscribed to the reason to handle PacketIn
		for name, handler := range c.packetInHandlers[packetHandlerReason] {
			err := handler.HandlePacketIn(pktIn)
			if err != nil {
				klog.Errorf("PacketIn handler %s failed to process packet: %+v", name, err)
			}
		}
	}
}

func (c *client) parsePacketInRateLimiting(packetInQueue workqueue.RateLimitingInterface, packetHandlerReason uint8) {
	for {
		obj, quit := packetInQueue.Get()
		if quit {
			break
		}
		packetInQueue.Done(obj)
		pktIn, ok := obj.(*ofctrl.PacketIn)
		if !ok {
			klog.Errorf("Invalid packetin data in queue, skipping.")
			// remove rate limit tracking for invalid packetin
			packetInQueue.Forget(obj)
			continue
		}
		// Use corresponding handlers subscribed to the reason to handle PacketIn
		for name, handler := range c.packetInHandlers[packetHandlerReason] {
			err := handler.HandlePacketIn(pktIn)
			if err != nil {
				klog.Errorf("PacketIn handler %s failed to process packet: %+v", name, err)
			}
		}
		// reset rate limit tracking for succeeded objects
		packetInQueue.Forget(obj)
	}
}
