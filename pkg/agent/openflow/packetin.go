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

type ofpPacketInReason uint

type PacketInHandler interface {
	HandlePacketIn(pktIn *ofctrl.PacketIn) error
}

const (
	// Action explicitly output to controller.
	ofprAction ofpPacketInReason = 1
	// Action output to cluster network policy controller.
	ofnpAction ofpPacketInReason = 2
	// Name for traceflow PacketInHandler
	tfPacketHandlerName = "traceflow"
	// Name for CNP Logging PacketInHandler
	npPacketHandlerName = "networkpolicy"
	// Max packetInQueue size.
	packetInQueueSize int = 256
)

func (c *client) RegisterPacketInHandler(packetHandlerName string, packetInHandler interface{}) {
	handler, ok := packetInHandler.(PacketInHandler)
	if !ok {
		klog.Errorf("Invalid controller.")
		return
	}
	c.packetInHandlers[packetHandlerName] = handler
}

func (c *client) StartPacketInHandler(stopCh <-chan struct{}) {
	if len(c.packetInHandlers) == 0 {
		return
	}
	// Subscribe packetin for TraceFlow with reason 1
	ch := make(chan *ofctrl.PacketIn)
	err := c.SubscribePacketIn(uint8(ofprAction), ch)
	if err != nil {
		klog.Errorf("Subscribe PacketIn failed %+v", err)
		return
	}
	packetInQueue := workqueue.NewNamed("packetIn")
	go c.parsePacketIn(packetInQueue, stopCh, tfPacketHandlerName)

	// Subscribe packetin for CNP Logging with reason 2
	npCh := make(chan *ofctrl.PacketIn)
	err = c.SubscribePacketIn(uint8(ofnpAction), npCh)
	if err != nil {
		klog.Errorf("Subscribe PacketIn failed %+v", err)
		return
	}
	npPacketInQueue :=workqueue.NewNamed("cnpPacketIn")
	go c.parsePacketIn(npPacketInQueue, stopCh, npPacketHandlerName)

	for {
		select {
		// TODO: handle cnpPacketInQueue size
		case pktIn := <-ch:
			// Ensure that the queue doesn't grow too big. This is NOT to provide an exact guarantee.
			if packetInQueue.Len() < packetInQueueSize {
				packetInQueue.Add(pktIn)
			} else {
				klog.Warningf("Max packetInQueue size exceeded.")
			}
		case npPktIn := <-npCh:
			npPacketInQueue.Add(npPktIn)
		case <-stopCh:
			packetInQueue.ShutDown()
			npPacketInQueue.ShutDown()
			break
		}
	}
}

func (c *client) parsePacketIn(packetInQueue workqueue.Interface, stopCh <-chan struct{}, packetHandlerName string) {
	for {
		obj, quit := packetInQueue.Get()
		if quit {
			break
		}
		packetInQueue.Done(obj)
		pktIn, ok := obj.(*ofctrl.PacketIn)
		if !ok {
			klog.Errorf("Invalid packet in data in queue, skipping.")
			continue
		}
		// Use corresponding handler to handle PacketIn
		err := c.packetInHandlers[packetHandlerName].HandlePacketIn(pktIn)
		if err != nil {
			klog.Errorf("PacketIn handler %s failed to process packet: %+v", packetHandlerName, err)
		}
	}
}
