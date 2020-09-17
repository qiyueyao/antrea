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

package networkpolicy

import (
	"errors"
	"fmt"
	"log"
	"os"

	"github.com/contiv/libOpenflow/openflow13"
	"github.com/contiv/libOpenflow/protocol"
	"github.com/contiv/ofnet/ofctrl"
	"gopkg.in/natefinch/lumberjack.v2"
	"k8s.io/klog"

	"github.com/vmware-tanzu/antrea/pkg/agent/openflow"
	opsv1alpha1 "github.com/vmware-tanzu/antrea/pkg/apis/ops/v1alpha1"
	binding "github.com/vmware-tanzu/antrea/pkg/ovs/openflow"
)

const (
	logDir string = "/var/log/antrea/networkpolicy/"
	logfileName string = "np.log"
)

var (
	CNPLogger    *log.Logger
)

type logInfo struct {
	tableName string
	npName string
	disposition string
	ofPriority string
	srcIP string
	destIP string
	pckLength uint16
	protocolStr string
}

func InitLogger() {
	// logging file should be /var/log/antrea/networkpolicy/np.log
	if _, err := os.Stat(logDir); os.IsNotExist(err) {
		os.Mkdir(logDir, 0755)
	}
	file, err := os.OpenFile(logDir + logfileName, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
	if err != nil {
		klog.Errorf("Failed to initiate logger %v", err)
	}

	CNPLogger = log.New(file, "", log.Ldate|log.Lmicroseconds)
	// Use lumberjack log file rotation
	CNPLogger.SetOutput(&lumberjack.Logger{
		Filename:   logDir + logfileName,
		MaxSize:    500,  // megabytes after which new file is created
		MaxBackups: 3,  // number of backups
		MaxAge:     28, //days
		Compress:   true,
	})
	klog.V(2).Info("Initiated CNPLogger for audit logging")
}

func (c *Controller) HandlePacketIn(pktIn *ofctrl.PacketIn) error {
	if pktIn == nil {
		return errors.New("empty packetin for CNP")
	}

	ob := new(logInfo)

	// Get network policy log info
	err := getNetworkPolicyInfo(pktIn, c, ob)
	if err != nil {
		return err
	}

	// Get packet log info
	err = getPacketInfo(pktIn, ob)
	if err != nil {
		return err
	}

	// Store log file
	CNPLogger.Printf("%s %s %s %s SRC: %s DEST: %s %d %s", ob.tableName, ob.npName, ob.disposition, ob.ofPriority, ob.srcIP, ob.destIP, ob.pckLength, ob.protocolStr)
	return nil
}

func getNetworkPolicyFullName(npName string, npNamespace string) string {
	if npName == "" || npNamespace == "" {
		return npName
	} else {
		return fmt.Sprintf("%s/%s", npNamespace, npName)
	}
}

func getMatchRegField(matchers *ofctrl.Matchers, regNum uint32) *ofctrl.MatchField {
	return matchers.GetMatchByName(fmt.Sprintf("NXM_NX_REG%d", regNum))
}

func getInfoInReg(regMatch *ofctrl.MatchField, rng *openflow13.NXRange) (uint32, error) {
	regValue, ok := regMatch.GetValue().(*ofctrl.NXRegister)
	if !ok {
		return 0, errors.New("register value cannot be retrieved")
	}
	if rng != nil {
		return ofctrl.GetUint32ValueWithRange(regValue.Data, rng), nil
	}
	return regValue.Data, nil
}

func getNetworkPolicyInfo(pktIn *ofctrl.PacketIn, c *Controller, ob *logInfo) error {
	matchers := pktIn.GetMatches()
	var match *ofctrl.MatchField
	// Get table name
	tableID := binding.TableIDType(pktIn.TableId)
	ob.tableName = openflow.GetFlowTableName(tableID)

	// Get ingress/egress reg
	for _, table := range openflow.GetCNPEgressTables() {
		if tableID == table {
			match = getMatchRegField(matchers, uint32(openflow.EgressReg))
		}
	}
	for _, table := range openflow.GetCNPIngressTables() {
		if tableID == table {
			match = getMatchRegField(matchers, uint32(openflow.IngressReg))
		}
	}

	// Get network policy full name, CNP is not namespaced
	info, err := getInfoInReg(match, nil)
	if err != nil {
		return err
	}
	npName, npNamespace := c.ofClient.GetPolicyFromConjunction(info)
	ob.npName = getNetworkPolicyFullName(npName, npNamespace)

	// Get OF priority of the conjunction
	ob.ofPriority = c.ofClient.GetPriorityFromConjunction(info)

	// Get disposition Allow or Drop
	match = getMatchRegField(matchers, uint32(openflow.DispositionReg))
	info, err = getInfoInReg(match, nil)
	if err != nil {
		return err
	}
	ob.disposition = openflow.DispositionToString[info]
	return nil
}

func getPacketInfo(pktIn *ofctrl.PacketIn, ob *logInfo) error {
	if pktIn.Data.Ethertype == opsv1alpha1.EtherTypeIPv4 {
		ipPacket, ok := pktIn.Data.Data.(*protocol.IPv4)
		if !ok {
			return errors.New("invalid IPv4 packet")
		}
		// Get source destination IP and protocol
		ob.srcIP = ipPacket.NWSrc.String()
		ob.destIP = ipPacket.NWDst.String()
		ob.pckLength = ipPacket.Length
		ob.protocolStr = opsv1alpha1.ProtocolsToString[int32(ipPacket.Protocol)]
	}
	return nil
}