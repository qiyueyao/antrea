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

	"github.com/contiv/libOpenflow/openflow13"
	"github.com/contiv/ofnet/ofctrl"
	"k8s.io/klog"

	"github.com/vmware-tanzu/antrea/pkg/agent/openflow"
	opsv1alpha1 "github.com/vmware-tanzu/antrea/pkg/apis/ops/v1alpha1"
	binding "github.com/vmware-tanzu/antrea/pkg/ovs/openflow"
)

func (c *Controller) HandlePacketIn(pktIn *ofctrl.PacketIn) error {
	if pktIn != nil {
		klog.Infof("received packet")
	}
	matchers := pktIn.GetMatches()
	var match *ofctrl.MatchField
	tableID := binding.TableIDType(pktIn.TableId)

	ob := new(opsv1alpha1.Observation)
	if tableID >= openflow.EmergencyEgressRuleTable && tableID <= openflow.ApplicationEgressRuleTable {
		match = getMatchRegField(matchers, uint32(openflow.EgressReg))
		ob.Action = opsv1alpha1.Forwarded
	} else if tableID >= openflow.EmergencyIngressRuleTable && tableID <= openflow.ApplicationIngressRuleTable {
		match = getMatchRegField(matchers, uint32(openflow.IngressReg))
		ob.Action = opsv1alpha1.Forwarded
	} else if tableID == openflow.EgressDefaultTable {
		match = getMatchRegField(matchers, uint32(openflow.EgressReg))
		ob.Action = opsv1alpha1.Dropped
	} else if  tableID == openflow.IngressDefaultTable {
		match = getMatchRegField(matchers, uint32(openflow.IngressReg))
		ob.Action = opsv1alpha1.Dropped
	}

	ob.Component = opsv1alpha1.NetworkPolicy
	ob.ComponentInfo = openflow.GetFlowTableName(tableID)

	info, err := getInfoInReg(match, nil)
	if err != nil {
		return err
	}
	npName, npNamespace := c.ofClient.GetPolicyFromConjunction(info)
	if npName != "" {
		ob.NetworkPolicy = fmt.Sprintf("%s/%s", npNamespace, npName)
	}

	klog.Infof(fmt.Sprintf("%s %s %s in %s", ob.Component, ob.NetworkPolicy, ob.Action, ob.ComponentInfo))

	return nil
}

func getMatchRegField(matchers *ofctrl.Matchers, regNum uint32) *ofctrl.MatchField {
	return matchers.GetMatchByName(fmt.Sprintf("NXM_NX_REG%d", regNum))
}

func getInfoInReg(regMatch *ofctrl.MatchField, rng *openflow13.NXRange) (uint32, error) {
	regValue, ok := regMatch.GetValue().(*ofctrl.NXRegister)
	if !ok {
		return 0, errors.New("register value cannot be got")
	}
	if rng != nil {
		return ofctrl.GetUint32ValueWithRange(regValue.Data, rng), nil
	}
	return regValue.Data, nil
}