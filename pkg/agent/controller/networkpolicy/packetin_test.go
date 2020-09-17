package networkpolicy

import (
	"github.com/contiv/libOpenflow/protocol"
	"github.com/contiv/libOpenflow/util"
	"github.com/contiv/ofnet/ofctrl"
	"github.com/stretchr/testify/assert"
	"net"
	"testing"
)

func Test_getNetworkPolicyFullName(t *testing.T) {
	type args struct {
		npName      string
		npNamespace string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			"non-namespaced",
			args{"cnp-test", ""},
			"cnp-test",
		},
		{
			"namespaced",
			args{"anp-test", "default"},
			"default/anp-test",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := getNetworkPolicyFullName(tt.args.npName, tt.args.npNamespace); got != tt.want {
				t.Errorf("getNetworkPolicyFullName() = %v, want %v", got, tt.want)
			}
		})
	}
}

func getMockPacketIn() *ofctrl.PacketIn {
	ipPacket := protocol.IPv4{
		NWSrc: net.IPv4(1, 1, 1, 1),
		NWDst: net.IPv4(2, 2, 2, 2),
		Length: 1,
		Protocol: 6,
	}
	etherPacket := protocol.Ethernet{
		Ethertype: 0x0800,
		Data: util.Message(&ipPacket),
	}
	result := ofctrl.PacketIn{
		Reason: 1,
		Data: etherPacket,
	}
	return &result
}

func Test_getPacketInfo(t *testing.T) {
	type args struct {
		pktIn *ofctrl.PacketIn
		ob    *logInfo
	}
	mockOb := new(logInfo)
	expectedOb := logInfo{srcIP: "1.1.1.1", destIP: "2.2.2.2", pckLength: 1, protocolStr: "TCP"}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			"ipv4",
			args{
				getMockPacketIn(),
				mockOb,
				},
				false,
			},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := getPacketInfo(tt.args.pktIn, tt.args.ob); (err != nil) != tt.wantErr {
				t.Errorf("getPacketInfo() error = %v, wantErr %v", err, tt.wantErr)
			}
			assert.Equal(t, expectedOb, *mockOb, "Expect to retrieve exact packet info while differed")
		})
	}
}