package detector

import (
	"fmt"

	flowpb "github.com/cilium/cilium/api/v1/flow"
)

// Flow-extraction helpers shared across triggers. Kept in their own file so
// the individual trigger files don't have to duplicate defensive nil checks.

func extractIP(ep *flowpb.Endpoint) string {
	if ep == nil {
		return ""
	}
	return fmt.Sprintf("%d", ep.GetID())
}

func sourceIP(flow *flowpb.Flow) string {
	if ip := flow.GetIP(); ip != nil {
		return ip.GetSource()
	}
	return extractIP(flow.GetSource())
}

func destinationIP(flow *flowpb.Flow) string {
	if ip := flow.GetIP(); ip != nil {
		return ip.GetDestination()
	}
	return extractIP(flow.GetDestination())
}

func extractDstPort(flow *flowpb.Flow) uint32 {
	l4 := flow.GetL4()
	if l4 == nil {
		return 0
	}
	if tcp := l4.GetTCP(); tcp != nil {
		return tcp.GetDestinationPort()
	}
	if udp := l4.GetUDP(); udp != nil {
		return udp.GetDestinationPort()
	}
	return 0
}

func extractProtocol(flow *flowpb.Flow) string {
	l4 := flow.GetL4()
	if l4 == nil {
		return "TCP"
	}
	if l4.GetTCP() != nil {
		return "TCP"
	}
	if l4.GetUDP() != nil {
		return "UDP"
	}
	if l4.GetICMPv4() != nil {
		return "ICMPv4"
	}
	if l4.GetICMPv6() != nil {
		return "ICMPv6"
	}
	return "TCP"
}

var rcodeNames = map[int]string{
	0: "NOERROR",
	1: "FORMERR",
	2: "SERVFAIL",
	3: "NXDOMAIN",
	4: "NOTIMP",
	5: "REFUSED",
}

func rcodeToString(rcode int) string {
	if name, ok := rcodeNames[rcode]; ok {
		return name
	}
	return fmt.Sprintf("RCODE_%d", rcode)
}
