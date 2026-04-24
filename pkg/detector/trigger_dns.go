package detector

import (
	"fmt"
	"time"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	"github.com/vperez237/cilium-flight-recorder/pkg/config"
	"github.com/vperez237/cilium-flight-recorder/pkg/metrics"
)

// checkDNSFailure fires on DNS responses with an RCODE in the configured
// failure set. "rate" mode keys by source IP (the querying client) and
// fires when failures/total exceeds RateThreshold over WindowSeconds.
func (d *AnomalyDetector) checkDNSFailure(flow *flowpb.Flow, ts time.Time) {
	l7 := flow.GetL7()
	if l7 == nil {
		return
	}
	dns := l7.GetDns()
	if dns == nil {
		return
	}

	rcode := rcodeToString(int(dns.GetRcode()))
	isFailure := d.isDNSFailureRCode(rcode)

	srcIPStr := sourceIP(flow)

	if d.cfg.DNSFailures.Mode == config.ModeRate {
		key := fmt.Sprintf("dns:%s", srcIPStr)
		rw := d.getOrCreateRateWindow(d.dnsRates, key, time.Duration(d.cfg.DNSFailures.WindowSeconds)*time.Second)
		rw.Add(isFailure)
		total, errors, rate := rw.Stats()
		metrics.RateWindowErrors.WithLabelValues(string(TriggerDNSFailure)).Set(rate)
		if total < d.cfg.DNSFailures.MinEvents {
			return
		}
		if rate < d.cfg.DNSFailures.RateThreshold {
			return
		}
		metrics.AnomaliesDetected.WithLabelValues(string(TriggerDNSFailure)).Inc()
		req := CaptureRequest{
			Trigger: TriggerDNSFailure,
			Reason: fmt.Sprintf("DNS failure rate %.1f%% (%d/%d) from %s exceeds %.1f%% over %ds",
				rate*100, errors, total, srcIPStr,
				d.cfg.DNSFailures.RateThreshold*100, d.cfg.DNSFailures.WindowSeconds),
			SrcIP:     srcIPStr,
			DstPort:   53,
			Protocol:  "UDP",
			Timestamp: ts,
		}
		d.emit(req)
		return
	}

	if !isFailure {
		return
	}

	metrics.AnomaliesDetected.WithLabelValues(string(TriggerDNSFailure)).Inc()
	req := CaptureRequest{
		Trigger:   TriggerDNSFailure,
		Reason:    fmt.Sprintf("DNS %s for query %s", rcode, dns.GetQuery()),
		SrcIP:     srcIPStr,
		DstIP:     destinationIP(flow),
		DstPort:   53,
		Protocol:  "UDP",
		Timestamp: ts,
	}
	d.emit(req)
}

func (d *AnomalyDetector) isDNSFailureRCode(rcode string) bool {
	for _, r := range d.cfg.DNSFailures.RCodes {
		if r == rcode {
			return true
		}
	}
	return false
}
