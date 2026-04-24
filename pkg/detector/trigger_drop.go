package detector

import (
	"fmt"
	"time"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	"github.com/vperez237/cilium-flight-recorder/pkg/config"
	"github.com/vperez237/cilium-flight-recorder/pkg/metrics"
)

// checkDrop fires on DROPPED flows. In "rate" mode, fires when MinDrops
// drops accumulate for a (dstIP, dstPort) tuple within WindowSeconds.
// In "immediate" mode, fires on every drop (subject to per-tuple cooldown).
func (d *AnomalyDetector) checkDrop(flow *flowpb.Flow, ts time.Time) {
	if flow.GetVerdict() != flowpb.Verdict_DROPPED {
		return
	}

	dstIP := destinationIP(flow)
	dstPort := extractDstPort(flow)
	proto := extractProtocol(flow)

	metrics.AnomaliesDetected.WithLabelValues(string(TriggerDrop)).Inc()

	if d.cfg.Drops.Mode == config.ModeRate {
		key := fmt.Sprintf("drop:%s:%d", dstIP, dstPort)
		rw := d.getOrCreateRateWindow(d.dropRates, key, time.Duration(d.cfg.Drops.WindowSeconds)*time.Second)
		rw.Add(true)
		count := rw.ErrorCount()
		if count < d.cfg.Drops.MinDrops {
			return
		}
		req := CaptureRequest{
			Trigger:   TriggerDrop,
			Reason:    fmt.Sprintf("%d drops to %s:%d in last %ds", count, dstIP, dstPort, d.cfg.Drops.WindowSeconds),
			DstIP:     dstIP,
			DstPort:   dstPort,
			Protocol:  proto,
			Timestamp: ts,
		}
		d.emit(req)
		return
	}

	req := CaptureRequest{
		Trigger:   TriggerDrop,
		Reason:    fmt.Sprintf("packet dropped: %s", flow.GetDropReasonDesc().String()),
		SrcIP:     sourceIP(flow),
		DstIP:     dstIP,
		DstPort:   dstPort,
		Protocol:  proto,
		Timestamp: ts,
	}
	d.emit(req)
}
