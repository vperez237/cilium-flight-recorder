package detector

import (
	"fmt"
	"time"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	"github.com/vperez237/cilium-flight-recorder/pkg/config"
	"github.com/vperez237/cilium-flight-recorder/pkg/metrics"
)

// checkHTTPError fires on HTTP responses whose status code is in the
// configured error set. In "rate" mode it tracks per (dstIP, dstPort) tuples
// and fires when errors/total exceeds RateThreshold over WindowSeconds.
func (d *AnomalyDetector) checkHTTPError(flow *flowpb.Flow, ts time.Time) {
	l7 := flow.GetL7()
	if l7 == nil {
		return
	}
	http := l7.GetHttp()
	if http == nil {
		return
	}

	code := int(http.GetCode())
	if code == 0 {
		return
	}
	isError := d.isHTTPErrorCode(code)

	dstIP := destinationIP(flow)
	dstPort := extractDstPort(flow)

	if d.cfg.HTTPErrors.Mode == config.ModeRate {
		key := fmt.Sprintf("http:%s:%d", dstIP, dstPort)
		rw := d.getOrCreateRateWindow(d.httpRates, key, time.Duration(d.cfg.HTTPErrors.WindowSeconds)*time.Second)
		rw.Add(isError)
		total, errors, rate := rw.Stats()
		metrics.RateWindowErrors.WithLabelValues(string(TriggerHTTPError)).Set(rate)
		if total < d.cfg.HTTPErrors.MinEvents {
			return
		}
		if rate < d.cfg.HTTPErrors.RateThreshold {
			return
		}
		metrics.AnomaliesDetected.WithLabelValues(string(TriggerHTTPError)).Inc()
		req := CaptureRequest{
			Trigger: TriggerHTTPError,
			Reason: fmt.Sprintf("HTTP error rate %.1f%% (%d/%d) to %s:%d exceeds %.1f%% over %ds",
				rate*100, errors, total, dstIP, dstPort,
				d.cfg.HTTPErrors.RateThreshold*100, d.cfg.HTTPErrors.WindowSeconds),
			DstIP:     dstIP,
			DstPort:   dstPort,
			Protocol:  "TCP",
			Timestamp: ts,
		}
		d.emit(req)
		return
	}

	if !isError {
		return
	}

	metrics.AnomaliesDetected.WithLabelValues(string(TriggerHTTPError)).Inc()
	req := CaptureRequest{
		Trigger:   TriggerHTTPError,
		Reason:    fmt.Sprintf("HTTP %d on %s %s", code, http.GetMethod(), http.GetUrl()),
		SrcIP:     sourceIP(flow),
		DstIP:     dstIP,
		DstPort:   dstPort,
		Protocol:  "TCP",
		Timestamp: ts,
	}
	d.emit(req)
}

func (d *AnomalyDetector) isHTTPErrorCode(code int) bool {
	for _, c := range d.cfg.HTTPErrors.StatusCodes {
		if c == code {
			return true
		}
	}
	return false
}
