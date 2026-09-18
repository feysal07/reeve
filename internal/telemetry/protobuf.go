package telemetry

import (
	"encoding/json"
	"fmt"
	"strconv"
)

// Decoding OTLP protobuf into the same intermediate types the JSON path produces.
//
// The important design point is that this file stops at those types. Everything above
// them, the vendor name mapping, the token categorisation, the pricing and the team
// resolution, is shared. Two encodings must never mean two normalisation paths,
// because the second one always drifts and the drift is invisible.
//
// Field numbers below come from the OTLP specification. They are fixed by the
// protocol: changing one would be a breaking change to OTLP itself, which is the
// guarantee that makes decoding a subset safe.

// DecodeMetricsProto reads an OTLP ExportMetricsServiceRequest in protobuf encoding.
func (d *Decoder) DecodeMetricsProto(body []byte) ([]Event, error) {
	var req otlpMetricsRequest

	err := each(body, func(p *buf, field, wire int) (bool, error) {
		// ExportMetricsServiceRequest.resource_metrics = 1
		if field != 1 || wire != wireBytes {
			return false, nil
		}
		b, err := p.bytes()
		if err != nil {
			return true, err
		}
		rm, err := decodeResourceMetrics(b)
		if err != nil {
			return true, err
		}
		req.ResourceMetrics = append(req.ResourceMetrics, rm)
		return true, nil
	})
	if err != nil {
		return nil, fmt.Errorf("decode otlp metrics (protobuf): %w", err)
	}
	return d.eventsFromMetrics(req), nil
}

// DecodeLogsProto reads an OTLP ExportLogsServiceRequest in protobuf encoding.
func (d *Decoder) DecodeLogsProto(body []byte) ([]Event, error) {
	var req otlpLogsRequest

	err := each(body, func(p *buf, field, wire int) (bool, error) {
		// ExportLogsServiceRequest.resource_logs = 1
		if field != 1 || wire != wireBytes {
			return false, nil
		}
		b, err := p.bytes()
		if err != nil {
			return true, err
		}
		rl, err := decodeResourceLogs(b)
		if err != nil {
			return true, err
		}
		req.ResourceLogs = append(req.ResourceLogs, rl)
		return true, nil
	})
	if err != nil {
		return nil, fmt.Errorf("decode otlp logs (protobuf): %w", err)
	}
	return d.eventsFromLogs(req), nil
}

// resourceMetrics is the anonymous struct type used inside otlpMetricsRequest.
type resourceMetricsT = struct {
	Resource     otlpResource `json:"resource"`
	ScopeMetrics []struct {
		Metrics []otlpMetric `json:"metrics"`
	} `json:"scopeMetrics"`
}

type resourceLogsT = struct {
	Resource  otlpResource `json:"resource"`
	ScopeLogs []struct {
		LogRecords []otlpLogRecord `json:"logRecords"`
	} `json:"scopeLogs"`
}

type scopeMetricsT = struct {
	Metrics []otlpMetric `json:"metrics"`
}

type scopeLogsT = struct {
	LogRecords []otlpLogRecord `json:"logRecords"`
}

func decodeResourceMetrics(b []byte) (resourceMetricsT, error) {
	var out resourceMetricsT
	err := each(b, func(p *buf, field, wire int) (bool, error) {
		switch {
		case field == 1 && wire == wireBytes: // resource
			rb, err := p.bytes()
			if err != nil {
				return true, err
			}
			out.Resource, err = decodeResource(rb)
			return true, err
		case field == 2 && wire == wireBytes: // scope_metrics
			sb, err := p.bytes()
			if err != nil {
				return true, err
			}
			sm, err := decodeScopeMetrics(sb)
			if err != nil {
				return true, err
			}
			out.ScopeMetrics = append(out.ScopeMetrics, sm)
			return true, nil
		}
		return false, nil
	})
	return out, err
}

func decodeScopeMetrics(b []byte) (scopeMetricsT, error) {
	var out scopeMetricsT
	err := each(b, func(p *buf, field, wire int) (bool, error) {
		// ScopeMetrics.metrics = 2
		if field != 2 || wire != wireBytes {
			return false, nil
		}
		mb, err := p.bytes()
		if err != nil {
			return true, err
		}
		m, err := decodeMetric(mb)
		if err != nil {
			return true, err
		}
		out.Metrics = append(out.Metrics, m)
		return true, nil
	})
	return out, err
}

func decodeResourceLogs(b []byte) (resourceLogsT, error) {
	var out resourceLogsT
	err := each(b, func(p *buf, field, wire int) (bool, error) {
		switch {
		case field == 1 && wire == wireBytes: // resource
			rb, err := p.bytes()
			if err != nil {
				return true, err
			}
			out.Resource, err = decodeResource(rb)
			return true, err
		case field == 2 && wire == wireBytes: // scope_logs
			sb, err := p.bytes()
			if err != nil {
				return true, err
			}
			sl, err := decodeScopeLogs(sb)
			if err != nil {
				return true, err
			}
			out.ScopeLogs = append(out.ScopeLogs, sl)
			return true, nil
		}
		return false, nil
	})
	return out, err
}

func decodeScopeLogs(b []byte) (scopeLogsT, error) {
	var out scopeLogsT
	err := each(b, func(p *buf, field, wire int) (bool, error) {
		// ScopeLogs.log_records = 2
		if field != 2 || wire != wireBytes {
			return false, nil
		}
		lb, err := p.bytes()
		if err != nil {
			return true, err
		}
		lr, err := decodeLogRecord(lb)
		if err != nil {
			return true, err
		}
		out.LogRecords = append(out.LogRecords, lr)
		return true, nil
	})
	return out, err
}

// decodeResource reads Resource.attributes = 1.
func decodeResource(b []byte) (otlpResource, error) {
	var out otlpResource
	err := each(b, func(p *buf, field, wire int) (bool, error) {
		if field != 1 || wire != wireBytes {
			return false, nil
		}
		ab, err := p.bytes()
		if err != nil {
			return true, err
		}
		kv, err := decodeKeyValue(ab)
		if err != nil {
			return true, err
		}
		out.Attributes = append(out.Attributes, kv)
		return true, nil
	})
	return out, err
}

func decodeKeyValue(b []byte) (otlpAttr, error) {
	var out otlpAttr
	err := each(b, func(p *buf, field, wire int) (bool, error) {
		switch {
		case field == 1 && wire == wireBytes: // key
			s, err := p.string()
			out.Key = s
			return true, err
		case field == 2 && wire == wireBytes: // value
			vb, err := p.bytes()
			if err != nil {
				return true, err
			}
			out.Value, err = decodeAnyValue(vb)
			return true, err
		}
		return false, nil
	})
	return out, err
}

// decodeAnyValue reads the scalar arms of the AnyValue union. A structured value is
// rendered as JSON rather than dropped, so an operator can see that something arrived
// even when Reeve has no field for it.
func decodeAnyValue(b []byte) (otlpValue, error) {
	var out otlpValue
	err := each(b, func(p *buf, field, wire int) (bool, error) {
		switch {
		case field == 1 && wire == wireBytes: // string_value
			s, err := p.string()
			out.StringValue = &s
			return true, err
		case field == 2 && wire == wireVarint: // bool_value
			v, err := p.varint()
			if err != nil {
				return true, err
			}
			bv := v != 0
			out.BoolValue = &bv
			return true, nil
		case field == 3 && wire == wireVarint: // int_value
			v, err := p.varint()
			if err != nil {
				return true, err
			}
			n := json.Number(strconv.FormatInt(int64(v), 10))
			out.IntValue = &n
			return true, nil
		case field == 4 && wire == wireFixed64: // double_value
			v, err := p.fixed64()
			if err != nil {
				return true, err
			}
			f := float64frombits(v)
			out.DoubleValue = &f
			return true, nil
		}
		return false, nil
	})
	return out, err
}

// decodeMetric reads Metric.name and whichever data arm is present.
func decodeMetric(b []byte) (otlpMetric, error) {
	var out otlpMetric
	err := each(b, func(p *buf, field, wire int) (bool, error) {
		switch {
		case field == 1 && wire == wireBytes: // name
			s, err := p.string()
			out.Name = s
			return true, err

		case field == 5 && wire == wireBytes: // gauge
			gb, err := p.bytes()
			if err != nil {
				return true, err
			}
			pts, err := decodeNumberDataPoints(gb)
			if err != nil {
				return true, err
			}
			out.Gauge = &struct {
				DataPoints []otlpDataPoint `json:"dataPoints"`
			}{DataPoints: pts}
			return true, nil

		case field == 7 && wire == wireBytes: // sum
			sb, err := p.bytes()
			if err != nil {
				return true, err
			}
			pts, err := decodeNumberDataPoints(sb)
			if err != nil {
				return true, err
			}
			out.Sum = &struct {
				DataPoints []otlpDataPoint `json:"dataPoints"`
			}{DataPoints: pts}
			return true, nil

		case field == 9 && wire == wireBytes: // histogram
			hb, err := p.bytes()
			if err != nil {
				return true, err
			}
			pts, err := decodeHistogramDataPoints(hb)
			if err != nil {
				return true, err
			}
			out.Histogram = &struct {
				DataPoints []otlpDataPoint `json:"dataPoints"`
			}{DataPoints: pts}
			return true, nil
		}
		return false, nil
	})
	return out, err
}

// decodeNumberDataPoints reads Sum.data_points or Gauge.data_points, both field 1.
func decodeNumberDataPoints(b []byte) ([]otlpDataPoint, error) {
	var out []otlpDataPoint
	err := each(b, func(p *buf, field, wire int) (bool, error) {
		if field != 1 || wire != wireBytes {
			return false, nil
		}
		db, err := p.bytes()
		if err != nil {
			return true, err
		}
		dp, err := decodeNumberDataPoint(db)
		if err != nil {
			return true, err
		}
		out = append(out, dp)
		return true, nil
	})
	return out, err
}

func decodeNumberDataPoint(b []byte) (otlpDataPoint, error) {
	var out otlpDataPoint
	err := each(b, func(p *buf, field, wire int) (bool, error) {
		switch {
		case field == 3 && wire == wireFixed64: // time_unix_nano
			v, err := p.fixed64()
			if err != nil {
				return true, err
			}
			out.TimeUnixNano = json.Number(strconv.FormatUint(v, 10))
			return true, nil

		case field == 4 && wire == wireFixed64: // as_double
			v, err := p.fixed64()
			if err != nil {
				return true, err
			}
			f := float64frombits(v)
			out.AsDouble = &f
			return true, nil

		case field == 6 && wire == wireFixed64: // as_int, an sfixed64
			v, err := p.fixed64()
			if err != nil {
				return true, err
			}
			out.AsInt = json.Number(strconv.FormatInt(int64(v), 10))
			return true, nil

		case field == 7 && wire == wireBytes: // attributes
			ab, err := p.bytes()
			if err != nil {
				return true, err
			}
			kv, err := decodeKeyValue(ab)
			if err != nil {
				return true, err
			}
			out.Attributes = append(out.Attributes, kv)
			return true, nil
		}
		return false, nil
	})
	return out, err
}

// decodeHistogramDataPoints reads Histogram.data_points = 1. A HistogramDataPoint is a
// different message from a NumberDataPoint: its attributes are field 9, and its sum is
// field 5.
func decodeHistogramDataPoints(b []byte) ([]otlpDataPoint, error) {
	var out []otlpDataPoint
	err := each(b, func(p *buf, field, wire int) (bool, error) {
		if field != 1 || wire != wireBytes {
			return false, nil
		}
		db, err := p.bytes()
		if err != nil {
			return true, err
		}
		dp, err := decodeHistogramDataPoint(db)
		if err != nil {
			return true, err
		}
		out = append(out, dp)
		return true, nil
	})
	return out, err
}

func decodeHistogramDataPoint(b []byte) (otlpDataPoint, error) {
	var out otlpDataPoint
	err := each(b, func(p *buf, field, wire int) (bool, error) {
		switch {
		case field == 3 && wire == wireFixed64: // time_unix_nano
			v, err := p.fixed64()
			if err != nil {
				return true, err
			}
			out.TimeUnixNano = json.Number(strconv.FormatUint(v, 10))
			return true, nil

		case field == 5 && wire == wireFixed64: // sum
			v, err := p.fixed64()
			if err != nil {
				return true, err
			}
			f := float64frombits(v)
			out.Sum = &f
			return true, nil

		case field == 9 && wire == wireBytes: // attributes
			ab, err := p.bytes()
			if err != nil {
				return true, err
			}
			kv, err := decodeKeyValue(ab)
			if err != nil {
				return true, err
			}
			out.Attributes = append(out.Attributes, kv)
			return true, nil
		}
		return false, nil
	})
	return out, err
}

func decodeLogRecord(b []byte) (otlpLogRecord, error) {
	var out otlpLogRecord
	err := each(b, func(p *buf, field, wire int) (bool, error) {
		switch {
		case field == 1 && wire == wireFixed64: // time_unix_nano
			v, err := p.fixed64()
			if err != nil {
				return true, err
			}
			out.TimeUnixNano = json.Number(strconv.FormatUint(v, 10))
			return true, nil

		case field == 5 && wire == wireBytes: // body
			bb, err := p.bytes()
			if err != nil {
				return true, err
			}
			v, err := decodeAnyValue(bb)
			if err != nil {
				return true, err
			}
			out.Body = &v
			return true, nil

		case field == 6 && wire == wireBytes: // attributes
			ab, err := p.bytes()
			if err != nil {
				return true, err
			}
			kv, err := decodeKeyValue(ab)
			if err != nil {
				return true, err
			}
			out.Attributes = append(out.Attributes, kv)
			return true, nil
		}
		return false, nil
	})
	return out, err
}
