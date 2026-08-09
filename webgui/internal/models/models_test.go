package models

import (
	"database/sql"
	"encoding/json"
	"testing"
)

func TestQueryEventLatencyJSON(t *testing.T) {
	t.Run("valid number", func(t *testing.T) {
		event := QueryEvent{Latency: sql.NullFloat64{Float64: 0, Valid: true}}
		data, err := json.Marshal(event)
		if err != nil {
			t.Fatal(err)
		}
		var payload map[string]any
		if err := json.Unmarshal(data, &payload); err != nil {
			t.Fatal(err)
		}
		if got, ok := payload["latency_ms"]; !ok || got != float64(0) {
			t.Fatalf("latency_ms = %#v, present=%v; want numeric zero", got, ok)
		}
	})

	t.Run("invalid omitted", func(t *testing.T) {
		data, err := json.Marshal(QueryEvent{})
		if err != nil {
			t.Fatal(err)
		}
		var payload map[string]any
		if err := json.Unmarshal(data, &payload); err != nil {
			t.Fatal(err)
		}
		if _, ok := payload["latency_ms"]; ok {
			t.Fatal("latency_ms should be omitted when invalid")
		}
	})

	t.Run("unmarshal number and null", func(t *testing.T) {
		var event QueryEvent
		if err := json.Unmarshal([]byte(`{"domain":"example.com","latency_ms":12.5}`), &event); err != nil {
			t.Fatal(err)
		}
		if !event.Latency.Valid || event.Latency.Float64 != 12.5 {
			t.Fatalf("latency = %#v; want valid 12.5", event.Latency)
		}
		if err := json.Unmarshal([]byte(`{"latency_ms":null}`), &event); err != nil {
			t.Fatal(err)
		}
		if event.Latency.Valid {
			t.Fatalf("latency = %#v; want invalid", event.Latency)
		}
	})
}
