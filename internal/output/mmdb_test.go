package output

import (
	"testing"
	"time"

	"blackroute/internal/record"
	"github.com/maxmind/mmdbwriter/mmdbtype"
)

func TestThreatMMDBEntryMergesSignals(t *testing.T) {
	entry := buildThreatMMDBEntry("192.0.2.1/32", []record.Record{
		{
			IP:             "192.0.2.1",
			SourceName:     "blocklist_de_ssh",
			Threat:         []string{"recent_attack_any", "recent_attack_ssh"},
			Infrastructure: []string{"prefix_cybercrime"},
			Confidence:     55,
			LastSeen:       time.Now(),
		},
		{
			IP:         "192.0.2.1",
			SourceName: "emergingthreats_compromised",
			Threat:     []string{"compromised_or_hostile_host"},
			Confidence: 70,
			LastSeen:   time.Now(),
		},
	})

	if got := uint16(entry["confidence"].(mmdbtype.Uint16)); got != 70 {
		t.Fatalf("confidence = %d, want 70", got)
	}
	threats := entry["threat"].(mmdbtype.Slice)
	if len(threats) != 3 {
		t.Fatalf("threat len = %d, want 3: %#v", len(threats), threats)
	}
	infra := entry["infrastructure"].(mmdbtype.Slice)
	if len(infra) != 1 || string(infra[0].(mmdbtype.String)) != "prefix_cybercrime" {
		t.Fatalf("infrastructure = %#v, want [prefix_cybercrime]", infra)
	}
}
