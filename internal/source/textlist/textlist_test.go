package textlist

import (
	"reflect"
	"testing"
)

func TestExtractIPTokensKeepsIPv6CIDR(t *testing.T) {
	got := extractIPTokens("2001:678:254::/48 ; SBL697648")
	want := []string{"2001:678:254::/48"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("tokens = %#v, want %#v", got, want)
	}
}

func TestExtractIPTokensKeepsIPv4FromPortEvidence(t *testing.T) {
	got := extractIPTokens("8.8.8.8:443,botnet")
	want := []string{"8.8.8.8"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("tokens = %#v, want %#v", got, want)
	}
}
