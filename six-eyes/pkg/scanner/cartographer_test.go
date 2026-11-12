package scanner

import (
	"net"
	"reflect"
	"testing"
)

func TestExpandCIDRIncludesIPv4NetworkAndBroadcast(t *testing.T) {
	got, err := ExpandCIDR("192.0.2.0/30")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"192.0.2.0", "192.0.2.1", "192.0.2.2", "192.0.2.3"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ExpandCIDR() = %v, want %v", got, want)
	}
}

func TestExpandCIDRIPv6(t *testing.T) {
	got, err := ExpandCIDR("2001:db8::/126")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"2001:db8::", "2001:db8::1", "2001:db8::2", "2001:db8::3"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ExpandCIDR() = %v, want %v", got, want)
	}
	for _, address := range got {
		if net.ParseIP(address) == nil {
			t.Fatalf("invalid returned IP %q", address)
		}
	}
}

func TestExpandCIDRRejectsOversizedRange(t *testing.T) {
	if _, err := ExpandCIDR("192.0.2.0/23"); err == nil {
		t.Fatal("expected oversized CIDR to be rejected")
	}
}
