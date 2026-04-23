package server

import "testing"

func TestNormalizeAnswer(t *testing.T) {
	cases := []struct{ in, want string }{
		{"  Café  ", "cafe"},
		{"CAFÉ", "cafe"},
		{"café", "cafe"},
		{"N°  123", "n° 123"},
		{"Élodie   Martin", "elodie martin"},
		{"", ""},
	}
	for _, c := range cases {
		if got := NormalizeAnswer(c.in); got != c.want {
			t.Errorf("NormalizeAnswer(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestNormalizeIPv6(t *testing.T) {
	cases := []struct{ in, want string }{
		{"192.168.1.1", "192.168.1.1"},
		{"2001:0db8:85a3:0000:1234:5678:9abc:def0", "2001:db8:85a3::"},
		{"2001:db8:85a3::ff:1", "2001:db8:85a3::"},
		{"2001:db8:85a3:0:9999::", "2001:db8:85a3::"},
		{"::1", "::"},
		{"not-an-ip", "not-an-ip"},
	}
	for _, c := range cases {
		if got := normalizeIP(c.in); got != c.want {
			t.Errorf("normalizeIP(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestRateLimiterMapCap(t *testing.T) {
	l := newIPLimiter(1, 2)
	l.maxKeys = 3
	for i := 0; i < 3; i++ {
		if !l.Allow(string(rune('a' + i))) {
			t.Fatalf("should allow key %d", i)
		}
	}
	if !l.Allow("overflow") {
		t.Fatal("should evict oldest and allow new key")
	}
	if len(l.window) > l.maxKeys {
		t.Fatalf("map grew beyond maxKeys: %d", len(l.window))
	}
}

func TestAnswerHashBoundToID(t *testing.T) {
	secret := []byte("server-secret-32-bytes-xxxxxxxxxx")
	h1 := AnswerHash(secret, "id-a", "hello")
	h2 := AnswerHash(secret, "id-b", "hello")
	if HashEqual(h1, h2) {
		t.Fatal("same answer produced same hash across distinct secret ids")
	}
	h3 := AnswerHash(secret, "id-a", "HELLO")
	if !HashEqual(h1, h3) {
		t.Fatal("case-insensitive normalization broken")
	}
}
