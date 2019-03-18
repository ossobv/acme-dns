package main

import (
	"testing"

	"github.com/google/uuid"
)

func TestGetValidUsername(t *testing.T) {
	v1, _ := uuid.Parse("5ec1d7f2-496d-11e9-8646-d663bd873d93")
	for i, test := range []struct {
		uname  string
		output uuid.UUID
		valid  bool
	}{
		{"5ec1d7f2-496d-11e9-8646-d663bd873d93", v1, true},
		{"5Ec1d7f2-496d-11e9-8646-d663bd873d93", uuid.UUID{}, false}, // non-lowercase
		{"a-97455b-52cc-4569-90c8-7a4b97c6eba8", uuid.UUID{}, false},
		{"", uuid.UUID{}, false},
		{"&!#!25123!%!'%", uuid.UUID{}, false},
	} {
		ret, err := getValidUsername(test.uname)
		if !test.valid && err == nil {
			t.Errorf("Test %d: Expected error, but there was none", i)
		}
		if test.valid && err != nil {
			t.Errorf("Test %d: Expected no error, but got [%v]", i, err)
		}
		if ret != test.output {
			t.Errorf("Test %d: Expected return value %v, but got %v", i, test.output, ret)
		}
	}
}

func TestValidKey(t *testing.T) {
	for i, test := range []struct {
		key    string
		output bool
	}{
		{"", false},
		{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", true},
		{"aaaaaaaa-aaa-aaaaaa-aaaaaaaa-aaa_aacaaaa", true},
		{"aaaaaaaa-aaa-aaaaaa#aaaaaaaa-aaa_aacaaaa", false},
		{"aaaaaaaa-aaa-aaaaaa-aaaaaaaa-aaa_aacaaaaa", false},
	} {
		ret := validKey(test.key)
		if ret != test.output {
			t.Errorf("Test %d: Expected return value %t, but got %t", i, test.output, ret)
		}
	}
}

func TestGetValidSubdomain(t *testing.T) {
	for i, test := range []struct {
		subdomain string
		output    bool
	}{
		// UUIDs are valid subdomains
		{"5ec1d7f2-496d-11e9-8646-d663bd873d93", true},
		// But so are all other domain parts with [a-z0-9.-]
		{"a-97455b-52cc-4569-90c8-7a4b97c6eba8", true},
		{"subdomain", true},
		{"even-full-tld.style", true},
		{"and.with.5.parts.too", true},
		// But it has to be lowercase
		{"SUBDOMAIN", false},
		{"even-Full-tld.style", false},
		{"And.with.5.parts.too", false},
		// And these are particularly invalid
		{"", false},
		{"&!#!25123!%!'%", false},
		{"domain.", false},
		{"double..period", false},
	} {
		ret := validSubdomain(test.subdomain)
		if ret != test.output {
			t.Errorf("Test %d: Expected return value %t, but got %t", i, test.output, ret)
		}
	}
}

func TestValidTXT(t *testing.T) {
	for i, test := range []struct {
		txt    string
		output bool
	}{
		{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", true}, // 43 chars
		{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", false},
		{"aaaaaaaaaaaaaaaaaaaaaaaaaaaa#aaaaaaaaaaaaaa", false},
		{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", false},
		{"", false},
	} {
		ret := validTXT(test.txt)
		if ret != test.output {
			t.Errorf("Test %d: Expected return value %t, but got %t", i, test.output, ret)
		}
	}
}

func TestCorrectPassword(t *testing.T) {
	for i, test := range []struct {
		pw     string
		hash   string
		output bool
	}{
		{"PUrNTjU24JYNEOCeS2JcjaJGv1sinT80oV9--dpX",
			"$2a$10$ldVoGU5yrdlbPzuPUbUfleVovGjaRelP9tql0IltVUJk778gf.2tu",
			true},
		{"PUrNTjU24JYNEOCeS2JcjaJGv1sinT80oV9--dpX",
			"$2a$10$ldVoGU5yrdlbPzuPUbUfleVovGjaRelP9tql0IltVUJk778gf.2t",
			false},
		{"PUrNTjU24JYNEOCeS2JcjaJGv1sinT80oV9--dp",
			"$2a$10$ldVoGU5yrdlbPzuPUbUfleVovGjaRelP9tql0IltVUJk778gf.2tu",
			false},
		{"", "", false},
	} {
		ret := correctPassword(test.pw, test.hash)
		if ret != test.output {
			t.Errorf("Test %d: Expected return value %t, but got %t", i, test.output, ret)
		}
	}
}

func TestGetValidCIDRMasks(t *testing.T) {
	for i, test := range []struct {
		input  cidrslice
		output cidrslice
	}{
		{cidrslice{"10.0.0.1/24"}, cidrslice{"10.0.0.1/24"}},
		{cidrslice{"invalid", "127.0.0.1/32"}, cidrslice{"127.0.0.1/32"}},
		{cidrslice{"2002:c0a8::0/32", "8.8.8.8/32"}, cidrslice{"2002:c0a8::0/32", "8.8.8.8/32"}},
	} {
		ret := test.input.ValidEntries()
		if len(ret) == len(test.output) {
			for i, v := range ret {
				if v != test.output[i] {
					t.Errorf("Test %d: Expected %q but got %q", i, test.output, ret)
				}
			}
		} else {
			t.Errorf("Test %d: Expected %q but got %q", i, test.output, ret)
		}
	}
}
