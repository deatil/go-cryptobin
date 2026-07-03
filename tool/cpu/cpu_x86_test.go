// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build 386 || amd64

package cpu_test

import (
	"testing"

	. "github.com/deatil/go-cryptobin/tool/cpu"
)

func TestX86ifAVX2hasAVX(t *testing.T) {
	if X86.HasAVX2 && !X86.HasAVX {
		t.Fatalf("HasAVX expected true when HasAVX2 is true, got false")
	}
}

func TestDisableSSE3(t *testing.T) {
	if GetGOAMD64level() > 1 {
		t.Skip("skipping test: can't run on GOAMD64>v1 machines")
	}
	runDebugOptionsTest(t, "TestSSE3DebugOption", "cpu.sse3=off")
}

