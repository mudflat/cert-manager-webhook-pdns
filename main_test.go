// Copyright 2020 Steve Giacomelli <stevegiacomelli@gmail.com>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
// ---------------------------------------------------------------------
// Note: This test requires that the pdns-mock in /test/mock is running
//    # docker run -d -p 8081:8081 -p 53:53 -p 53:53/udp pdns-mock
// TODO: incorporate into build process

package main

import (
	"context"
	"testing"

	"github.com/jetstack/cert-manager/test/acme/dns"
	"github.com/rs/zerolog"
	pdns "mudflat.io/cert-manager-webhook-pdns/pkg/provider"
)

var (
	zone               = "example.com."
	kubeBuilderBinPath = "./_out/kubebuilder/bin"
)

func TestRunsSuite(t *testing.T) {
	zerolog.SetGlobalLevel(zerolog.TraceLevel)

	// The manifest path should contain a file named config.json that is a
	// snippet of valid configuration that should be included on the
	// ChallengeRequest passed as part of the test cases.
	fixture := dns.NewFixture(pdns.NewPowerDNSProviderSolver(context.Background()),
		dns.SetBinariesPath(kubeBuilderBinPath),
		dns.SetResolvedZone(zone),
		dns.SetAllowAmbientCredentials(false),
		dns.SetManifestPath("test/pdns"),
		dns.SetStrict(true),
		dns.SetDNSServer("127.0.0.1:53"),
	)

	fixture.RunConformance(t)
}
