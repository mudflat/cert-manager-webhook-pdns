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

package main

import (
	"context"
	"os"

	cmd "github.com/jetstack/cert-manager/pkg/acme/webhook/cmd"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	pdns "mudflat.io/cert-manager-webhook-pdns/pkg/provider"
)

func main() {
	logLevel := os.Getenv("LOG_LEVEL")
	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	if logLevel != "" {
		if l, err := zerolog.ParseLevel(logLevel); err != nil {
			zerolog.SetGlobalLevel(l)
		}
	}

	groupName := os.Getenv("GROUP_NAME")
	if groupName == "" {
		log.Panic().Msg("GROUP_NAME must be specified")
	}

	log.Info().Msg("Starting Cert-Manager PowerDNS Webhook")
	cmd.RunWebhookServer(groupName,
		pdns.NewPowerDNSProviderSolver(context.Background()),
	)
}
