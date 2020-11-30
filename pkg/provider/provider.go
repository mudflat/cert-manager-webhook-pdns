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

package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	whapi "github.com/jetstack/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	"github.com/rs/zerolog/log"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	restclient "k8s.io/client-go/rest"
	"mudflat.io/cert-manager-webhook-pdns/pkg/pdns"
)

type powerDNSProviderConfig struct {
	Host            string                   `json:"host"`
	APIKeySecretRef cmmeta.SecretKeySelector `json:"apiKeySecretRef"`

	// +optional
	ServerID string `json:"serverID"`

	// +optional
	TTL int `json:"ttl"`

	// +optional
	Timeout int `json:"timeout"`
}

type PowerDNSProviderSolver struct {
	client *kubernetes.Clientset
	ctx    context.Context
}

func NewPowerDNSProviderSolver(ctx context.Context) *PowerDNSProviderSolver {
	return &PowerDNSProviderSolver{ctx: ctx}
}

func (p *PowerDNSProviderSolver) Initialize(kubeClientConfig *restclient.Config, stopCh <-chan struct{}) (err error) {
	log.Info().Msg("Initializing PowerDNS Solver")
	p.client, err = kubernetes.NewForConfig(kubeClientConfig)
	return
}

func (p *PowerDNSProviderSolver) Present(ch *whapi.ChallengeRequest) error {
	log.Info().Msgf("Presenting challenge for fqdn=%s zone=%s", ch.ResolvedFQDN, ch.ResolvedZone)
	log.Trace().Msgf("Present: DNSName: %s, Key: %s, ResolvedFQDN: %s, ResolvedZone: %s",
		ch.DNSName,
		ch.Key,
		ch.ResolvedFQDN,
		ch.ResolvedZone,
	)
	client, err := p.newClientFromConfig(ch)

	if err != nil {
		log.Error().Msgf("failed to get client from ChallengeRequest: %s", err)
		return err
	}

	err = client.Initialize()
	if err != nil {
		log.Error().Msgf("Failed to initialize pdns client: %s", err)
		return err
	}

	rn, domain := extractNames(ch.ResolvedFQDN)

	log.Info().Msgf("creating DNS record %s/%s", rn, domain)
	err = client.CreateTxtRecord(rn, domain, ch.Key)

	if err != nil {
		log.Error().Msgf("failed to create DNS Record '%s/%s': %s", rn, domain, err)
		return err
	}

	log.Info().Msgf("Successfully created txt record for fqdn=%s zone=%s", ch.ResolvedFQDN, ch.ResolvedZone)
	return nil
}

func (p *PowerDNSProviderSolver) CleanUp(ch *whapi.ChallengeRequest) error {
	log.Info().Msgf("Cleaning up entry for fqdn=%s", ch.ResolvedFQDN)
	client, err := p.newClientFromConfig(ch)
	if err != nil {
		log.Error().Msgf("failed to get client from ChallengeRequest: %s", err)
		return fmt.Errorf("failed to get client from ChallengeRequest: %w", err)
	}

	err = client.Initialize()
	if err != nil {
		log.Error().Msgf("Failed to initialize pdns client: %s", err)
		return err
	}

	rn, domain := extractNames(ch.ResolvedFQDN)

	err = client.DeleteTxtRecord(rn, domain, ch.Key)
	if err != nil {
		log.Error().Msgf("failed to delete DNS record '%s': %s", rn, err)
		return fmt.Errorf("failed to delete DNS record '%s': %s", rn, err)
	}

	return nil
}

func (p *PowerDNSProviderSolver) Name() string {
	return "pdns"
}

func (p *PowerDNSProviderSolver) newClientFromConfig(ch *whapi.ChallengeRequest) (pdns.Client, error) {
	cfg, err := p.loadConfig(ch)
	if err != nil {
		return nil, err
	}

	apiKey, err := p.getSecretData(cfg.APIKeySecretRef, ch.ResourceNamespace)
	if err != nil {
		return nil, err
	}

	return pdns.NewClient(cfg.Host, cfg.ServerID, apiKey, cfg.TTL, cfg.Timeout)
}

func (p *PowerDNSProviderSolver) loadConfig(ch *whapi.ChallengeRequest) (*powerDNSProviderConfig, error) {
	cfg := &powerDNSProviderConfig{}
	if ch.Config == nil {
		return cfg, nil
	}

	if err := json.Unmarshal(ch.Config.Raw, cfg); err != nil {
		return cfg, fmt.Errorf("error decoding solver config: %v", err)
	}

	return cfg, nil
}

func (p *PowerDNSProviderSolver) getSecretData(secretRef cmmeta.SecretKeySelector, ns string) (string, error) {
	secret, err := p.client.CoreV1().Secrets(ns).Get(p.ctx, secretRef.LocalObjectReference.Name, metav1.GetOptions{})
	if err != nil {
		return "", fmt.Errorf("failed to load secret %s/%s: %w", ns, secretRef.LocalObjectReference.Name, err)
	}

	if data, ok := secret.Data[secretRef.Key]; ok {
		return string(data), nil
	}

	return "", fmt.Errorf("no key %s in secret %s/%s", "api-key", ns, secretRef.LocalObjectReference.Name)
}

func extractNames(fqdn string) (string, string) {
	p := strings.Split(fqdn, ".")
	record := p[0]
	zone := strings.Join(p[1:], ".")
	zone = strings.TrimSuffix(zone, ".")
	return record, zone
}
