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
// -------------------------
// TODO: Remove superfluous interfaces / types

package pdns

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
)

type TxtRecord interface {
	Name() string
	Values() []string
}

type record struct {
	Content  string `json:"content"`
	Disabled bool   `json:"disabled"`

	// pre-v1 API
	Name string `json:"name"`
	Type string `json:"type"`
	TTL  int    `json:"ttl,omitempty"`
}

type hostedZone struct {
	ID_     string   `json:"id"`
	Name_   string   `json:"name"`
	URL_    string   `json:"url"`
	RRSets_ []*rrSet `json:"rrsets"`

	// pre-v1 API
	Records_ []record `json:"records"`

	// extracted txt records
	txtRecords []TxtRecord
}

type Zone interface {
	ID() string
	Name() string
	URL() string
	TxtRecords() []TxtRecord
}

func (z *hostedZone) ID() string {
	return z.ID_
}

func (z *hostedZone) Name() string {
	return z.Name_
}

func (z *hostedZone) URL() string {
	return z.URL_
}

func (z *hostedZone) TxtRecords() []TxtRecord {
	return z.txtRecords
}

func (z *hostedZone) String() string {
	return fmt.Sprintf("Zone: %s, %s, %s, %v", z.ID_, z.Name_, z.URL_, z.TxtRecords())
}

type txtRecord struct {
	name   string
	values []string
}

func (t *txtRecord) Name() string {
	return t.name
}

func (t *txtRecord) Values() []string {
	return t.values
}

func (t *txtRecord) String() string {
	return fmt.Sprintf("%s: %v", t.name, t.values)
}

type rrSet struct {
	Name       string   `json:"name"`
	Type       string   `json:"type"`
	Kind       string   `json:"kind"`
	ChangeType string   `json:"changetype"`
	Records    []record `json:"records"`
	TTL        int      `json:"ttl,omitempty"`
}

func (r *rrSet) String() string {
	return fmt.Sprintf("%s %s %s %s %v %v", r.Name, r.Type, r.Kind, r.ChangeType, r.Records, r.TTL)
}

type rrSets struct {
	RRSets []rrSet `json:"rrsets"`
}

type apiError struct {
	ShortMsg string `json:"error"`
}

func (a apiError) Error() string {
	return a.ShortMsg
}

type apiVersion struct {
	URL     string `json:"url"`
	Version int    `json:"version"`
}

type Client interface {
	Initialize() error
	APIVersion() int
	TxtRecord(recordName, zoneName string) ([]TxtRecord, error)
	CreateTxtRecord(recordName, zoneName, value string) error
	DeleteTxtRecord(recordName, zoneName, value string) error
}

type pdnsClient struct {
	host       *url.URL
	serverID   string
	apiKey     string
	apiVersion int
	ttl        int
	client     *http.Client
}

func NewClient(host, serverID, apiKey string, ttl, timeout int) (client Client, err error) {
	host = strings.TrimSpace(host)
	if host == "" {
		log.Error().Msg("host must be set")
	}

	hostURL, err := url.Parse(host)
	if err != nil {
		log.Error().Msgf("Invalid host %s", host)
		return
	}

	serverID = strings.TrimSpace(serverID)
	if serverID == "" {
		serverID = "localhost"
	}

	apiKey = strings.TrimSpace(apiKey)
	if apiKey == "" {
		log.Error().Msg("apiKey must be set")

	}

	if ttl == 0 {
		ttl = 120
	}

	if timeout == 0 {
		timeout = 30
	}

	client = &pdnsClient{
		host:     hostURL,
		serverID: serverID,
		apiKey:   apiKey,
		ttl:      ttl,
		client:   &http.Client{Timeout: time.Duration(timeout) * time.Second},
	}

	return
}

func (d *pdnsClient) Initialize() error {
	return d.setAPIVersion()
}

func (d *pdnsClient) APIVersion() int {
	return d.apiVersion
}

func (d *pdnsClient) getTxtRecord(recordName string, zone Zone) ([]TxtRecord, error) {
	log.Trace().Msgf("getTxtRecord: recordName: %s", recordName)

	if d.apiVersion > 0 {
		recordName = recordName + "." + zone.Name()
	}

	o := []TxtRecord{}
	for _, r := range zone.TxtRecords() {
		if r.Name() == recordName {
			o = append(o, r)
		}
	}
	return o, nil
}

func (d *pdnsClient) TxtRecord(recordName, zoneName string) ([]TxtRecord, error) {
	log.Trace().Msgf("TxtRecord: recordName: %s, zoneName: %s", recordName, zoneName)
	zone, err := d.getZone(zoneName)
	if err != nil {
		return nil, err
	}

	return d.getTxtRecord(recordName, zone)
}

func (d *pdnsClient) CreateTxtRecord(recordName, zoneName, value string) error {
	log.Trace().Msgf("CreateTxtRecord: recordName: %s, zoneName: %s, value: %s", recordName, zoneName, value)
	zone, err := d.getZone(zoneName)
	if err != nil {
		return err
	}
	txt, err := d.getTxtRecord(recordName, zone)
	if err != nil {
		return err
	}

	if d.apiVersion > 0 {
		recordName = recordName + "." + zone.Name()
	}

	recordValue := "\"" + value + "\""
	records := []record{}
	for _, r := range txt {
		for _, v := range r.Values() {
			fmt.Println(v)
			if v != recordValue {
				records = append(records, record{
					Content:  v,
					Disabled: false,

					// pre-v1 API
					Type: "TXT",
					Name: recordName,
					TTL:  d.ttl,
				})
			}
		}
	}

	records = append(records, record{
		Content:  recordValue,
		Disabled: false,

		// pre-v1 API
		Type: "TXT",
		Name: recordName,
		TTL:  d.ttl,
	})

	rrsets := rrSets{
		RRSets: []rrSet{
			{
				Name:       recordName,
				ChangeType: "REPLACE",
				Type:       "TXT",
				Kind:       "Master",
				TTL:        d.ttl,
				Records:    records,
			},
		},
	}

	body, err := json.Marshal(rrsets)
	if err != nil {
		return err
	}

	_, err = d.sendRequest(http.MethodPatch, zone.URL(), bytes.NewReader(body))
	if err != nil {
		return err
	}

	return nil
}

func (d *pdnsClient) DeleteTxtRecord(recordName, zoneName, recordValue string) error {
	log.Trace().Msgf("DeleteTxtRecord: recordName: %s, zoneName: %s", recordName, zoneName)
	zone, err := d.getZone(zoneName)
	if err != nil {
		return err
	}

	txt, err := d.getTxtRecord(recordName, zone)
	if err != nil {
		return err
	}
	if d.apiVersion > 0 {
		recordName = recordName + "." + zone.Name()
	}
	recordValue = "\"" + recordValue + "\""
	records := []record{}
	for _, r := range txt {
		for _, v := range r.Values() {
			if recordValue == "" || v == recordValue {
				continue
			}
			records = append(records, record{
				Content:  v,
				Disabled: false,

				// pre-v1 API
				Type: "TXT",
				Name: recordName,
				TTL:  d.ttl,
			})
		}
	}

	rrsets := rrSets{
		RRSets: []rrSet{
			{
				Name:       recordName,
				ChangeType: "REPLACE",
				Type:       "TXT",
				Kind:       "Master",
				TTL:        d.ttl,
				Records:    records,
			},
		},
	}

	body, err := json.Marshal(rrsets)
	if err != nil {
		return err
	}

	_, err = d.sendRequest(http.MethodPatch, zone.URL(), bytes.NewReader(body))
	if err != nil {
		return err
	}

	return nil
}

func (d *pdnsClient) makeRequest(method, uri string, body io.Reader) (*http.Request, error) {
	var path = ""
	if d.host.Path != "/" {
		path = d.host.Path
	}

	if !strings.HasPrefix(uri, "/") {
		uri = "/" + uri
	}

	if d.apiVersion > 0 && !strings.HasPrefix(uri, "/api/v") {
		uri = "/api/v" + strconv.Itoa(d.apiVersion) + uri
	}

	u := d.host.Scheme + "://" + d.host.Host + path + uri
	req, err := http.NewRequest(method, u, body)
	if err != nil {
		return nil, err
	}

	req.Header.Set("X-API-Key", d.apiKey)

	return req, nil
}

func (d *pdnsClient) sendRequest(method, uri string, body io.Reader) (json.RawMessage, error) {
	req, err := d.makeRequest(method, uri, body)
	if err != nil {
		return nil, err
	}

	resp, err := d.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error talking to PDNS API -> %v", err)
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnprocessableEntity && (resp.StatusCode < 200 || resp.StatusCode >= 300) {
		return nil, fmt.Errorf("unexpected HTTP status code %d when fetching '%s'", resp.StatusCode, req.URL)
	}

	var msg json.RawMessage
	err = json.NewDecoder(resp.Body).Decode(&msg)
	if err != nil {
		if err == io.EOF {
			// empty body
			return nil, nil
		}
		// other error
		return nil, err
	}

	// check for PowerDNS error message
	if len(msg) > 0 && msg[0] == '{' {
		var errInfo apiError
		err = json.Unmarshal(msg, &errInfo)
		if err != nil {
			return nil, err
		}
		if errInfo.ShortMsg != "" {
			return nil, fmt.Errorf("error talking to PDNS API -> %v", errInfo)
		}
	}
	return msg, nil
}

func (d *pdnsClient) setAPIVersion() error {
	result, err := d.sendRequest(http.MethodGet, "/api", nil)
	if err != nil {
		return err
	}

	var versions []apiVersion
	if err := json.Unmarshal(result, &versions); err != nil {
		return err
	}

	latestVersion := 0
	for _, v := range versions {
		if v.Version > latestVersion {
			latestVersion = v.Version
		}
	}

	d.apiVersion = latestVersion
	return nil
}

func (d *pdnsClient) getZone(zoneName string) (Zone, error) {
	if !strings.HasSuffix(zoneName, ".") {
		zoneName = zoneName + "."
	}

	u := fmt.Sprint("/servers/", d.serverID, "/zones/", zoneName)
	result, err := d.sendRequest(http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}

	var zone hostedZone
	err = json.Unmarshal(result, &zone)
	if err != nil {
		return nil, err
	}

	// convert pre-v1 API result
	if len(zone.Records_) > 0 {
		zone.RRSets_ = []*rrSet{}
		for _, r := range zone.Records_ {
			set := &rrSet{
				Name:    r.Name,
				Type:    r.Type,
				Records: []record{r},
			}
			zone.RRSets_ = append(zone.RRSets_, set)
		}
	}

	zone.txtRecords = []TxtRecord{}
	for _, r := range zone.RRSets_ {
		if r.Type != "TXT" {
			continue
		}
		v := []string{}
		for _, s := range r.Records {
			v = append(v, s.Content)
		}
		zone.txtRecords = append(zone.txtRecords, &txtRecord{name: r.Name, values: v})
	}

	return &zone, nil
}
