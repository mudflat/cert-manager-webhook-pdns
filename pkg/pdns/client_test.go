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
// Refactor Tests

package pdns

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

const (
	host        = "http://localhost:8081"
	apiKey      = "gskNsnFZLTwj8yhcuggKgIlJF26RMGsr"
	zoneName    = "example.com"
	recordName  = "challenge"
	recordValue = "response"
)

func TestRunSuite(t *testing.T) {
	c, err := NewClient(host, "localhost", apiKey, 0, 0)
	if err != nil {
		t.Errorf("Error creating client %s", err)
		return
	}

	err = c.Initialize()
	if err != nil {
		t.Errorf("Error initializing client %s", err)
		return
	}

	r, err := c.TxtRecord(recordName, zoneName)
	if err != nil {
		t.Errorf("Error retrieving txt records %v", err)
	}
	assert.Empty(t, r, "Error unexpected txt records")

	err = c.CreateTxtRecord(recordName, zoneName, recordValue)
	if err != nil {
		t.Errorf("Error creating txt record: %v", err)
		return
	}

	r, err = c.TxtRecord(recordName, zoneName)
	if err != nil {
		t.Errorf("Error retrieving txt records %v", err)
	}
	assert.NotEmpty(t, r, "Error expected txt records")
	for _, s := range r {
		assert.Containsf(t, s.Values(), "\""+recordValue+"\"", "Error expected value: %s", recordValue)
	}

	err = c.DeleteTxtRecord("challenge", zoneName, "")
	if err != nil {
		t.Errorf("Error deleting txt record: %v", err)
		return
	}

	r, err = c.TxtRecord(recordName, zoneName)
	if err != nil {
		t.Errorf("Error retrieving txt records %v", err)
	}
	assert.Empty(t, r, "Error unexpected txt records")
}
