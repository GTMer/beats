// Licensed to Elasticsearch B.V. under one or more contributor
// license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright
// ownership. Elasticsearch B.V. licenses this file to you under
// the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package util

import (
	"encoding/hex"
	"github.com/elastic/beats/libbeat/beat"
	"github.com/elastic/beats/libbeat/common"

	"github.com/elastic/beats/filebeat/input/file"

	"github.com/elastic/beats/signature"
)

type Data struct {
	Event beat.Event
	state file.State
}

func NewData() *Data {
	return &Data{}
}

// SetState sets the state
func (d *Data) SetState(state file.State) {
	d.state = state
}

// GetState returns the current state
func (d *Data) GetState() file.State {
	return d.state
}

// HasState returns true if the data object contains state data
func (d *Data) HasState() bool {
	return !d.state.IsEmpty()
}

// GetEvent returns the event in the data object
// In case meta data contains module and fileset data, the event is enriched with it
func (d *Data) GetEvent() beat.Event {
	return d.Event
}

// GetMetadata creates a common.MapStr containing the metadata to
// be associated with the event.
func (d *Data) GetMetadata() common.MapStr {
	return d.Event.Meta
}

// HasEvent returns true if the data object contains event data
func (d *Data) HasEvent() bool {
	return d.Event.Fields != nil
}

var privateKey  = []byte(`
-----BEGIN PRIVATE KEY-----
MIICeQIBADANBgkqhkiG9w0BAQEFAASCAmMwggJfAgEAAoGBAMv6DptwpL8pD0Og
llle4Ui6Kz0hS9QrPJ+Q9q/p4Yz8c5GIFBckeSR/d36MiobTomUDlWfU/MAHBCOu
xBvqGb17BIUR72OZZIt9Kda128ir9d8/TANZBYipv8lKdNf2p+p3CTxidxHgefFs
kIzZfV1uY26sLkDawCRNlMFrGnf/AgMBAAECgYEAkGo6bVMTUUSAyiCoUh4a4qLs
ehtY1J7IDTFVdrbgOjGCoUb28mugWXbl43MdoNe14k7nONxTFqHhDGJv9lOIZJoH
h1K2up2ssRf9RgzvuE6LCI0YNGweO6yj55HhGK6w3GQAWZzqc7u4LTuUSl8LcaVc
zsA+ZNOGFxHe1LhQbAECQQD6VzaliWNa3K7TyThywh3aC9m5WgiVLH7zr9fFUz/N
+B/aFBq43hn9K/NSaTuPz+VO5cjJ1XA7rlESL0ZLdw6pAkEA0JaGEalew28QMFw3
GX2RDZH4rapKiuUtUIwf1Tzm0FuxExawggcLc3tRJiaUGB9t94KoMhNm8c/pss0U
mIxCZwJBAM3GTob3TZHsgFBZwGqkIUGQKCFxXkiwUJIiYmwyp+m4IQZzLBv1hMtU
Cygck/b8XnLh8o/lP+HuwXj/Hvr9HDECQQCradeZcgd3MbErHM0G/KKUdU3YYaZK
iFV56P1L/nVr6r4VAsNgx6tIZqHkaTWwsTtseIoCROGHfKX/kvsG9dSnAkEAheRy
uJBZp1lRMGC3mwX3dFh5FSVymMav3o/fTCpEPG4WSAr4LR1dIwJDbJ6LubvPcdqr
AgaQqoTNDp/vX0T6rw==
-----END PRIVATE KEY-----
`)

var publicKey = []byte(`
-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDL+g6bcKS/KQ9DoJZZXuFIuis9
IUvUKzyfkPav6eGM/HORiBQXJHkkf3d+jIqG06JlA5Vn1PzABwQjrsQb6hm9ewSF
Ee9jmWSLfSnWtdvIq/XfP0wDWQWIqb/JSnTX9qfqdwk8YncR4HnxbJCM2X1dbmNu
rC5A2sAkTZTBaxp3/wIDAQAB
-----END PUBLIC KEY-----
`)

func (d *Data) SignMessage() {
	mess := d.Event.Fields["message"].(string)
	str,_ := signature.RsaSignWithSha1Hex(mess,hex.EncodeToString(privateKey))
	d.Event.Fields["message"] = mess + "*[" + str + "]*"
}