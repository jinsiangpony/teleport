//go:build touchid
// +build touchid

// Copyright 2022 Gravitational, Inc
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

package touchid

// #cgo CFLAGS: -Wall -xobjective-c -fblocks -fobjc-arc
// #cgo LDFLAGS: -framework CoreFoundation -framework Foundation -framework LocalAuthentication -framework Security
// #include <stdlib.h>
// #include "authenticate.h"
// #include "credential_info.h"
// #include "credentials.h"
// #include "register.h"
import "C"

import (
	"crypto/ecdsa"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"unsafe"

	"github.com/google/uuid"
	"github.com/gravitational/trace"

	log "github.com/sirupsen/logrus"
)

func init() {
	native = &touchIDImpl{}
}

type touchIDImpl struct{}

func (*touchIDImpl) IsAvailable() bool {
	// TODO(codingllama): Write a deeper check that looks at binary
	//  signature/entitlements/etc.
	return true
}

func (*touchIDImpl) Register(rpID, user string, userHandle []byte) (*CredentialInfo, error) {
	credentialID := uuid.NewString()
	userHandleB64 := base64.RawURLEncoding.EncodeToString(userHandle)

	var req C.CredentialInfo
	req.label = C.CString(makeLabel(rpID, user))
	req.app_label = C.CString(credentialID)
	req.app_tag = C.CString(userHandleB64)
	defer func() {
		C.free(unsafe.Pointer(req.label))
		C.free(unsafe.Pointer(req.app_label))
		C.free(unsafe.Pointer(req.app_tag))
	}()

	var errMsgC, pubKeyC *C.char
	defer func() {
		C.free(unsafe.Pointer(errMsgC))
		C.free(unsafe.Pointer(pubKeyC))
	}()

	if res := C.Register(req, &pubKeyC, &errMsgC); res != 0 {
		errMsg := C.GoString(errMsgC)
		return nil, errors.New(errMsg)
	}

	pubKeyB64 := C.GoString(pubKeyC)
	pubKeyRaw, err := base64.StdEncoding.DecodeString(pubKeyB64)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return &CredentialInfo{
		CredentialID: credentialID,
		publicKeyRaw: pubKeyRaw,
	}, nil
}

// rpID are domain names, so it's safe to assume they won't have spaces in them.
// https://www.w3.org/TR/webauthn-2/#relying-party-identifier
const labelSeparator = " "

func makeLabel(rpID, user string) string {
	return fmt.Sprintf("%v%v%v", rpID, labelSeparator, user)
}

func splitLabel(label string) (string, string) {
	idx := strings.Index(label, labelSeparator)
	if idx == -1 {
		return "", ""
	}
	rpID := label[0:idx]
	user := label[idx+1:]
	return rpID, user
}

func (*touchIDImpl) Authenticate(credentialID string, digest []byte) ([]byte, error) {
	var req C.AuthenticateRequest
	req.app_label = C.CString(credentialID)
	req.digest = C.CString(string(digest))
	req.digest_len = C.int(len(digest))
	defer func() {
		C.free(unsafe.Pointer(req.app_label))
		C.free(unsafe.Pointer(req.digest))
	}()

	var sigOutC, errMsgC *C.char
	defer func() {
		C.free(unsafe.Pointer(sigOutC))
		C.free(unsafe.Pointer(errMsgC))
	}()

	if res := C.Authenticate(req, &sigOutC, &errMsgC); res != 0 {
		errMsg := C.GoString(errMsgC)
		return nil, errors.New(errMsg)
	}

	sigB64 := C.GoString(sigOutC)
	return base64.StdEncoding.DecodeString(sigB64)
}

func (*touchIDImpl) FindCredentials(rpID, user string) ([]CredentialInfo, error) {
	infos, res := findCredentialsImpl(rpID, user, func(filter C.LabelFilter, infosC **C.CredentialInfo) C.int {
		return C.FindCredentials(filter, infosC)
	})
	if res < 0 {
		return nil, fmt.Errorf("failed to find credentials: status %d", res)
	}
	return infos, nil
}

func findCredentialsImpl(rpID, user string, find func(C.LabelFilter, **C.CredentialInfo) C.int) ([]CredentialInfo, int) {
	var filterC C.LabelFilter
	if user == "" {
		filterC.kind = C.LABEL_PREFIX
	}
	filterC.value = C.CString(makeLabel(rpID, user))
	defer C.free(unsafe.Pointer(filterC.value))

	var infosC *C.CredentialInfo
	defer C.free(unsafe.Pointer(infosC))

	res := find(filterC, &infosC)
	if res < 0 {
		return nil, int(res)
	}

	start := unsafe.Pointer(infosC)
	size := unsafe.Sizeof(C.CredentialInfo{})
	infos := make([]CredentialInfo, res)
	for i := 0; i < int(res); i++ {
		// IMPORTANT: The defer below is used to free the pointers inside infos.
		// It relies on the fact that we never error out of the function after
		// this point, otherwise some instances would leak.
		infoC := (*C.CredentialInfo)(unsafe.Add(start, uintptr(i)*size))
		defer func() {
			C.free(unsafe.Pointer(infoC.label))
			C.free(unsafe.Pointer(infoC.app_label))
			C.free(unsafe.Pointer(infoC.app_tag))
			C.free(unsafe.Pointer(infoC.pub_key_b64))
		}()

		// user@rpid
		label := C.GoString(infoC.label)
		rpID, user := splitLabel(label)
		if rpID == "" || user == "" {
			log.Debugf("Skipping credential with unexpected label: %q", label)
			continue
		}

		// credential ID / UUID
		credentialID := C.GoString(infoC.app_label)

		// user handle
		appTag := C.GoString(infoC.app_tag)
		userHandle, err := base64.RawURLEncoding.DecodeString(appTag)
		if err != nil {
			log.Debugf("Skipping credential with unexpected application tag: %q", appTag)
			continue
		}

		// ECDSA public key
		var pubKey *ecdsa.PublicKey
		pubKeyB64 := C.GoString(infoC.pub_key_b64)
		pubKeyRaw, err := base64.StdEncoding.DecodeString(pubKeyB64)
		if err != nil {
			log.WithError(err).Warn("Failed to decode public key for credential %q", credentialID)
		} else {
			pubKey = pubKeyFromRawAppleKey(pubKeyRaw)
		}

		infos[i] = CredentialInfo{
			UserHandle:   userHandle,
			CredentialID: credentialID,
			RPID:         rpID,
			User:         user,
			PublicKey:    pubKey,
		}
	}
	return infos, int(res)
}
