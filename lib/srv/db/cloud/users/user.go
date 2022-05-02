/*
Copyright 2022 Gravitational, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package users

import (
	"context"
	"time"

	"github.com/gravitational/teleport/lib/secrets"
	"github.com/gravitational/teleport/lib/utils"
	"github.com/gravitational/trace"
)

type user struct {
	secrets                     secrets.Secrets
	secretKeyPath               string
	databaseUserName            string
	maxPasswordLength           int
	usePreviousPasswordForLogin bool
	modifyUserFunc              func(ctx context.Context, oldPassword, newPassword string) error
}

func (u *user) String() string {
	return u.GetID()
}

func (u *user) GetID() string {
	return u.secretKeyPath
}

func (u *user) GetDatabaseUserName() string {
	return u.databaseUserName
}

func (u *user) GetPassword(ctx context.Context) (string, error) {
	version := secrets.CurrentVersion
	if u.usePreviousPasswordForLogin {
		version = secrets.PreviousVersion
	}

	value, err := u.secrets.GetValue(ctx, u.secretKeyPath, version)
	if err != nil {
		return "", trace.Wrap(err)
	}
	return value.Value, nil
}

func (u *user) RotatePassword(ctx context.Context, lastUpdateExpiresAt time.Time) error {
	currentValue, err := u.secrets.GetValue(ctx, u.secretKeyPath, secrets.CurrentVersion)
	if err != nil {
		if trace.IsNotFound(err) {
			return u.createNewPassowrdSecret(ctx)
		}

		return trace.Wrap(err)
	}

	// The password is up-to-date. Nothing to do.
	if currentValue.CreatedAt.After(lastUpdateExpiresAt) {
		return nil
	}

	return u.updatePasswordSecret(ctx, currentValue)
}

func (u *user) DeletePassword(ctx context.Context) error {
	return trace.Wrap(u.secrets.Delete(ctx, u.secretKeyPath))
}

func (u *user) createNewPassowrdSecret(ctx context.Context) error {
	newPassword, err := genRandomPassword(u.maxPasswordLength)
	if err != nil {
		return trace.Wrap(err)
	}
	if err = u.secrets.Create(ctx, u.secretKeyPath, newPassword); err != nil {
		return trace.Wrap(err)
	}

	if u.modifyUserFunc != nil {
		return u.modifyUserFunc(ctx, "", newPassword)
	}
	return nil
}

func (u *user) updatePasswordSecret(ctx context.Context, currentValue *secrets.SecretValue) error {
	newPassword, err := genRandomPassword(u.maxPasswordLength)
	if err != nil {
		return trace.Wrap(err)
	}
	if err = u.secrets.PutValue(ctx, u.secretKeyPath, newPassword, currentValue.Version); err != nil {
		return trace.Wrap(err)
	}

	if u.modifyUserFunc != nil {
		return u.modifyUserFunc(ctx, currentValue.Value, newPassword)
	}
	return nil
}

// genRandomPassword generate a random password for specified length.
func genRandomPassword(length int) (string, error) {
	if length <= 0 {
		return "", trace.BadParameter("invalid random value length")
	}

	// Hex generated from CryptoRandomHex is twice of the input.
	hex, err := utils.CryptoRandomHex((length + 1) / 2)
	if err != nil {
		return "", trace.Wrap(err)
	} else if len(hex) < length {
		return "", trace.CompareFailed("generated hex is too short")
	}
	return hex[:length], nil
}
