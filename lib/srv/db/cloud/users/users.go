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
	"path"
	"sync"
	"time"

	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/srv/db/common"
	"github.com/gravitational/teleport/lib/utils"
	"github.com/gravitational/teleport/lib/utils/interval"
	"github.com/gravitational/trace"
	"github.com/jonboulle/clockwork"
	"github.com/sirupsen/logrus"
)

type GetDatabasesFunc func() types.Databases

// Config is the config for Users.
type Config struct {
	// Clients is an interface for retrieving cloud clients.
	Clients common.CloudClients
	// Clock is used to control time.
	Clock clockwork.Clock
	// Interval is the interval between user updates. Interval is also used as
	// the minimum password expiration duration.
	Interval time.Duration
	// Cache is used to cache cloud resources fetched from cloud APIs to avoid
	// making same the call repeatedly in a short time.
	Cache *utils.FnCache
}

// CheckAndSetDefaults validates the config and set defaults.
func (c *Config) CheckAndSetDefaults() (err error) {
	if c.Clients == nil {
		c.Clients = common.NewCloudClients()
	}
	if c.Clock == nil {
		c.Clock = clockwork.NewRealClock()
	}
	if c.Interval == 0 {
		// AWS Secrets Manager can have at most 100 versions per day (about one
		// new version per 15 minutes).
		//
		// https://docs.aws.amazon.com/secretsmanager/latest/userguide/reference_limits.html
		//
		// Note that currently all database types are sharing the same interval
		// for password rotations.
		c.Interval = 15 * time.Minute
	}
	if c.Cache == nil {
		c.Cache, err = utils.NewFnCache(utils.FnCacheConfig{
			TTL:   c.Interval / 2, // Make sure cache expires at next interval.
			Clock: c.Clock,
		})
		if err != nil {
			return trace.Wrap(err)
		}
	}
	return nil
}

type usersMap map[types.Database][]*user

// TODO
type Users struct {
	cfg Config
	log logrus.FieldLogger

	users usersMap
	mu    sync.RWMutex
}

// TODO
func NewUsers(cfg Config) (*Users, error) {
	if err := cfg.CheckAndSetDefaults(); err != nil {
		return nil, trace.Wrap(err)
	}

	return &Users{
		cfg:   cfg,
		log:   logrus.WithField(trace.Component, "cloudusers"),
		users: make(usersMap),
	}, nil
}

// TODO
func (u *Users) GetPassword(ctx context.Context, database types.Database, username string) (string, error) {
	u.mu.RLock()
	user, found := findUserByName(u.users[database], username)
	u.mu.RUnlock()

	if !found {
		return "", trace.NotFound("database user %s is not managed", username)
	}

	password, err := user.GetPassword(ctx)
	if err != nil {
		return "", trace.ConnectionProblem(err, "failed to get password for database %v, user %v.", database.GetName(), username)
	}
	return password, nil
}

// TODO
func (u *Users) SetupDatabase(ctx context.Context, database types.Database) error {
	databaseUsers, err := u.setupDatabase(ctx, database)
	if len(databaseUsers) > 0 {
		u.mu.Lock()
		u.users[database] = databaseUsers
		u.mu.Unlock()
	}
	return trace.Wrap(err)
}

// TODO
func (u *Users) Start(ctx context.Context, getDatabases GetDatabasesFunc) {
	ticker := interval.New(interval.Config{
		Jitter:   utils.NewSeventhOutboundJitter(),
		Duration: u.cfg.Interval,
	})

	u.log.Debug("Starting cloud users service.")
	defer u.log.Debug("Cloud users service done.")

	for {
		select {
		case <-ticker.Next():
			u.SetupAllDatabases(ctx, getDatabases())
		case <-ctx.Done():
			return
		}
	}
}

func (u *Users) SetupAllDatabases(ctx context.Context, allDatabases types.Databases) {
	// Discover users.
	newUsers := make(usersMap)
	for _, database := range allDatabases {
		databaseUsers, err := u.setupDatabase(ctx, database)
		if len(databaseUsers) > 0 {
			u.log.Debugf("Found %d managed users for database %v.", len(databaseUsers), database)
			newUsers[database] = databaseUsers
		}
		if err != nil {
			u.log.WithError(err).Warnf("Failed to setup users for database %v.", database)
		}
	}

	// Update internal tracking.
	u.mu.Lock()
	removedUsers := findRemovedUsers(u.users, newUsers)
	u.users = newUsers
	u.mu.Unlock()

	// Teardown users that are no longer managed.
	for _, user := range removedUsers {
		if err := user.DeletePassword(ctx); err != nil {
			u.log.WithError(err).Warnf("Failed to delete password for user %v.", user)
		}
	}
}

func (u *Users) setupDatabase(ctx context.Context, database types.Database) ([]*user, error) {
	databaseUsers, err := u.fetchDatabaseUsers(ctx, database)
	if err != nil || len(databaseUsers) == 0 {
		return nil, trace.Wrap(err)
	}

	// Passwords are considered expired if last update is more than
	// config.Interval ago.
	lastUpdateExpiresAt := u.cfg.Clock.Now().Add(-u.cfg.Interval)
	var errs []error
	for _, databaseUser := range databaseUsers {
		if err = databaseUser.RotatePassword(ctx, lastUpdateExpiresAt); err != nil {
			errs = append(errs, err)
		}
	}
	return databaseUsers, trace.NewAggregate(errs...)
}

func (u *Users) fetchDatabaseUsers(ctx context.Context, database types.Database) (databaseUsers []*user, err error) {
	switch {
	case database.IsElastiCache():
		databaseUsers, err = fetchElastiCacheUsersForDatabase(ctx, database, u.cfg.Clients, u.cfg.Cache)

	default:
		return nil, nil
	}

	if err != nil {
		if trace.IsAccessDenied(err) { // Permission errors are expected.
			u.log.WithError(err).Debugf("No permissions to fetch users for %q.", database)
			return nil, nil
		}
	}
	return databaseUsers, nil
}

func findUserByName(users []*user, username string) (*user, bool) {
	for _, user := range users {
		if user.GetDatabaseUserName() == username {
			return user, true
		}
	}
	return nil, false
}

func findRemovedUsers(oldMap, newMap usersMap) (removed []*user) {
	for database, oldDatabaseUsers := range oldMap {
		newDatabaseUsers, databaseFoundInNew := newMap[database]

		if !databaseFoundInNew {
			removed = append(removed, oldDatabaseUsers...)
			continue
		}

		for _, oldDatabaseUser := range oldDatabaseUsers {
			_, userFoundInNew := findUserByName(newDatabaseUsers, oldDatabaseUser.GetDatabaseUserName())
			if !userFoundInNew {
				removed = append(removed, oldDatabaseUser)
			}
		}
	}
	return removed
}

type cacheKeyType string

const (
	cacheKeyUsers cacheKeyType = "users"
	cacheKeyTags  cacheKeyType = "tags"
)

func cacheKey(keyType cacheKeyType, data ...string) string {
	return path.Join(append([]string{string(keyType)}, data...)...)
}
