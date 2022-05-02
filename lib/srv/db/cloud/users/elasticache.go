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
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/aws/aws-sdk-go/service/elasticache"
	"github.com/aws/aws-sdk-go/service/elasticache/elasticacheiface"
	"github.com/gravitational/trace"
	"github.com/sirupsen/logrus"

	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/api/utils"
	libcloud "github.com/gravitational/teleport/lib/cloud"
	libaws "github.com/gravitational/teleport/lib/cloud/aws"
	"github.com/gravitational/teleport/lib/secrets"
	"github.com/gravitational/teleport/lib/srv/db/common"
	libutils "github.com/gravitational/teleport/lib/utils"
)

func newElastiCacheUser(ecUser *elasticache.User, client elasticacheiface.ElastiCacheAPI, secrets secrets.Secrets) (*user, error) {
	if ecUser == nil {
		return nil, trace.BadParameter("missing ElastiCache user")
	}
	if client == nil {
		return nil, trace.BadParameter("missing ElastiCache client")
	}

	// ElastiCache User ARN looks like this:
	// arn:aws:elasticache:<region>:<account-id>:user:<user-id>
	//
	// Make an unique secret key like this:
	// elasticache/<region>/<account-id>/user/<user-id>
	_, err := arn.Parse(aws.StringValue(ecUser.ARN))
	if err != nil {
		return nil, trace.Wrap(err)
	}
	secretKeyPath := strings.ReplaceAll(strings.TrimPrefix(aws.StringValue(ecUser.ARN), "arn:aws:"), ":", "/")

	return &user{
		secretKeyPath:               secretKeyPath,
		secrets:                     secrets,
		databaseUserName:            aws.StringValue(ecUser.UserName),
		usePreviousPasswordForLogin: true,
		modifyUserFunc:              modifyElastiCacheUserFunc(ecUser, client),
		maxPasswordLength:           128,
	}, nil
}

func modifyElastiCacheUserFunc(user *elasticache.User, client elasticacheiface.ElastiCacheAPI) func(context.Context, string, string) error {
	return func(ctx context.Context, oldPassword, newPassword string) error {
		input := &elasticache.ModifyUserInput{
			UserId: user.UserId,
		}
		if oldPassword != "" {
			input.Passwords = append(input.Passwords, aws.String(oldPassword))
		}
		if newPassword != "" {
			input.Passwords = append(input.Passwords, aws.String(newPassword))
		}
		input.SetNoPasswordRequired(len(input.Passwords) == 0)

		if _, err := client.ModifyUserWithContext(ctx, input); err != nil {
			return trace.Wrap(libaws.ConvertRequestFailureError(err))
		}
		return nil
	}
}

func fetchElastiCacheUsersForDatabase(ctx context.Context, database types.Database, clients common.CloudClients, cache *libutils.FnCache) ([]*user, error) {
	if !database.IsElastiCache() || len(database.GetAWS().ElastiCache.UserGroupIDs) == 0 {
		return nil, nil
	}

	client, err := clients.GetAWSElastiCacheClient(database.GetAWS().Region)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	secrets, err := secrets.New(secrets.Config{
		Region: database.GetAWS().Region,
	})
	if err != nil {
		return nil, trace.Wrap(err)
	}

	users := []*user{}
	for _, userGroupID := range database.GetAWS().ElastiCache.UserGroupIDs {
		managedUsers, err := getElastiCacheUsersForGroup(ctx, database.GetAWS().Region, userGroupID, client, cache)
		if err != nil {
			return nil, trace.Wrap(err)
		}

		for _, managedUser := range managedUsers {
			user, err := newElastiCacheUser(managedUser, client, secrets)
			if err != nil {
				return nil, trace.Wrap(err)
			}

			users = append(users, user)
		}
	}
	return users, nil
}

func getElastiCacheUsersForGroup(ctx context.Context, region, userGroupID string, client elasticacheiface.ElastiCacheAPI, cache *libutils.FnCache) ([]*elasticache.User, error) {
	allUsers, err := getElastiCacheUsersForRegion(ctx, region, client, cache)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	managedUsers := []*elasticache.User{}
	for _, user := range allUsers {
		// Match user group ID.
		if !utils.SliceContainsStr(aws.StringValueSlice(user.UserGroupIds), userGroupID) {
			continue
		}

		// Match special Teleport "managed" tag.
		userTags, err := getElastiCacheTagsForUser(ctx, region, user, client, cache)
		if err != nil {
			if trace.IsAccessDenied(err) {
				logrus.WithError(err).Debugf("No Permission to get tags for user %v", aws.StringValue(user.ARN))
			} else {
				logrus.WithError(err).Warnf("Failed to get tags for user %v", aws.StringValue(user.ARN))
			}
			continue
		}
		for _, tag := range userTags {
			if aws.StringValue(tag.Key) == libcloud.TagKeyTeleportManaged &&
				aws.StringValue(tag.Value) == libcloud.TagValueTrue {
				managedUsers = append(managedUsers, user)
				break
			}
		}
	}
	return managedUsers, nil
}

func getElastiCacheUsersForRegion(ctx context.Context, region string, client elasticacheiface.ElastiCacheAPI, cache *libutils.FnCache) ([]*elasticache.User, error) {
	usersInterface, err := cache.Get(ctx,
		cacheKey(cacheKeyUsers, region, types.DatabaseTypeElastiCache),
		func() (interface{}, error) {
			users := []*elasticache.User{}
			err := client.DescribeUsersPagesWithContext(ctx, &elasticache.DescribeUsersInput{}, func(output *elasticache.DescribeUsersOutput, _ bool) bool {
				users = append(users, output.Users...)
				return true
			})
			if err != nil {
				return nil, trace.Wrap(libaws.ConvertRequestFailureError(err))
			}
			return users, nil
		},
	)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	users, ok := usersInterface.([]*elasticache.User)
	if !ok {
		return nil, trace.BadParameter("failed to convert users")
	}
	return users, nil
}

func getElastiCacheTagsForUser(ctx context.Context, region string, user *elasticache.User, client elasticacheiface.ElastiCacheAPI, cache *libutils.FnCache) ([]*elasticache.Tag, error) {
	userTagsInterface, err := cache.Get(ctx,
		cacheKey(cacheKeyTags, aws.StringValue(user.ARN)),
		func() (interface{}, error) {
			output, err := client.ListTagsForResourceWithContext(ctx, &elasticache.ListTagsForResourceInput{
				ResourceName: user.ARN,
			})
			if err != nil {
				return nil, trace.Wrap(libaws.ConvertRequestFailureError(err))
			}
			return output.TagList, nil
		},
	)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	userTags, ok := userTagsInterface.([]*elasticache.Tag)
	if !ok {
		return nil, trace.BadParameter("failed to convert user tags")
	}
	return userTags, nil
}
