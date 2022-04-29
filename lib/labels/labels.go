/*
Copyright 2020 Gravitational, Inc.

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

// Package labels provides a way to get dynamic labels. Used by SSH, App,
// and Kubernetes servers.
package labels

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/teleport/lib/utils"
	"github.com/gravitational/trace"
	"github.com/sirupsen/logrus"
)

// DynamicConfig is the configuration for dynamic labels.
type DynamicConfig struct {
	// Labels is the list of dynamic labels to update.
	Labels services.CommandLabels

	// Log is a component logger.
	Log *logrus.Entry
}

// CheckAndSetDefaults makes sure valid values were passed in to create
// dynamic labels.
func (c *DynamicConfig) CheckAndSetDefaults() error {
	if c.Log == nil {
		c.Log = logrus.NewEntry(logrus.StandardLogger())
	}

	// Loop over all labels and make sure the key name is valid and the interval
	// is valid as well. If the interval is not valid, update the value.
	labels := c.Labels.Clone()
	for name, label := range labels {
		if len(label.GetCommand()) == 0 {
			return trace.BadParameter("command missing")

		}
		if !types.IsValidLabelKey(name) {
			return trace.BadParameter("invalid label key: %q", name)
		}

		if label.GetPeriod() < time.Second {
			label.SetPeriod(time.Second)
			labels[name] = label
			c.Log.Warnf("Label period can't be less than 1 second. Period for label %q was set to 1 second.", name)
		}
	}
	c.Labels = labels

	return nil
}

// Dynamic allows defining a set of labels whose output is the result
// of some command execution. Dynamic labels can be configured to update
// periodically to provide updated information.
type Dynamic struct {
	mu sync.Mutex
	c  *DynamicConfig

	closeContext context.Context
	closeFunc    context.CancelFunc
}

// NewDynamic returns new Dynamic that can be configured to run
// asynchronously in a loop or synchronously.
func NewDynamic(ctx context.Context, config *DynamicConfig) (*Dynamic, error) {
	if err := config.CheckAndSetDefaults(); err != nil {
		return nil, trace.Wrap(err)
	}

	closeContext, closeFunc := context.WithCancel(ctx)

	return &Dynamic{
		c:            config,
		closeContext: closeContext,
		closeFunc:    closeFunc,
	}, nil
}

// Get returns the list of updated dynamic labels.
func (l *Dynamic) Get() map[string]types.CommandLabel {
	l.mu.Lock()
	defer l.mu.Unlock()

	out := make(map[string]types.CommandLabel, len(l.c.Labels))
	for name, label := range l.c.Labels {
		out[name] = label.Clone()
	}

	return out
}

// Sync will block and synchronously update dynamic labels. Used in tests.
func (l *Dynamic) Sync() {
	for name, label := range l.Get() {
		l.updateLabel(name, label)
	}
}

// Start will start a loop that continually keeps dynamic labels updated.
func (l *Dynamic) Start() {
	for name, label := range l.Get() {
		go l.periodicUpdateLabel(name, label)
	}
}

// Close will free up all resources and stop the keeping dynamic labels updated.
func (l *Dynamic) Close() {
	l.closeFunc()
}

// periodicUpdateLabel ticks at the update period defined for each label and
// updates its value.
func (l *Dynamic) periodicUpdateLabel(name string, label types.CommandLabel) {
	ticker := time.NewTicker(label.GetPeriod())
	defer ticker.Stop()

	for {
		l.updateLabel(name, label.Clone())
		select {
		case <-ticker.C:
		case <-l.closeContext.Done():
			return
		}
	}
}

// updateLabel will run a command, then update the value of a label.
func (l *Dynamic) updateLabel(name string, label types.CommandLabel) {
	out, err := exec.Command(label.GetCommand()[0], label.GetCommand()[1:]...).Output()
	if err != nil {
		l.c.Log.Errorf("Failed to run command and update label: %v.", err)
		label.SetResult(err.Error() + " output: " + string(out))
	} else {
		label.SetResult(strings.TrimSpace(string(out)))
	}

	// Perform the actual label update under a lock.
	l.setLabel(name, label)
}

// setLabel updates the value of a particular label under a lock.
func (l *Dynamic) setLabel(name string, value types.CommandLabel) {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.c.Labels[name] = value
}

type EC2LabelConfig struct {
	Client *utils.InstanceMetadataClient
	Log    *logrus.Entry
}

func (conf *EC2LabelConfig) checkAndSetDefaults() error {
	if conf.Client == nil {
		client, err := utils.NewInstanceMetadataClient(context.TODO())
		if err != nil {
			return trace.Wrap(err)
		}
		conf.Client = client
	}
	if conf.Log == nil {
		conf.Log = logrus.NewEntry(logrus.StandardLogger())
	}
	return nil
}

type EC2Labels struct {
	c      *EC2LabelConfig
	mu     sync.Mutex
	once   sync.Once
	labels map[string]string

	closeContext context.Context
	closeFunc    context.CancelFunc
}

func NewEC2Labels(ctx context.Context, c *EC2LabelConfig) (*EC2Labels, error) {
	if err := c.checkAndSetDefaults(); err != nil {
		return nil, trace.Wrap(err)
	}
	closeContext, closeFunc := context.WithCancel(ctx)

	return &EC2Labels{
		c:            c,
		labels:       make(map[string]string),
		closeContext: closeContext,
		closeFunc:    closeFunc,
	}, nil
}

// Get returns the list of updated EC2 labels.
func (l *EC2Labels) Get() map[string]string {
	l.mu.Lock()
	defer l.mu.Unlock()

	m := make(map[string]string)
	for k, v := range l.labels {
		m[fmt.Sprintf("%s/%s", types.AWSNamespace, k)] = v
	}

	return m
}

// Sync will block and synchronously update EC2 labels.
func (l *EC2Labels) Sync() {
	m := make(map[string]string)

	tags, err := l.c.Client.GetTagKeys()
	if err != nil {
		l.c.Log.Errorf("Error fetching EC2 tags: %v", err)
		return
	}

	for _, t := range tags {
		value, err := l.c.Client.GetTagValue(t)
		if err != nil {
			l.c.Log.Errorf("Error fetching EC2 tags: %v", err)
			return
		}
		m[t] = value
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	l.labels = m
}

// Start will start a loop that continually keeps EC2 labels updated.
func (l *EC2Labels) Start() {
	l.once.Do(func() { go l.periodicUpdateLabels() })
}

func (l *EC2Labels) periodicUpdateLabels() {
	ticker := time.NewTicker(types.EC2LabelUpdatePeriod)
	defer ticker.Stop()

	for {
		l.Sync()
		select {
		case <-ticker.C:
		case <-l.closeContext.Done():
			return
		}
	}
}

// Close will free up all resources and stop keeping EC2 labels updated.
func (l *EC2Labels) Close() {
	l.closeFunc()
}
