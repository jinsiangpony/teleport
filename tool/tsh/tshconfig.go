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

package main

import (
	"errors"
	"io/fs"
	"os"

	"github.com/gravitational/trace"
	"gopkg.in/yaml.v2"
)

// .tsh config must go in a subdir as all .yaml files in .tsh get
// parsed automatically by the profile loader and results in yaml
// unmarshal errors.
const tshConfigPath = "config/config.yaml"

// TshConfig represents configuration loaded from the tsh config file.
type TshConfig struct {
	// ExtraHeaders are additional http headers to be included in
	// webclient requests.
	ExtraHeaders []ExtraProxyHeaders `yaml:"add_headers"`
	// ProxyTemplates describe rules for parsing out proxy out of full hostnames.
	ProxyTemplates []ProxyTemplate `yaml:"proxy_templates"`
}

// ExtraProxyHeaders represents the headers to include with the
// webclient.
type ExtraProxyHeaders struct {
	// Proxy is the domain of the proxy for these set of Headers, can contain globs.
	Proxy string `yaml:"proxy"`
	// Headers are the http header key values.
	Headers map[string]string `yaml:"headers,omitempty"`
}

// ProxyTemplate describes a single rule for parsing out proxy address from
// the full hostname. Used by tsh proxy ssh.
type ProxyTemplate struct {
	// Template is a regular expression that full hostname is matched against.
	Template string `yaml:"template"`
	// Proxy is the proxy address. Can refer to regex groups from the template.
	Proxy string `yaml:"proxy"`
	// Host is optional hostname. Can refer to regex groups from the template.
	Host string `yaml:"host"`
}

func loadConfig(fullConfigPath string) (*TshConfig, error) {
	bs, err := os.ReadFile(fullConfigPath)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return &TshConfig{}, nil
		}
		return nil, trace.ConvertSystemError(err)
	}

	cfg := TshConfig{}
	if err := yaml.Unmarshal(bs, &cfg); err != nil {
		return nil, trace.ConvertSystemError(err)
	}
	return &cfg, nil
}
