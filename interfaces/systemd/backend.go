// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2016 Canonical Ltd
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 3 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

// Package systemd implements integration between snappy interfaces and
// arbitrary systemd units that may be required for "oneshot" style tasks.
package systemd

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/snapcore/snapd/dirs"
	"github.com/snapcore/snapd/interfaces"
	"github.com/snapcore/snapd/logger"
	"github.com/snapcore/snapd/osutil"
	"github.com/snapcore/snapd/snap"
	sysd "github.com/snapcore/snapd/systemd"
)

// FIXME: This backend unmarshals snippets as JSON. This is a hack that needs to be fixed
// by making the interface methods get a typed backend object to talk to instead.

// Backend is responsible for maintaining apparmor profiles for ubuntu-core-launcher.
type Backend struct{}

// Name returns the name of the backend.
func (b *Backend) Name() string {
	return "systemd"
}

func (b *Backend) Setup(snapInfo *snap.Info, devMode bool, repo *interfaces.Repository) error {
	snapName := snapInfo.Name()
	rawSnippets, err := repo.SecuritySnippetsForSnap(snapInfo.Name(), interfaces.SecuritySystemd)
	if err != nil {
		return fmt.Errorf("cannot obtain systemd security snippets for snap %q: %s", snapName, err)
	}
	snippets, err := unmarshalRawSnippetMap(rawSnippets)
	if err != nil {
		return fmt.Errorf("cannot unmarshal systemd snippets for snap %q: %s", snapName, err)
	}
	snippet, err := mergeSnippetMap(snippets)
	if err != nil {
		return fmt.Errorf("cannot merge systemd snippets for snap %q: %s", snapName, err)
	}
	content, err := renderSnippet(snippet)
	if err != nil {
		return fmt.Errorf("cannot render systemd snippets for snap %q: %s", snapName, err)
	}
	dir := dirs.SnapServicesDir
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("cannot create directory for systemd services %q: %s", dir, err)
	}
	glob := interfaces.InterfaceServiceName(snapName, "*")
	changed, removed, errEnsure := osutil.EnsureDirState(dir, glob, content)
	systemd := sysd.New(dirs.GlobalRootDir, &dummyReporter{})
	// Reload systemd whenever something is added or removed
	if len(changed) > 0 || len(removed) > 0 {
		err := systemd.DaemonReload()
		if err != nil {
			logger.Noticef("cannot reload systemd state: %s", err)
		}
	}
	// Start any new services
	for _, service := range changed {
		err := systemd.Start(service)
		if err != nil {
			logger.Noticef("cannot start service %q: %s", service, err)
		}
	}
	// Stop any removed services
	for _, service := range removed {
		err := systemd.Stop(service, 10*time.Second)
		if err != nil {
			logger.Noticef("cannot stop service %q: %s", service, err)
		}
	}
	return errEnsure
}

func (b *Backend) Remove(snapName string) error {
	systemd := sysd.New(dirs.GlobalRootDir, &dummyReporter{})
	// Remove all the files matching snap glob
	glob := interfaces.InterfaceServiceName(snapName, "*")
	_, removed, errEnsure := osutil.EnsureDirState(dirs.SnapServicesDir, glob, nil)
	for _, service := range removed {
		err := systemd.Stop(service, 10*time.Second)
		if err != nil {
			logger.Noticef("cannot stop service %q: %s", service, err)
		}
	}
	// Reload systemd whenever something is removed
	if len(removed) > 0 {
		err := systemd.DaemonReload()
		if err != nil {
			logger.Noticef("cannot reload systemd state: %s", err)
		}
	}
	return errEnsure
}

func unmarshalRawSnippetMap(rawSnippetMap map[string][][]byte) (map[string][]*Snippet, error) {
	richSnippetMap := make(map[string][]*Snippet)
	for tag, rawSnippets := range rawSnippetMap {
		for _, rawSnippet := range rawSnippets {
			richSnippet := &Snippet{}
			err := json.Unmarshal(rawSnippet, &richSnippet)
			if err != nil {
				return nil, err
			}
			richSnippetMap[tag] = append(richSnippetMap[tag], richSnippet)
		}
	}
	return richSnippetMap, nil
}

// Flatten, deduplicate and check for conflicts in the services in the given snippet map
func mergeSnippetMap(snippetMap map[string][]*Snippet) (*Snippet, error) {
	services := make(map[string]Service)
	for _, snippets := range snippetMap {
		for _, snippet := range snippets {
			for name, service := range snippet.Services {
				if old, present := services[name]; present {
					if old != service {
						return nil, fmt.Errorf("interface require conflicting system needs")
					}
				} else {
					services[name] = service
				}
			}
		}
	}
	return &Snippet{Services: services}, nil
}

func renderSnippet(snippet *Snippet) (map[string]*osutil.FileState, error) {
	content := make(map[string]*osutil.FileState)
	for name, service := range snippet.Services {
		content[name] = &osutil.FileState{
			Content: []byte(service.String()),
			Mode:    0644,
		}
	}
	return content, nil
}

type dummyReporter struct{}

func (dr *dummyReporter) Notify(msg string) {
}
