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

package builtin

import (
	"fmt"
	"bytes"

	"github.com/snapcore/snapd/interfaces"
)

var edsCommomConnectedPlugAppArmor = []byte(`
# DBus accesses
#include <abstractions/dbus-session-strict>

# Allow all access to eds service
dbus (receive, send)
    bus=session
    peer=(label=###SLOT_SECURITY_TAGS###),

dbus (send)
     bus=session
     path=/org/freedesktop/DBus
     interface=org.freedesktop.DBus
     member={Request,Release}Name
     peer=(name=org.freedesktop.DBus),
dbus (send)
     bus=session
     path=/org/freedesktop/*
     interface=org.freedesktop.DBus.Properties
     peer=(label=unconfined),

# Evolution calendar interface
dbus (receive, send)
     bus=session
     path=/org/gnome/evolution/dataserver/SourceManager{,/**}
     peer=(label=unconfined),
`)

var edsCalendarConnectedPlugAppArmor = []byte(`
# Description: Can access the calendar. This policy group is reserved for
#  vetted applications only in this version of the policy. Once LP: #1227824
#  is fixed, this can be moved out of reserved status.
# Usage: reserved

dbus (receive, send)
     bus=session
     path=/org/gnome/evolution/dataserver/CalendarFactory
     peer=(label=unconfined),
dbus (receive, send)
     bus=session
     path=/org/gnome/evolution/dataserver/Subprocess/**
     peer=(label=unconfined),
dbus (receive, send)
     bus=session
     path=/org/gnome/evolution/dataserver/CalendarView/**
     peer=(label=unconfined),
`)

var edsContactsConnectedPlugAppArmor = []byte(`
# Description: Can access contacts. This policy group is reserved for vetted
#  applications only in this version of the policy. Once LP: #1227821 is
#  fixed, this can be moved out of reserved status.
# Usage: reserved

dbus (receive, send)
     bus=session
     path=/org/gnome/evolution/dataserver/AddressBookFactory
     peer=(label=unconfined),
dbus (receive, send)
     bus=session
     path=/org/gnome/evolution/dataserver/Subprocess/**
     peer=(label=unconfined),
dbus (receive, send)
     bus=session
     path=/org/gnome/evolution/dataserver/AddressBookView/**
     peer=(label=unconfined),
`)

var edsConnectedPlugSecComp = []byte(`
# Description: Can access the calendar. This policy group is reserved for
#  vetted applications only in this version of the policy. Once LP: #1227824
#  is fixed, this can be moved out of reserved status.
# Usage: reserved

# Can communicate with DBus system service
accept
accept4
bind
connect
getpeername
getsockname
getsockopt
listen
recv
recvfrom
recvmmsg
recvmsg
send
sendmmsg
sendmsg
sendto
setsockopt
shutdown
socketpair
socket
`)

var edsServices = []string {"calendar", "contact"}

type EDSInterface struct{}

func (iface *EDSInterface) Name() string {
	return "eds"
}

func (iface *EDSInterface) PermanentPlugSnippet(plug *interfaces.Plug, securitySystem interfaces.SecuritySystem) ([]byte, error) {
	switch securitySystem {
	case interfaces.SecurityDBus, interfaces.SecurityAppArmor, interfaces.SecuritySecComp, interfaces.SecurityUDev, interfaces.SecurityMount:
		return nil, nil
	default:
		return nil, interfaces.ErrUnknownSecurity
	}
}

func (iface *EDSInterface) ConnectedPlugSnippetByService(plug *interfaces.Plug) []byte {
	if service, ok := plug.Attrs["service"].(string); ok {
		if service == "calendar" {
			return append(edsCommomConnectedPlugAppArmor, edsCalendarConnectedPlugAppArmor...)
		} else if service == "contact" {
			return append(edsCommomConnectedPlugAppArmor, edsContactsConnectedPlugAppArmor...)
		}
	}
	panic("slot is not sanitized")
}

func (iface *EDSInterface) ConnectedPlugSnippet(plug *interfaces.Plug, slot *interfaces.Slot, securitySystem interfaces.SecuritySystem) ([]byte, error) {
	switch securitySystem {
	case interfaces.SecurityAppArmor:
		old := []byte("###SLOT_SECURITY_TAGS###")
		new := slotAppLabelExpr(slot)
		snippet := iface.ConnectedPlugSnippetByService(plug)
		snippet = bytes.Replace(snippet, old, new, -1)
		return snippet, nil
	case interfaces.SecuritySecComp:
		return edsConnectedPlugSecComp, nil
	case interfaces.SecurityUDev, interfaces.SecurityMount, interfaces.SecurityDBus:
		return nil, nil
	default:
		return nil, interfaces.ErrUnknownSecurity
	}
}

func (iface *EDSInterface) PermanentSlotSnippet(slot *interfaces.Slot, securitySystem interfaces.SecuritySystem) ([]byte, error) {
	switch securitySystem {
	case interfaces.SecurityDBus, interfaces.SecurityAppArmor, interfaces.SecuritySecComp, interfaces.SecurityUDev, interfaces.SecurityMount:
		return nil, nil
	default:
		return nil, interfaces.ErrUnknownSecurity
	}
}

func (iface *EDSInterface) ConnectedSlotSnippet(plug *interfaces.Plug, slot *interfaces.Slot, securitySystem interfaces.SecuritySystem) ([]byte, error) {
	switch securitySystem {
	case interfaces.SecurityDBus, interfaces.SecurityAppArmor, interfaces.SecuritySecComp, interfaces.SecurityUDev, interfaces.SecurityMount:
		return nil, nil
	default:
		return nil, interfaces.ErrUnknownSecurity
	}
}

func (iface *EDSInterface) SanitizePlug(plug *interfaces.Plug) error {
	if iface.Name() != plug.Interface {
		panic(fmt.Sprintf("plug is not of interface %q", iface))
	}

	service, ok := plug.Attrs["service"].(string)
	if !ok || service == "" {
		return fmt.Errorf("eds must contain the service attribute")
	}

	for _, edsService := range edsServices {
		if service == edsService {
            return nil
		}
	}

    return fmt.Errorf("valid values for service are: [calendar, contact]")
}

func (iface *EDSInterface) SanitizeSlot(slot *interfaces.Slot) error {
	return nil
}

func (iface *EDSInterface) AutoConnect() bool {
	return false
}
