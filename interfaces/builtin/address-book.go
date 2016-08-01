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
	"bytes"

	"github.com/snapcore/snapd/interfaces"
)

var addressBookPermanentSlotAppArmor = []byte(`
# Description: Allow operating as the PIM service. Reserved because this
#  gives privileged access to the system.
# Usage: reserved

# DBus accesses
#include <abstractions/dbus-session-strict>
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

# Allow binding the service to the requested connection name
dbus (bind)
	bus=session
	name="com.canonical.pim",

# Allow traffic to/from our path and interface with any method
dbus (receive, send)
	bus=session
	path=/com/canonical/pim/AddressBook
	interface=com.canonical.pim.AddressBook,
dbus (receive, send)
	bus=session
	path=/com/canonical/pim/AddressBookView/**
	interface=com.canonical.pim.AddressBookView,

# Allow traffic to/from org.freedesktop.DBus for PIM service
dbus (receive, send)
	bus=session
	path=/
	interface=org.freedesktop.DBus.**,
dbus (receive, send)
	bus=session
	path=/com/canonical/pim/AddressBook
	interface=org.freedesktop.DBus.**,
dbus (receive, send)
	bus=session
	path=/com/canonical/pim/AddressBookView/**
	interface=org.freedesktop.DBus.**,
`)

var addressBookConnectedPlugAppArmor = []byte(`
# Description: Can access addressbook. This policy group is reserved for vetted
#  applications only in this version of the policy. Once LP: #1227821 is
#  fixed, this can be moved out of reserved status.
# Usage: reserved
#include <abstractions/dbus-session-strict>

# Allow all access to PIM service
dbus (receive, send)
	bus=session
	peer=(label=###SLOT_SECURITY_TAGS###),
dbus (receive, send)
	bus=session
	path=/com/canonical/pim/AddressBook
	peer=(label=unconfined),
dbus (receive, send)
	bus=session
	path=/com/canonical/pim/AddressBookView/**
	peer=(label=unconfined),
`)

var addressBookPermanentSlotSecComp = []byte(`
# Description: Allow operating as the PIM service. Reserved because this
# gives
#  privileged access to the system.
# Usage: reserved
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

var addressBookConnectedPlugSecComp = []byte(`
# Description: Allow using PIM service. Reserved because this gives
#  privileged access to the bluez service.
# Usage: reserved

# Can communicate with DBus system service
connect
getsockname
recv
recvmsg
send
sendto
sendmsg
socket
`)

var addressBookPermanentSlotDBus = []byte(`
<policy user="root">
    <allow own="com.canonical.pim"/>
    <allow send_destination="com.canonical.pim"/>

    <allow send_interface="com.canonical.pim.AddressBook"/>
    <allow send_interface="com.canonical.pim.AddressBookView"/>

    <allow send_interface="org.freedesktop.DBus.Properties"/>
    <allow send_interface="org.freedesktop.DBus.ObjectManager"/>
    <allow send_interface="org.freedesktop.DBus.Introspectable"/>
</policy>
<policy context="default">
    <deny send_destination="com.canonical.pim"/>
</policy>
`)


type AddressBookInterface struct{}

func (iface *AddressBookInterface) Name() string {
	return "address-book"
}

func (iface *AddressBookInterface) PermanentPlugSnippet(plug *interfaces.Plug, securitySystem interfaces.SecuritySystem) ([]byte, error) {
	switch securitySystem {
	case interfaces.SecurityDBus, interfaces.SecurityAppArmor, interfaces.SecuritySecComp, interfaces.SecurityUDev, interfaces.SecurityMount:
		return nil, nil
	default:
		return nil, interfaces.ErrUnknownSecurity
	}
}

func (iface *AddressBookInterface) ConnectedPlugSnippet(plug *interfaces.Plug, slot *interfaces.Slot, securitySystem interfaces.SecuritySystem) ([]byte, error) {
	switch securitySystem {
	case interfaces.SecurityAppArmor:
		old := []byte("###SLOT_SECURITY_TAGS###")
		new := slotAppLabelExpr(slot)
		snippet := bytes.Replace(addressBookConnectedPlugAppArmor, old, new, -1)
		return snippet, nil
	case interfaces.SecuritySecComp:
		return addressBookConnectedPlugSecComp, nil
	case interfaces.SecurityUDev, interfaces.SecurityMount, interfaces.SecurityDBus:
		return nil, nil
	default:
		return nil, interfaces.ErrUnknownSecurity
	}
}

func (iface *AddressBookInterface) PermanentSlotSnippet(slot *interfaces.Slot, securitySystem interfaces.SecuritySystem) ([]byte, error) {
	switch securitySystem {
	case interfaces.SecurityAppArmor:
		return addressBookPermanentSlotAppArmor, nil
	case interfaces.SecuritySecComp:
		return addressBookPermanentSlotSecComp, nil
	case interfaces.SecurityDBus:
		return addressBookPermanentSlotDBus, nil
	case interfaces.SecurityUDev, interfaces.SecurityMount:
		return nil, nil
	default:
		return nil, interfaces.ErrUnknownSecurity
	}
}

func (iface *AddressBookInterface) ConnectedSlotSnippet(plug *interfaces.Plug, slot *interfaces.Slot, securitySystem interfaces.SecuritySystem) ([]byte, error) {
	switch securitySystem {
	case interfaces.SecurityDBus, interfaces.SecurityAppArmor, interfaces.SecuritySecComp, interfaces.SecurityUDev, interfaces.SecurityMount:
		return nil, nil
	default:
		return nil, interfaces.ErrUnknownSecurity
	}
}

func (iface *AddressBookInterface) SanitizePlug(plug *interfaces.Plug) error {
	return nil
}

func (iface *AddressBookInterface) SanitizeSlot(slot *interfaces.Slot) error {
	return nil
}

func (iface *AddressBookInterface) AutoConnect() bool {
	return false
}
