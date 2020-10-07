// Copyright (c) 2020 Private Internet Access, Inc.
//
// This file is part of the Private Internet Access Desktop Client.
//
// The Private Internet Access Desktop Client is free software: you can
// redistribute it and/or modify it under the terms of the GNU General Public
// License as published by the Free Software Foundation, either version 3 of
// the License, or (at your option) any later version.
//
// The Private Internet Access Desktop Client is distributed in the hope that
// it will be useful, but WITHOUT ANY WARRANTY; without even the implied
// warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with the Private Internet Access Desktop Client.  If not, see
// <https://www.gnu.org/licenses/>.

#ifndef DNSFLOWS_H
#define DNSFLOWS_H

#pragma warning(push)
#pragma warning(disable:4201)       // unnamed struct/union
#include <fwpsk.h>
#pragma warning(pop)

// Pool tag used by PIA's WFP callout
#define PIA_WFP_TAG 'xaip'

// Although WFP provides a "flow context" concept that can be used to attach
// driver-specific data to a data flow, it does not extend to the IP packet
// layers, since there are no "flows" at those layers.
//
// Consequently, to rewrite DNS packets in the IP packet layers based on the app
// ID available in higher layers only, we need to keep track of flow states
// manually.

// DnsFlow describes a DNS packet flow to a remote DNS server that is being
// rewritten.
//
// "Actual" fields refer to the flow as observed by the application (the DNS
// server it thought it sent the request to, the interface it used, etc.)
//
// "Intended" fields indicate where we really want the request to go and how we
// rewrite the packets.
typedef struct DnsFlow_T
{
    // Local IP - rewritten to force the request onto the physical or tunnel
    // interface
    UINT32 actualLocalIp, intendedLocalIp;
    // Remote IP - rewritten to force the request to a specific DNS server
    UINT32 actualRemoteIp, intendedRemoteIp;
    // Actual interface and subinterface indices - needed to reinject the
    // response after it is rewritten.  Intended interface/subinterface are not
    // needed.
    IF_INDEX actualInterfaceIdx, actualSubinterfaceIdx;
    // Local port - this is not changed, so actual/intended are the same.
    UINT16 localPort;
} DnsFlow;

// Set up and tear down the DnsFlow storage.
void DnsFlow_Init();
void DnsFlow_Teardown();

// Add a DnsFlow context entry for a new UDP DNS flow that was observed.
// Adds the entry if it does not exist, or updates the expiration time if it
// does.
//
// The caller sets everything other than the interface/subinterface indices.
// Those are not known yet; they're learned when an outbound packet is observed.
//
// If the entry is added, DnsFlow_Add() returns a nonzero token, which must be
// used to free the entry later with DnsFlow_Delete().  (The callout filters
// store this as a flow context.)
UINT64 DnsFlow_Add(const DnsFlow *pNewFlow);

// Check if an outbound DNS flow is present in the flow cache, without saving or
// returning anything.  This is used in the callout's ALE_AUTH_CONNECT layer to
// permit DNS flows that would normally be blocked but will be rewritten by the
// callout.
//
// The caller sets the 'actual' IPs and the local port.  The intended IPs and
// interface/subinterface indices are not used or set.
BOOL DnsFlow_Permit(const DnsFlow *pPermitFlow);

// For an outbound UDP DNS packet, check if this flow is known, and if so:
// - store the actual interface/subinterface indices
// - return the intended local/remote IPs to use to rewrite the packet
//
// The caller sets all 'actual' parameters and the local port.  If the flow is
// found, DnsFlow_FindOutbound() fills in the 'intended' IP addresses and
// returns TRUE.  Otherwise, it returns FALSE.
//
// This also updates the expiration time of the entry if it is found, since a
// packet is being sent.
BOOL DnsFlow_FindOutbound(DnsFlow *pOutboundFlow);

// For an inbound UDP DNS packet, check if this flow is known, and if so,
// return the actual IPs and interface/subinterface index to use to rewrite the
// inbound packet.
//
// The caller sets the 'intended' IPs and the local port.  If the flow is found,
// DnsFlow_FindInbound() filles in the 'actual' IP addresses and interface/
// subinterface indices, and returns TRUE.  Otherwise, it returns FALSE.
//
// This doesn't update the expiration time; inbound packets don't extend
// expiration since DNS only uses single packet requests/replies (no more
// replies are expected unless the app sends another request).
BOOL DnsFlow_FindInbound(DnsFlow *pInboundFlow);

// Delete a flow previously added with DnsFlow_Add().
void DnsFlow_Delete(UINT64 flowToken);

#endif
