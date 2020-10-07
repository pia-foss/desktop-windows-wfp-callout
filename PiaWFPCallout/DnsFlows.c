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

#include "DnsFlows.h"
#include <ntddk.h>

typedef struct DnsFlowEntry_T
{
    // Whether the entry is in use
    BOOL used;
    // The actual DnsFlow data for the entry
    DnsFlow flow;
} DnsFlowEntry;

// Spin lock used to guard the DnsFlowEntry storage.
KSPIN_LOCK dnsFlowCacheLock;

// As discussed in the header, we need to maintain state for DNS flow contexts
// in this cache.
//
// We need to be prepared to store a large number of flow contexts (they survive
// a relatively long time, and there could be a lot of requests in flight on a
// busy machine), but we also need to be able to prove that a flow isn't cached
// efficiently (such as when a new flow appears).  This code runs at
// DISPATCH_IRQL and most interrupts are blocked; doc recommends not to block
// for more than 25 microseconds or so.  (Additionally, there is a single shared
// lock around the flow cache.)
//
// The cache is implemented as a sort of associative cache based on local port.
// For a given local port, there are a total of 128 (=CacheWays) slots where
// that flow could be stored, starting at offset (port % CacheSize).  Ports are
// assigned randomly by the OS already so no hashing is applied to the port
// number.
//
// This is a relatively simple way to store a relatively large number of flows,
// with just a single cache buffer (allocated from nonpaged pool).  A tree or
// map structure would be more general, but would be much more complex, and
// likely would have poorer locality of reference.

enum
{
    // Number of flow entry cache windows (~= number of entries, although there
    // are an extra CacheWays-1 entries to fill out the final windows at the end
    // of the cache)
    DnsFlowEntryCacheWindows = 16384,
    // Length of an individual window - number of entries we could store a flow
    // for a given port in.
    DnsFlowEntryCacheWays = 128,
    // Actual size of the flow entry cache
    DnsFlowEntryCacheTotalSize = DnsFlowEntryCacheWindows + DnsFlowEntryCacheWays - 1,
    // Internally, a "flow token" returned by DnsFlow_Add is just an index into
    // the cache indicating the cache entry used for this flow.  Since 0
    // indicates failure, this flag is OR'd with the index to create a flow
    // token.
    DnsFlowTokenValidFlag = 0x80000000,
};

// Flow entry cache - allocated from nonpaged pool (must be NPP due to driver
// running at DISPATCH_LEVEL)
typedef struct DnsFlowEntryCache_T
{
    DnsFlowEntry entries[DnsFlowEntryCacheTotalSize];
} DnsFlowEntryCache;
DnsFlowEntryCache *pDnsFlowCache = NULL;

#define DEBUG_PRINT(...)  \
    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, \
              "PIA_DNSFLOW: " __VA_ARGS__))

void DnsFlow_Init()
{
    KeInitializeSpinLock(&dnsFlowCacheLock);
    pDnsFlowCache = ExAllocatePoolWithTag(NonPagedPool,
                                          sizeof(DnsFlowEntryCache),
                                          PIA_WFP_TAG);
    if(!pDnsFlowCache)
    {
        DEBUG_PRINT("Unable to allocate DNS flow cache");
    }
    else
    {
        RtlZeroMemory(pDnsFlowCache, sizeof(DnsFlowEntryCache));
    }
}

void DnsFlow_Teardown()
{
    if(pDnsFlowCache)
    {
        ExFreePoolWithTag(pDnsFlowCache, PIA_WFP_TAG);
        pDnsFlowCache = NULL;
    }

    // There's nothing to destroy for the spinlock.
}

typedef BOOL(*EntryMatchFunc)(const DnsFlowEntry *pCheck, const void *pCtx);

// Walk the cache to find an entry matching matchFunc with optional context
// pCtx.  The first matching entry is returned.
//
// If pRetIdx is valid, the index of the returned entry is stored there on a
// successful match.
//
// The caller must lock dnsFlowCacheLock.
static DnsFlowEntry *DnsFlow_FindEntry(UINT16 localPort,
                                       EntryMatchFunc matchFunc,
                                       unsigned *pRetIdx,
                                       const void *pCtx)
{
    if(pRetIdx)
        *pRetIdx = 0;

    if(!pDnsFlowCache)
        return NULL;

    unsigned startIndex = localPort % DnsFlowEntryCacheWindows;
    unsigned endIndex = startIndex + DnsFlowEntryCacheWays - 1;
    for(unsigned i=startIndex; i<endIndex; ++i)
    {
        if(matchFunc(&(pDnsFlowCache->entries[i]), pCtx))
        {
            if(pRetIdx)
                *pRetIdx = i;
            return &(pDnsFlowCache->entries[i]);
        }
    }

    return NULL;
}

// Check if a flow entry is not in use
static BOOL DnsFlow_IsEntryFree(const DnsFlowEntry *pEntry)
{
    return pEntry && !pEntry->used;
}

// Wrapper for DnsFlow_IsEntryFree() that takes an unused pCtx parameter for use
// with DnsFlow_FindEntry().
static BOOL DnsFlow_MatchFree(const DnsFlowEntry *pEntry,
                              const void *pCtx)
{
    UNREFERENCED_PARAMETER(pCtx);
    return DnsFlow_IsEntryFree(pEntry);
}

// Match a new flow being added by DnsFlow_Add().
static BOOL DnsFlow_MatchNew(const DnsFlowEntry *pCheck,
                             const void *pCtx)
{
    const DnsFlow *pCtxFlow = pCtx;
    // Look for an in-use (not free) entry that matches the specified entry.
    // The specified entry knows everything except the interface/subinterface
    // indices.
    return pCheck && pCtxFlow &&
        !DnsFlow_IsEntryFree(pCheck) &&
        pCheck->flow.actualLocalIp == pCtxFlow->actualLocalIp &&
        pCheck->flow.intendedLocalIp == pCtxFlow->intendedLocalIp &&
        pCheck->flow.actualRemoteIp == pCtxFlow->actualRemoteIp &&
        pCheck->flow.intendedRemoteIp == pCtxFlow->intendedRemoteIp &&
        pCheck->flow.localPort == pCtxFlow->localPort;
}

// Match an outbound flow in DnsFlow_FindOutbound().  Checks the port and actual
// IPs.
static BOOL DnsFlow_MatchOutbound(const DnsFlowEntry *pCheck,
                                  const void *pCtx)
{
    const DnsFlow *pCtxFlow = pCtx;
    // Look for an in-use (not free) entry that matches the specified entry.
    return pCheck && pCtxFlow &&
        !DnsFlow_IsEntryFree(pCheck) &&
        pCheck->flow.actualLocalIp == pCtxFlow->actualLocalIp &&
        pCheck->flow.actualRemoteIp == pCtxFlow->actualRemoteIp &&
        pCheck->flow.localPort == pCtxFlow->localPort;
}

// Match an inbound flow in DnsFlow_FindInbound().  Checks the port and intended
// IPs.
static BOOL DnsFlow_MatchInbound(const DnsFlowEntry *pCheck,
                                 const void *pCtx)
{
    const DnsFlow *pCtxFlow = pCtx;
    // Look for an in-use (not free) entry that matches the specified entry.
    return pCheck && pCtxFlow &&
        !DnsFlow_IsEntryFree(pCheck) &&
        pCheck->flow.intendedLocalIp == pCtxFlow->intendedLocalIp &&
        pCheck->flow.intendedRemoteIp == pCtxFlow->intendedRemoteIp &&
        pCheck->flow.localPort == pCtxFlow->localPort;
}

UINT64 DnsFlow_Add(const DnsFlow *pNewFlow)
{
    if(!pNewFlow)
        return 0;

    KLOCK_QUEUE_HANDLE lock;
    KeAcquireInStackQueuedSpinLockAtDpcLevel(&dnsFlowCacheLock, &lock);

    // Check if there's an entry that matches this one
    unsigned flowToken = 0;
    DnsFlowEntry *pMatch = DnsFlow_FindEntry(pNewFlow->localPort,
                                             &DnsFlow_MatchNew, &flowToken,
                                             pNewFlow);

    // If not, find an empty entry and fill it.
    if(!pMatch)
    {
        pMatch = DnsFlow_FindEntry(pNewFlow->localPort, &DnsFlow_MatchFree,
                                   &flowToken, NULL);
        // If this failed, there are no free entries, we won't be able to track
        // this flow.
        if(pMatch)
        {
            // Fill the new entry
            pMatch->flow = *pNewFlow;
            DEBUG_PRINT("(a): added DNS flow %08X:%d -> %08X with rewrite to %08X -> %08X",
                        pMatch->flow.actualLocalIp, pMatch->flow.localPort,
                        pMatch->flow.actualRemoteIp, pMatch->flow.intendedLocalIp,
                        pMatch->flow.intendedRemoteIp);
        }
        else
        {
            DEBUG_PRINT("(a): no free DNS flow entries, cannot track flow %08X:%d -> %08X with rewrite to %08X -> %08X",
                        pNewFlow->actualLocalIp, pNewFlow->localPort,
                        pNewFlow->actualRemoteIp, pNewFlow->intendedLocalIp,
                        pNewFlow->intendedRemoteIp);
        }
    }
    else
    {
        DEBUG_PRINT("(a): updated DNS flow %08X:%d -> %08X with rewrite to %08X -> %08X",
                    pMatch->flow.actualLocalIp, pMatch->flow.localPort,
                    pMatch->flow.actualRemoteIp, pMatch->flow.intendedLocalIp,
                    pMatch->flow.intendedRemoteIp);
    }

    // If we either found or created an entry, mark it as used, in case it
    // wasn't before.
    // pMatch is only NULL at this point if we didn't find a matching entry and
    // the cache is full.
    if(pMatch)
    {
        pMatch->used = TRUE;
        // Flow token is valid
        flowToken |= DnsFlowTokenValidFlag;
    }
    else
        flowToken = 0;

    KeReleaseInStackQueuedSpinLockFromDpcLevel(&lock);

    // Return the release token - the index of the used cache entry, if the
    // flow was added
    return flowToken;
}

BOOL DnsFlow_Permit(const DnsFlow *pPermitFlow)
{
    if(!pPermitFlow)
        return FALSE;

    KLOCK_QUEUE_HANDLE lock;
    KeAcquireInStackQueuedSpinLockAtDpcLevel(&dnsFlowCacheLock, &lock);

    // Check if there's an entry that matches this one
    DnsFlowEntry *pMatch = DnsFlow_FindEntry(pPermitFlow->localPort,
                                             &DnsFlow_MatchOutbound, NULL,
                                             pPermitFlow);

    KeReleaseInStackQueuedSpinLockFromDpcLevel(&lock);

    // Just indicate whether we found such a flow.  As in DnsFlow_FindOutbound(),
    // we can't dereference pMatch at this point, but we can check whether it's
    // valid.
    return !!pMatch;
}

BOOL DnsFlow_FindOutbound(DnsFlow *pOutboundFlow)
{
    if(!pOutboundFlow)
        return FALSE;

    KLOCK_QUEUE_HANDLE lock;
    KeAcquireInStackQueuedSpinLockAtDpcLevel(&dnsFlowCacheLock, &lock);

    // Check if there's an entry that matches this one
    DnsFlowEntry *pMatch = DnsFlow_FindEntry(pOutboundFlow->localPort,
                                             &DnsFlow_MatchOutbound, NULL,
                                             pOutboundFlow);

    // If so, store the interface/subinterface indices, return the intended
    // addresses, and update the expiration time
    if(pMatch)
    {
        pMatch->flow.actualInterfaceIdx = pOutboundFlow->actualInterfaceIdx;
        pMatch->flow.actualSubinterfaceIdx = pOutboundFlow->actualSubinterfaceIdx;
        pOutboundFlow->intendedLocalIp = pMatch->flow.intendedLocalIp;
        pOutboundFlow->intendedRemoteIp = pMatch->flow.intendedRemoteIp;

        DEBUG_PRINT("(o): found DNS flow %08X:%d -> %08X with rewrite to %08X -> %08X, storing interface %d/%d",
                    pMatch->flow.actualLocalIp, pMatch->flow.localPort,
                    pMatch->flow.actualRemoteIp, pMatch->flow.intendedLocalIp,
                    pMatch->flow.intendedRemoteIp, pMatch->flow.actualInterfaceIdx,
                    pMatch->flow.actualSubinterfaceIdx);
    }

    KeReleaseInStackQueuedSpinLockFromDpcLevel(&lock);

    // Although it's not safe to dereference pMatch at this point due to
    // releasing the spin lock, we can still test whether it was set for the
    // return value.
    return !!pMatch;
}

BOOL DnsFlow_FindInbound(DnsFlow *pInboundFlow)
{
    if(!pInboundFlow)
        return FALSE;

    KLOCK_QUEUE_HANDLE lock;
    KeAcquireInStackQueuedSpinLockAtDpcLevel(&dnsFlowCacheLock, &lock);

    // Check if there's an entry that matches this one
    DnsFlowEntry *pMatch = DnsFlow_FindEntry(pInboundFlow->localPort,
                                             &DnsFlow_MatchInbound, NULL,
                                             pInboundFlow);

    // If so, return the actual IPs and interface/subinterface indices.
    if(pMatch)
    {
        pInboundFlow->actualLocalIp = pMatch->flow.actualLocalIp;
        pInboundFlow->actualRemoteIp = pMatch->flow.actualRemoteIp;
        pInboundFlow->actualInterfaceIdx = pMatch->flow.actualInterfaceIdx;
        pInboundFlow->actualSubinterfaceIdx = pMatch->flow.actualSubinterfaceIdx;
        // Don't need to extend expiration time as discussed with the
        // declaration of DnsFlow_FindInbound().

        DEBUG_PRINT("(i): found DNS flow %08X:%d -> %08X with rewrite to %08X -> %08X, returning interface %d/%d",
                    pMatch->flow.actualLocalIp, pMatch->flow.localPort,
                    pMatch->flow.actualRemoteIp, pMatch->flow.intendedLocalIp,
                    pMatch->flow.intendedRemoteIp, pMatch->flow.actualInterfaceIdx,
                    pMatch->flow.actualSubinterfaceIdx);
    }

    KeReleaseInStackQueuedSpinLockFromDpcLevel(&lock);

    // As in DnsFlow_FindOutbound(), we can still test pMatch at this point
    // even though we can't dereference it.
    return !!pMatch;
}

void DnsFlow_Delete(UINT64 flowToken)
{
    if(!flowToken)
        return;

    NT_ASSERT(flowToken & DnsFlowTokenValidFlag);
    flowToken &= (~DnsFlowTokenValidFlag);

    KLOCK_QUEUE_HANDLE lock;
    KeAcquireInStackQueuedSpinLockAtDpcLevel(&dnsFlowCacheLock, &lock);

    if(flowToken >= DnsFlowEntryCacheTotalSize)
    {
        DEBUG_PRINT("(d): DNS flow token %X is not valid, exceeds cache size %d",
                    flowToken, DnsFlowEntryCacheTotalSize);
    }
    else if(pDnsFlowCache)
    {
        DnsFlowEntry *pEntry = &(pDnsFlowCache->entries[flowToken]);
        if(pEntry->used)
        {
            DEBUG_PRINT("(d): deleted DNS flow %08X:%d -> %08X with rewrite to %08X -> %08X, token %08X",
                        pEntry->flow.actualLocalIp, pEntry->flow.localPort,
                        pEntry->flow.actualRemoteIp, pEntry->flow.intendedLocalIp,
                        pEntry->flow.intendedRemoteIp, flowToken);
            pDnsFlowCache->entries[flowToken].used = FALSE;
        }
        else
        {
            DEBUG_PRINT("(d): DNS flow token %X was not in use", flowToken);
        }
    }

    KeReleaseInStackQueuedSpinLockFromDpcLevel(&lock);
}
