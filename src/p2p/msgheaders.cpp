#include "msgheaders.h"
#include "nodestats.h"
#include "validation.h"
#include "global.h"
#include "init.h"
#include "cnodestate.h"
#include "netmsgtypes.h"

/** Number of nodes with fSyncStarted. */
int nSyncStarted = 0;

/**
 * Sources of received blocks, saved to be able to send them reject
 * messages or ban them when processing happens afterwards. Protected by
 * cs_main.
 * Set mapBlockSource[hash].second to false if the node should not be
 * punished if the block is invalid.
 */
std::map<uint256, std::pair<NodeId, bool>> mapBlockSource;

std::map<uint256, std::pair<NodeId, std::list<QueuedBlock>::iterator> > mapBlocksInFlight;

/** Stack of nodes which we have set to announce using compact blocks */
std::list<NodeId> lNodesAnnouncingHeaderAndIDs;

/** Number of preferable block download peers. */
int nPreferredDownload = 0;

/** Number of peers from which we're downloading blocks. */
int nPeersWithValidatedDownloads = 0;

/** Convert CValidationState to a human-readable message for logging */
std::string FormatStateMessage(const CValidationState &state)
{
    return strprintf("%s%s (code %i)",
        state.GetRejectReason().c_str(),
        state.GetDebugMessage().empty() ? "" : (", " + state.GetDebugMessage()).c_str(),
        state.GetRejectCode());
}

bool ContextualCheckBlockHeader(const CBlockHeader& block, CValidationState& state, const CBlockIndex* pindexPrev, int64_t nAdjustedTime)
{
    assert(pindexPrev != NULL);
    // Check proof of work
    if (block.nBits != GetNextTargetRequired(pindexPrev, (pindexPrev->nHeight + 1) > 86400)) // 86400 is the PoW cutoff height
        return state.DoS(100, false, REJECT_INVALID, "bad-diffbits", false, "incorrect proof of work");

    // Check timestamp against prev
    if (block.GetBlockTime() <= pindexPrev->GetMedianTimePast())
        return state.Invalid(false, REJECT_INVALID, "time-too-old", "block's timestamp is too early");

    // Check timestamp
    if (block.GetBlockTime() > nAdjustedTime + nMaxClockDrift)
        return state.Invalid(false, REJECT_INVALID, "time-too-new", "block timestamp too far in the future");

    // Reject outdated version blocks when 95% (75% on testnet) of the network has upgraded:
    // check for version 2, 3 and 4 upgrades
    if(block.nVersion < 4)
            return state.Invalid(false, REJECT_OBSOLETE, strprintf("bad-version(0x%08x)", block.nVersion),
                                 strprintf("rejected nVersion=0x%08x block", block.nVersion));

    return true;
}
static bool CheckIndexAgainstCheckpoint(const CBlockIndex* pindexPrev, CValidationState& state, const uint256& hash)
{
    if (*pindexPrev->phashBlock == hashGenesisBlock)
        return true;

    int nHeight = pindexPrev->nHeight+1;
    // Don't accept any forks from the main chain prior to last checkpoint.
    // GetLastCheckpoint finds the last checkpoint in MapCheckpoints that's in our
    // MapBlockIndex.
    CBlockIndex* pcheckpoint = pcheckpointMain->GetLastCheckpoint(mapBlockIndex);
    if (pcheckpoint && nHeight < pcheckpoint->nHeight)
        return state.DoS(100, error("%s: forked chain older than last checkpoint (height %d)", __func__, nHeight), REJECT_CHECKPOINT, "bad-fork-prior-to-checkpoint");

    return true;
}
// Requires cs_main.
// Returns a bool indicating whether we requested this block.
// Also used if a block was /not/ received and timed out or started with another peer
bool MarkBlockAsReceived(const uint256& hash) {
    std::map<uint256, std::pair<NodeId, std::list<QueuedBlock>::iterator> >::iterator itInFlight = mapBlocksInFlight.find(hash);
    if (itInFlight != mapBlocksInFlight.end()) {
        CNodeState *state = State(itInFlight->second.first);
        state->nBlocksInFlightValidHeaders -= itInFlight->second.second->fValidatedHeaders;
        if (state->nBlocksInFlightValidHeaders == 0 && itInFlight->second.second->fValidatedHeaders) {
            // Last validated block on the queue was received.
            nPeersWithValidatedDownloads--;
        }
        if (state->vBlocksInFlight.begin() == itInFlight->second.second) {
            // First block on the queue was received, update the start download time for the next one
            state->nDownloadingSince = std::max(state->nDownloadingSince, GetTimeMicros());
        }
        state->vBlocksInFlight.erase(itInFlight->second.second);
        state->nBlocksInFlight--;
        state->nStallingSince = 0;
        mapBlocksInFlight.erase(itInFlight);
        return true;
    }
    return false;
}

bool CheckBlockHeader(const CBlockHeader& block, CValidationState& state, bool fCheckPOW = true)
{
    // Check proof of work matches claimed amount
    if (fCheckPOW && !CheckProofOfWork(block.GetHash(), block.nBits))
        return state.DoS(50, false, REJECT_INVALID, "high-hash", false, "proof of work failed");

    return true;
}

// Requires cs_main.
// returns false, still setting pit, if the block was already in flight from the same peer
// pit will only be valid as long as the same cs_main lock is being held
bool MarkBlockAsInFlight(NodeId nodeid, const uint256& hash, const CBlockIndex* pindex = NULL, std::list<QueuedBlock>::iterator** pit = NULL) {
    CNodeState *state = State(nodeid);
    assert(state != NULL);

    // Short-circuit most stuff in case its from the same node
    std::map<uint256, std::pair<NodeId, std::list<QueuedBlock>::iterator> >::iterator itInFlight = mapBlocksInFlight.find(hash);
    if (itInFlight != mapBlocksInFlight.end() && itInFlight->second.first == nodeid) {
        *pit = &itInFlight->second.second;
        return false;
    }

    // Make sure it's not listed somewhere already.
    MarkBlockAsReceived(hash);

    std::list<QueuedBlock>::iterator it = state->vBlocksInFlight.insert(state->vBlocksInFlight.end(), {hash, pindex, pindex != NULL});
    state->nBlocksInFlight++;
    state->nBlocksInFlightValidHeaders += it->fValidatedHeaders;
    if (state->nBlocksInFlight == 1) {
        // We're starting a block download (batch) from this peer.
        state->nDownloadingSince = GetTimeMicros();
    }
    if (state->nBlocksInFlightValidHeaders == 1 && pindex != NULL) {
        nPeersWithValidatedDownloads++;
    }
    itInFlight = mapBlocksInFlight.insert(std::make_pair(hash, std::make_pair(nodeid, it))).first;
    if (pit)
        *pit = &itInFlight->second.second;
    return true;
}

static bool AcceptBlockHeader(const CBlockHeader& blockHeader, CValidationState& state, CBlockIndex** ppindex)
{
    LOCK(cs_main);
    // Check for duplicate
    uint256 hash = blockHeader.GetHash();
    std::map<uint256, CBlockIndex*>::iterator miSelf = mapBlockIndex.find(hash);
    CBlockIndex *pindex = NULL;
    if (hash != hashGenesisBlock) {

        if (miSelf != mapBlockIndex.end()) {
            // Block header is already known.
            pindex = miSelf->second;
            if (ppindex)
                *ppindex = pindex;
            return true;
        }

        if (!CheckBlockHeader(blockHeader, state))
            return error("%s: Consensus::CheckBlockHeader: %s, %s", __func__, hash.ToString().c_str(), FormatStateMessage(state).c_str());

        // Get prev block index
        CBlockIndex* pindexPrev = NULL;
        std::map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(blockHeader.hashPrevBlock);
        if (mi == mapBlockIndex.end())
            return state.DoS(10, error("%s: prev block not found", __func__), 0, "prev-blk-not-found");
        pindexPrev = (*mi).second;

        assert(pindexPrev);
        if (!CheckIndexAgainstCheckpoint(pindexPrev, state, hash))
            return error("%s: CheckIndexAgainstCheckpoint(): %s", __func__, state.GetRejectReason().c_str());

        if (!ContextualCheckBlockHeader(blockHeader, state, pindexPrev, GetAdjustedTime()))
            return error("%s: Consensus::ContextualCheckBlockHeader: %s, %s", __func__, hash.ToString().c_str(), FormatStateMessage(state).c_str());
    }
    if (pindex == NULL)
    {
    //    pindex = blockHeader.AddHeaderToBlockIndex();
    }

    if (ppindex)
        *ppindex = pindex;

    return true;
}

// Exposed wrapper for AcceptBlockHeader
bool ProcessNewBlockHeaders(const std::vector<CBlockHeader>& headers, CValidationState& state, const CBlockIndex** ppindex)
{
    {
        LOCK(cs_main);
        for (const CBlockHeader& header : headers) {
            CBlockIndex *pindex = NULL; // Use a temp pindex instead of ppindex to avoid a const_cast
            if (!AcceptBlockHeader(header, state, &pindex)) {
                return false;
            }
            if (ppindex) {
                *ppindex = pindex;
            }
        }
    }
    return true;
}


/** Check whether the last unknown block a peer advertised is not yet known. */
void ProcessBlockAvailability(NodeId nodeid) {
    CNodeState *state = State(nodeid);
    assert(state != NULL);

    if (!state->hashLastUnknownBlock.IsNull()) {
        std::map<uint256, CBlockIndex*>::iterator itOld = mapBlockIndex.find(state->hashLastUnknownBlock);
        if (itOld != mapBlockIndex.end()) {
            if (state->pindexBestKnownBlock == NULL)
                state->pindexBestKnownBlock = itOld->second;
            state->hashLastUnknownBlock.SetNull();
        }
    }
}

/** Update tracking information about which blocks a peer is assumed to have. */
void UpdateBlockAvailability(NodeId nodeid, const uint256 &hash) {
    CNodeState *state = State(nodeid);
    assert(state != NULL);

    ProcessBlockAvailability(nodeid);

    std::map<uint256, CBlockIndex*>::iterator it = mapBlockIndex.find(hash);
    if (it != mapBlockIndex.end()) {
        // An actually better block was announced.
        if (state->pindexBestKnownBlock == NULL)
            state->pindexBestKnownBlock = it->second;
    } else {
        // An unknown block was announced; just assume that the latest one is the best one.
        state->hashLastUnknownBlock = hash;
    }
}

bool processGetHeaders(CNode* pfrom, CDataStream& vRecv)
{
    CBlockLocator locator;
    uint256 hashStop;
    vRecv >> locator >> hashStop;

    LOCK(cs_main);
    if (IsInitialBlockDownload()) {
        LogPrintf("Ignoring getheaders from peer=%d because node is in initial block download\n", pfrom->id);
        return true;
    }

    CNodeState *nodestate = State(pfrom->GetId());
    const CBlockIndex* pindex = NULL;
    if (locator.IsNull())
    {
        // If locator is null, return the hashStop block
        std::map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(hashStop);
        if (mi == mapBlockIndex.end())
            return true;
        pindex = (*mi).second;
    }
    else
    {
        // Find the last block the caller has in the main chain
        CBlockIndex* pindex = locator.GetBlockIndex();
        if (pindex)
            pindex = pindex->pnext;
    }

    // we must use CBlocks, as CBlockHeaders won't include the 0x00 nTx count at the end
    std::vector<CBlock> vHeaders;
    int nLimit = MAX_HEADERS_RESULTS;
    LogPrintf("getheaders %d to %s from peer=%d\n", (pindex ? pindex->nHeight : -1), hashStop.IsNull() ? "end" : hashStop.ToString().c_str(), pfrom->id);
    for (; pindex; pindex = pindex->pnext)
    {
        vHeaders.push_back(pindex->GetBlockHeader());
        if (--nLimit <= 0 || pindex->GetBlockHash() == hashStop)
            break;
    }
    // pindex can be NULL either if we sent chainActive.Tip() OR
    // if our peer has chainActive.Tip() (and thus we are sending an empty
    // headers message). In both cases it's safe to update
    // pindexBestHeaderSent to be our tip.
    //
    // It is important that we simply reset the BestHeaderSent value here,
    // and not max(BestHeaderSent, newHeaderSent). We might have announced
    // the currently-being-connected tip using a compact block, which
    // resulted in the peer sending a headers request, which we respond to
    // without the new block. By resetting the BestHeaderSent, we ensure we
    // will re-announce the new block via headers (or compact blocks again)
    // in the SendMessages logic.
    nodestate->pindexBestHeaderSent = pindex ? pindex : pindexBest;
    pfrom->PushMessage(NetMsgType::HEADERS, vHeaders);
    return true;
}

bool processHeaders(CNode* pfrom, CDataStream& vRecv)
{
    std::vector<CBlockHeader> headers;

    // Bypass the normal CBlock deserialization, as we don't want to risk deserializing 2000 full blocks.
    unsigned int nCount = ReadCompactSize(vRecv);
    if (nCount > MAX_HEADERS_RESULTS)
    {
        LOCK(cs_main);
        pfrom->Misbehaving(20);
        return error("headers message size = %u", nCount);
    }
    headers.resize(nCount);
    for (unsigned int n = 0; n < nCount; n++)
    {
        vRecv >> headers[n];
        ReadCompactSize(vRecv); // ignore tx count; assume it is 0.
    }

    if (nCount == 0)
    {
        // Nothing interesting. Stop asking this peers for more headers.
        return true;
    }

    const CBlockIndex *pindexLast = NULL;
    {
        LOCK(cs_main);
        CNodeState *nodestate = State(pfrom->GetId());

        // If this looks like it could be a block announcement (nCount <
        // MAX_BLOCKS_TO_ANNOUNCE), use special logic for handling headers that
        // don't connect:
        // - Send a getheaders message in response to try to connect the chain.
        // - The peer can send up to MAX_UNCONNECTING_HEADERS in a row that
        //   don't connect before giving DoS points
        // - Once a headers message is received that is valid and does connect,
        //   nUnconnectingHeaders gets reset back to 0.
        if (mapBlockIndex.find(headers[0].hashPrevBlock) == mapBlockIndex.end() && nCount < MAX_BLOCKS_TO_ANNOUNCE) {
            nodestate->nUnconnectingHeaders++;
            pfrom->PushMessage(NetMsgType::GETHEADERS, CBlockLocator(pindexBestHeader), uint256());
            LogPrintf("received header %s: missing prev block %s, sending getheaders (%d) to end (peer=%d, nUnconnectingHeaders=%d)\n",
                    headers[0].GetHash().ToString().c_str(),
                    headers[0].hashPrevBlock.ToString().c_str(),
                    pindexBestHeader->nHeight,
                    pfrom->id, nodestate->nUnconnectingHeaders);
            // Set hashLastUnknownBlock for this peer, so that if we
            // eventually get the headers - even from a different peer -
            // we can use this peer to download.
            UpdateBlockAvailability(pfrom->GetId(), headers.back().GetHash());

            if (nodestate->nUnconnectingHeaders % MAX_UNCONNECTING_HEADERS == 0)
            {
                pfrom->Misbehaving(20);
            }
            return true;
        }

        uint256 hashLastBlock;
        for (const CBlockHeader& header : headers) {
            if (!hashLastBlock.IsNull() && header.hashPrevBlock != hashLastBlock)
            {
                pfrom->Misbehaving(20);
                return error("non-continuous headers sequence");
            }
            hashLastBlock = header.GetHash();
        }
    }

    CValidationState state;
    if (!ProcessNewBlockHeaders(headers, state, &pindexLast))
    {
        int nDoS;
        if (state.IsInvalid(nDoS)) {
            if (nDoS > 0) {
                LOCK(cs_main);
                pfrom->Misbehaving(nDoS);
            }
            return error("invalid header received");
        }
    }

    {
        LOCK(cs_main);
        CNodeState *nodestate = State(pfrom->GetId());
        if (nodestate->nUnconnectingHeaders > 0) {
            LogPrintf("peer=%d: resetting nUnconnectingHeaders (%d -> 0)\n", pfrom->id, nodestate->nUnconnectingHeaders);
        }
        nodestate->nUnconnectingHeaders = 0;

        assert(pindexLast);
        UpdateBlockAvailability(pfrom->GetId(), pindexLast->GetBlockHash());

        if (nCount == MAX_HEADERS_RESULTS)
        {
            // Headers message had its maximum size; the peer may have more headers.
            // TODO: optimize: if pindexLast is an ancestor of chainActive.Tip or pindexBestHeader, continue
            // from there instead.
            LogPrintf("more getheaders (%d) to end to peer=%d (startheight:%d)\n", pindexLast->nHeight, pfrom->id, pfrom->nStartingHeight);
            pfrom->PushMessage(NetMsgType::GETHEADERS, CBlockLocator(pindexLast), uint256());
        }
        std::vector<const CBlockIndex*> vToFetch;
        const CBlockIndex *pindexWalk = pindexLast;
        // Calculate all the blocks we'd need to switch to pindexLast, up to a limit.
        while (pindexWalk && mapBlockIndex.count(pindexWalk->GetBlockHash()) && vToFetch.size() <= MAX_BLOCKS_IN_TRANSIT_PER_PEER)
        {
            if (!mapBlocksInFlight.count(pindexWalk->GetBlockHash()) && State(pfrom->GetId())->fHaveWitness)
            {
                // We don't have this block, and it's not yet in flight.
                vToFetch.push_back(pindexWalk);
            }
            pindexWalk = pindexWalk->pprev;
        }
        // If pindexWalk still isn't on our main chain, we're looking at a
        // very large reorg at a time we think we're close to caught up to
        // the main chain -- this shouldn't really happen.  Bail out on the
        // direct fetch and rely on parallel download instead.
        if (!mapBlockIndex.count(pindexWalk->GetBlockHash()))
        {
            LogPrintf("Large reorg, won't direct fetch to %s (%d)\n", pindexLast->GetBlockHash().ToString().c_str(), pindexLast->nHeight);
        } else
        {
            std::vector<CInv> vGetData;
            // Download as much as possible, from earliest to latest.
            BOOST_REVERSE_FOREACH(const CBlockIndex *pindex, vToFetch)
            {
                if (nodestate->nBlocksInFlight >= MAX_BLOCKS_IN_TRANSIT_PER_PEER)
                {
                    // Can't download any more from this peer
                    break;
                }
                vGetData.push_back(CInv(MSG_BLOCK, pindex->GetBlockHash()));
                MarkBlockAsInFlight(pfrom->GetId(), pindex->GetBlockHash(), pindex);
                LogPrintf("Requesting block %s from  peer=%d\n", pindex->GetBlockHash().ToString().c_str(), pfrom->id);
            }
            if (vGetData.size() > 1)
            {
                LogPrintf("Downloading blocks toward %s (%d) via headers direct fetch\n", pindexLast->GetBlockHash().ToString().c_str(), pindexLast->nHeight);
            }
            if (vGetData.size() > 0)
            {
                pfrom->PushMessage(NetMsgType::GETDATA, vGetData);
            }
        }
    }
    return true;
}
