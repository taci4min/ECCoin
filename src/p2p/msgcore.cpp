#include <boost/algorithm/string/replace.hpp>
#include <boost/random/mersenne_twister.hpp>
#include <boost/random/uniform_int_distribution.hpp>
#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>
#include <tuple>
#include <map>

#include "msgcore.h"
#include "msgprocessing.h"
#include "netmsgtypes.h"
#include "tx/mempool.h"
#include "validation.h"
#include "cnodestate.h"

#include "p2p/proxyutils.h"

using namespace std;
using namespace boost;



void PushNodeVersion(CNode *pnode, int64_t nTime)
{
    ServiceFlags nLocalNodeServices = nLocalServices;
    uint64_t nonce = RAND_bytes((unsigned char*)&nLocalHostNonce, sizeof(nLocalHostNonce));
    int nNodeStartingHeight = pnode->GetMyStartingHeight();
    NodeId nodeid = pnode->GetId();
    CAddress addr = pnode->addr;

    CAddress addrYou = (addr.IsRoutable() && !IsProxy(addr) ? addr : CAddress(CService(), addr.nServices));
    CAddress addrMe = CAddress(CService(), nLocalNodeServices);

    LOCK(pnode->cs_vSend);
    pnode->PushMessage(NetMsgType::VERSION, PROTOCOL_VERSION, (uint64_t)nLocalNodeServices, nTime, addrYou, addrMe,
            nonce, pnode->strSubVer, nNodeStartingHeight);

    LogPrintf("send version message: version %d, blocks=%d, us=%s, them=%s, peer=%d\n", PROTOCOL_VERSION, nNodeStartingHeight, addrMe.ToString().c_str(), addrYou.ToString().c_str(), nodeid);
}

// Is our peer's addrLocal potentially useful as an external IP source?
bool IsPeerAddrLocalGood(CNode *pnode)
{
    CService addrLocal = pnode->GetAddrLocal();
    return fDiscover && pnode->addr.IsRoutable() && addrLocal.IsRoutable() &&
           !IsLimited(addrLocal.GetNetwork());
}

/*
 * Code for processing the core set of messages
*/

bool processVersion(CNode* pfrom, CDataStream& vRecv)
{
    // Each connection can only send one version message
    if (pfrom->nVersion != 0)
    {
        pfrom->Misbehaving(1);
        return false;
    }

    int64_t nTime;
    CAddress addrMe;
    CAddress addrFrom;
    uint64_t nNonce = 1;
    uint64_t nServiceInt;
    ServiceFlags nServices;
    int nVersion;
    std::string strSubVer;
    std::string cleanSubVer;
    int nStartingHeight = -1;

    vRecv >> nVersion >> nServiceInt >> nTime >> addrMe;
    nServices = ServiceFlags(nServiceInt);
    /*
    if (!pfrom->fInbound)
    {
        addrman.SetServices(pfrom->addr, nServices);
    }
    if (pfrom->nServicesExpected & ~nServices)
    {
        LogPrintf("peer=%d does not offer the expected services (%08x offered, %08x expected); disconnecting\n", pfrom->id, nServices, pfrom->nServicesExpected);
        pfrom->fDisconnect = true;
        return false;
    }
    */

    if (nVersion < MIN_PROTO_VERSION)
    {
        LogPrintf("partner %s using obsolete version %i; disconnecting\n", pfrom->addr.ToString().c_str(), pfrom->nVersion);
        pfrom->fDisconnect = true;
        return false;
    }
    if (!vRecv.empty())
    {
        vRecv >> addrFrom >> nNonce;
    }
    if (!vRecv.empty())
    {
        vRecv >> strSubVer;
        //cleanSubVer = SanitizeString(strSubVer);
    }
    if (!vRecv.empty())
    {
        vRecv >> nStartingHeight;
    }

    if (pfrom->fInbound && addrMe.IsRoutable())
    {
        SeenLocal(addrMe);
    }

    // Disconnect if we connected to ourself
    if (nNonce == nLocalHostNonce && nNonce > 1)
    {
        LogPrintf("connected to self at %s, disconnecting\n", pfrom->addr.ToString().c_str());
        pfrom->fDisconnect = true;
        return true;
    }

    // record my external IP reported by peer
    if (addrFrom.IsRoutable() && addrMe.IsRoutable())
        addrSeenByPeer = addrMe;

    // Be shy and don't send version until we hear
    if (pfrom->fInbound)
        pfrom->PushVersion();

    pfrom->nServices = nServices;
    pfrom->SetAddrLocal(addrMe);
    {
        LOCK(pfrom->cs_SubVer);
        pfrom->strSubVer = strSubVer;
        pfrom->cleanSubVer = cleanSubVer;
    }
    pfrom->nStartingHeight = nStartingHeight;

    // Change version
    pfrom->PushMessage("verack");
    pfrom->vSend.SetVersion(min(pfrom->nVersion, PROTOCOL_VERSION));
    pfrom->nVersion = nVersion;

    if (!pfrom->fInbound)
    {
        // Advertise our address
        if (!fNoListen && !IsInitialBlockDownload())
        {
            CAddress addr = GetLocalAddress(&pfrom->addr); //function call might cause an issue
            if (addr.IsRoutable())
            {
                pfrom->PushAddress(addr);
            } else if (IsPeerAddrLocalGood(pfrom))
            {
                addr.SetIP(addrMe);
                LogPrintf("ProcessMessages: advertising address %s\n", addr.ToString().c_str());
                pfrom->PushAddress(addr);
            }

        }

        // Get recent addresses
        if (addrman.size() < 1000)
        {
            pfrom->PushMessage("getaddr");
            pfrom->fGetAddr = true;
        }
        addrman.Good(pfrom->addr);
    }
    else
    {
        ///depreacted else
        if (((CNetAddr)pfrom->addr) == (CNetAddr)addrFrom)
        {
            addrman.Add(addrFrom, addrFrom);
            addrman.Good(addrFrom);
        }
    }

    AddTimeData(pfrom->addr, nTime);

    // Ask a peer with more blocks than us for missing blocks
    if (pfrom->nStartingHeight > (pindexBest->nHeight - 144))
    {
        if(fDebugNet)
        {
            LogPrintf("peer has more blocks than us \n");
        }
        pfrom->PushGetBlocks(pindexBest, uint256(0));
        highestAskedFor = pindexBest->nHeight + 500;
    }
    else
    {
        if(fDebugNet)
            LogPrintf("peer does not have more blocks than us \n");
    }

    LogPrintf("receive version message: version %d, blocks=%d, us=%s, them=%s, peer=%s\n", pfrom->nVersion, pfrom->nStartingHeight, addrMe.ToString().c_str(), addrFrom.ToString().c_str(), pfrom->addr.ToString().c_str());

    cPeerBlockCounts.input(pfrom->nStartingHeight);

    LogPrintf("finished processing version message \n");

    // Update the last seen time for this node's address
    if (pfrom->fNetworkNode)
    {
        AddressCurrentlyConnected(pfrom->addr);
        pfrom->nLastSend = GetTime();
    }
    return true;
}


bool processVerack(CNode* pfrom, CDataStream& vRecv)
{
    pfrom->vRecv.SetVersion(min(pfrom->nVersion, PROTOCOL_VERSION));
    if (!pfrom->fInbound)
    {
        // Mark this node as currently connected, so we update its timestamp later.
        LOCK(cs_main);
        State(pfrom->GetId())->fCurrentlyConnected = true;
    }
    if (pfrom->nVersion >= SENDHEADERS_VERSION)
    {
        // Tell our peer we prefer to receive headers rather than inv's
        // We send this to non-NODE NETWORK peers as well, because even
        // non-NODE NETWORK peers can announce blocks (such as pruning
        // nodes)
        if(fDebugNet)
        {
            LogPrintf("sending message SendHeaders to peer \n");
        }
        pfrom->PushMessage(NetMsgType::SENDHEADERS);

    }
    pfrom->fSuccessfullyConnected = true;
    return true;
}


bool processAddr(CNode* pfrom, CDataStream& vRecv)
{
    vector<CAddress> vAddr;
    vRecv >> vAddr;

    // Don't want addr from older versions unless seeding
    if (addrman.size() > 1000)
        return true;
    if (vAddr.size() > 1000)
    {
        pfrom->Misbehaving(20);
        return error("message addr size() = %u", vAddr.size());
    }

    // Store the new addresses
    vector<CAddress> vAddrOk;
    int64_t nNow = GetAdjustedTime();
    int64_t nSince = nNow - 10 * 60;
    BOOST_FOREACH(CAddress& addr, vAddr)
    {
        if (fShutdown)
            return true;

        if (addr.nTime <= 100000000 || addr.nTime > nNow + 10 * 60)
            addr.nTime = nNow - 5 * 24 * 60 * 60;

        pfrom->AddAddressKnown(addr);
        bool fReachable = IsReachable(addr);
        if (addr.nTime > nSince && !pfrom->fGetAddr && vAddr.size() <= 10 && addr.IsRoutable())
        {
            // Relay to a limited number of other nodes
            {
                LOCK(cs_vNodes);
                // Use deterministic randomness to send to the same nodes for 24 hours
                // at a time so the setAddrKnowns of the chosen nodes prevent repeats
                static uint256 hashSalt;
                if (hashSalt == 0)
                    hashSalt = GetRandHash();
                uint64_t hashAddr = addr.GetHash();
                uint256 hashRand = hashSalt ^ (hashAddr<<32) ^ ((GetTime()+hashAddr)/(24*60*60));
                hashRand = Hash(BEGIN(hashRand), END(hashRand));
                multimap<uint256, CNode*> mapMix;
                BOOST_FOREACH(CNode* pnode, vNodes)
                {
                    unsigned int nPointer;
                    memcpy(&nPointer, &pnode, sizeof(nPointer));
                    uint256 hashKey = hashRand ^ nPointer;
                    hashKey = Hash(BEGIN(hashKey), END(hashKey));
                    mapMix.insert(make_pair(hashKey, pnode));
                }
                int nRelayNodes = fReachable ? 2 : 1; // limited relaying of addresses outside our network(s)
                for (multimap<uint256, CNode*>::iterator mi = mapMix.begin(); mi != mapMix.end() && nRelayNodes-- > 0; ++mi)
                    ((*mi).second)->PushAddress(addr);
            }
        }
        // Do not store addresses outside our network
        if (fReachable)
            vAddrOk.push_back(addr);
    }
    addrman.Add(vAddrOk, pfrom->addr, 2 * 60 * 60);
    if (vAddr.size() < 1000)
        pfrom->fGetAddr = false;

    // Update the last seen time for this node's address
    if (pfrom->fNetworkNode)
    {
        AddressCurrentlyConnected(pfrom->addr);
        pfrom->nLastSend = GetTime();
    }
    return true;
}

bool processInv(CNode* pfrom, CDataStream& vRecv)
{
    vector<CInv> vInv;
    vRecv >> vInv;
    if (vInv.size() > MAX_INV_SZ)
    {
        pfrom->Misbehaving(20);
        return error("message inv size() = %u", vInv.size());
    }

    // find last block in inv vector
    unsigned int nLastBlock = (unsigned int)(-1);
    for (unsigned int nInv = 0; nInv < vInv.size(); nInv++)
    {
        if (vInv[vInv.size() - 1 - nInv].type == MSG_BLOCK)
        {
            nLastBlock = vInv.size() - 1 - nInv;
            break;
        }
    }
    CTxDB txdb("r");
    for (unsigned int nInv = 0; nInv < vInv.size(); nInv++)
    {
        const CInv &inv = vInv[nInv];

        if (fShutdown)
            return true;
        pfrom->AddInventoryKnown(inv);

        bool fAlreadyHave = AlreadyHave(txdb, inv);
        if (fDebug)
            LogPrintf("  got inventory: %s  %s\n", inv.ToString().c_str(), fAlreadyHave ? "have" : "new");

        if (!fAlreadyHave)
            pfrom->AskFor(inv);
        else if (inv.type == MSG_BLOCK && mapOrphanBlocks.count(inv.hash)) {
            pfrom->PushGetBlocks(pindexBest, GetOrphanRoot(mapOrphanBlocks[inv.hash]));
        } else if (nInv == nLastBlock) {
            // In case we are on a very long side-chain, it is possible that we already have
            // the last block in an inv bundle sent in response to getblocks. Try to detect
            // this situation and push another getblocks to continue.
            pfrom->PushGetBlocks(mapBlockIndex[inv.hash], uint256(0));
            if (fDebug)
                LogPrintf("force request: %s\n", inv.ToString().c_str());
        }

        // Track requests for our stuff
        Inventory(inv.hash);
    }
    // Update the last seen time for this node's address
    if (pfrom->fNetworkNode)
    {
        AddressCurrentlyConnected(pfrom->addr);
        pfrom->nLastSend = GetTime();
    }
    return true;
}

bool processGetData(CNode* pfrom, CDataStream& vRecv)
/*
{
vector<CInv> vInv;
vRecv >> vInv;

if (vInv.size() > MAX_INV_SZ)
{
    LOCK(cs_main);
    pfrom->Misbehaving(20);
    return error("message getdata size() = %u", vInv.size());
}
if (vInv.size() > 0) {
    LogPrintf("received getdata for: %s peer=%d\n", vInv[0].ToString().c_str(), pfrom->id);
}


pfrom->vRecvGetData.insert(pfrom->vRecvGetData.end(), vInv.begin(), vInv.end());
//ProcessGetData(pfrom, chainparams.GetConsensus(), connman, interruptMsgProc);
    std::deque<CInv>::iterator it = pfrom->vRecvGetData.begin();

    vector<CInv> vNotFound;

    LOCK(cs_main);

    while (it != pfrom->vRecvGetData.end()) {
        // Don't bother if send buffer is too full to respond anyway
        //if (pfrom->nSendSize >= SendBufferSize())
        //    break;

        const CInv &inv = *it;
        {
            it++;

            if (inv.type == MSG_BLOCK)
            {
                // Send block from disk
                map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(inv.hash);
                if (mi != mapBlockIndex.end())
                {
                    CBlock block;
                    block.ReadFromDisk((*mi).second);
                    pfrom->PushMessage("block", block);

                    // Trigger them to send a getblocks request for the next batch of inventory
                    if (inv.hash == pfrom->hashContinue)
                    {
                        // Bypass PushInventory, this must send even if redundant,
                        // and we want it right after the last block so they don't
                        // wait for other stuff first.
                        vector<CInv> vInv;
                        vInv.push_back(CInv(MSG_BLOCK, pindexBest->GetBlockHash()));
                        pfrom->PushMessage("inv", vInv);
                        pfrom->hashContinue = 0;
                    }
                }
            }
            else if (inv.IsKnownType())
            {
                // Send stream from relay memory
                bool pushed = false;
                {
                    LOCK(cs_mapRelay);
                    map<CInv, CDataStream>::iterator mi = mapRelay.find(inv);
                    if (mi != mapRelay.end()) {
                        pfrom->PushMessage(inv.GetCommand(), (*mi).second);
                        pushed = true;
                    }
                }
                if (!pushed && inv.type == MSG_TX) {
                    CTransaction tx;
                    if (mempool.lookup(inv.hash, tx)) {
                        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
                        ss.reserve(1000);
                        ss << tx;
                        pfrom->PushMessage("tx", ss);
                        pushed = true;
                    }
                }
                if (!pushed) {
                    vNotFound.push_back(inv);
                }
            }

            // Track requests for our stuff.
            Inventory(inv.hash);

            if (inv.type == MSG_BLOCK )// || inv.type == MSG_FILTERED_BLOCK)
                break;
        }
    }

    pfrom->vRecvGetData.erase(pfrom->vRecvGetData.begin(), it);

    if (!vNotFound.empty()) {
        // Let the peer know that we didn't find what it asked for, so it doesn't
        // have to wait around forever. Currently only SPV clients actually care
        // about this message: it's needed when they are recursively walking the
        // dependencies of relevant unconfirmed transactions. SPV clients want to
        // do that because they want to know about (and store and rebroadcast and
        // risk analyze) the dependencies of transactions relevant to them, without
        // having to download the entire memory pool.
        pfrom->PushMessage("notfound", vNotFound);
    }
*/
{
vector<CInv> vInv;
vRecv >> vInv;
if (vInv.size() > MAX_INV_SZ)
{
    pfrom->Misbehaving(20);
    return error("message getdata size() = %d", vInv.size());
}

if (fDebugNet || (vInv.size() != 1))
    LogPrintf("received getdata (%d invsz)\n", vInv.size());

BOOST_FOREACH(const CInv& inv, vInv)
{
    if (fShutdown)
        return true;
    if (fDebugNet || (vInv.size() == 1))
        LogPrintf("received getdata for: %s\n", inv.ToString().c_str());

    if (inv.type == MSG_BLOCK)
    {
        // Send block from disk
        map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(inv.hash);
        if (mi != mapBlockIndex.end())
        {
            CBlock block;
            block.ReadFromDisk((*mi).second);
            pfrom->PushMessage("block", block);

            // Trigger them to send a getblocks request for the next batch of inventory
            if (inv.hash == pfrom->hashContinue)
            {
                // ppcoin: send latest proof-of-work block to allow the
                // download node to accept as orphan (proof-of-stake
                // block might be rejected by stake connection check)
                vector<CInv> vInv;
                vInv.push_back(CInv(MSG_BLOCK, GetLastBlockIndex(pindexBest, false)->GetBlockHash()));
                pfrom->PushMessage("inv", vInv);
                pfrom->hashContinue = 0;
            }
        }
    }
    else if (inv.IsKnownType())
    {
        // Send stream from relay memory
        bool pushed = false;
        {
            LOCK(cs_mapRelay);
            map<CInv, CDataStream>::iterator mi = mapRelay.find(inv);
            if (mi != mapRelay.end()) {
                pfrom->PushMessage(inv.GetCommand(), (*mi).second);
                pushed = true;
            }
        }
        if (!pushed && inv.type == MSG_TX) {
            LOCK(mempool.cs);
            if (mempool.exists(inv.hash)) {
                CTransaction tx = mempool.lookup(inv.hash);
                CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
                ss.reserve(1000);
                ss << tx;
                pfrom->PushMessage("tx", ss);
            }
        }
    }

    // Track requests for our stuff
    Inventory(inv.hash);
}
// Update the last seen time for this node's address
if (pfrom->fNetworkNode)
{
    AddressCurrentlyConnected(pfrom->addr);
    pfrom->nLastSend = GetTime();
}
return true;
}

bool processGetBlocks(CNode* pfrom, CDataStream& vRecv)
{
    CBlockLocator locator;
    uint256 hashStop;
    vRecv >> locator >> hashStop;

    // Find the last block the caller has in the main chain
    CBlockIndex* pindex = locator.GetBlockIndex();
    {
        // Send the rest of the chain
        if (pindex)
            pindex = pindex->pnext;
        int nLimit = 500;
        if(fDebugNet)
        {
            LogPrintf("getblocks %d to %s limit %d\n", (pindex ? pindex->nHeight : -1), hashStop.ToString().substr(0,20).c_str(), nLimit);
        }
        for (; pindex; pindex = pindex->pnext)
        {
            if (pindex->GetBlockHash() == hashStop)
            {
                LogPrintf("getblocks stopping at %d %s\n", pindex->nHeight, pindex->GetBlockHash().ToString());
                if (hashStop != pindexBest->GetBlockHash() && pindex->GetBlockIndexTime() + nStakeMinAge > pindexBest->GetBlockIndexTime())
                    pfrom->PushInventory(CInv(MSG_BLOCK, pindexBest->GetBlockHash()));
                break;
            }
            pfrom->PushInventory(CInv(MSG_BLOCK, pindex->GetBlockHash()));
            if (--nLimit <= 0)
            {
                // When this block is requested, we'll send an inv that'll make them
                // getblocks the next batch of inventory.
                LogPrintf("getblocks stopping at limit %d %s\n", pindex->nHeight, pindex->GetBlockHash().ToString());
                pfrom->hashContinue = pindex->GetBlockHash();
                break;
            }
        }
    }
    return true;
}

bool processTx(CNode* pfrom, CDataStream& vRecv)
{
    vector<uint256> vWorkQueue;
    vector<uint256> vEraseQueue;
    CDataStream vMsg(vRecv);
    CTxDB txdb("r");
    CTransaction tx;
    vRecv >> tx;

    CInv inv(MSG_TX, tx.GetHash());
    pfrom->AddInventoryKnown(inv);

    pfrom->setAskFor.erase(inv.hash);
    mapAlreadyAskedFor.erase(inv);

    bool fMissingInputs = false;

    if (!AlreadyHave(txdb, inv) && tx.AcceptToMemoryPool(txdb, true, &fMissingInputs))
    {
        SyncWithWallets(tx, NULL, true);
        RelayTransaction(tx, inv.hash);
        vWorkQueue.push_back(inv.hash);
        vEraseQueue.push_back(inv.hash);

        pfrom->nLastTXTime = GetTime();


        // Recursively process any orphan transactions that depended on this one
        for (unsigned int i = 0; i < vWorkQueue.size(); i++)
        {
            uint256 hashPrev = vWorkQueue[i];
            for (set<uint256>::iterator mi = mapOrphanTransactionsByPrev[hashPrev].begin();
                 mi != mapOrphanTransactionsByPrev[hashPrev].end();
                 ++mi)
            {
                const uint256& orphanTxHash = *mi;
                CTransaction& orphanTx = mapOrphanTransactions[orphanTxHash];
                bool fMissingInputs2 = false;

                if (orphanTx.AcceptToMemoryPool(txdb, true, &fMissingInputs2))
                {
                    LogPrintf("   accepted orphan tx %s\n", orphanTxHash.ToString().substr(0,10).c_str());
                    SyncWithWallets(tx, NULL, true);
                    RelayTransaction(orphanTx, orphanTxHash);
                    mapAlreadyAskedFor.erase(CInv(MSG_TX, orphanTxHash));
                    vWorkQueue.push_back(orphanTxHash);
                    vEraseQueue.push_back(orphanTxHash);
                }
                else if (!fMissingInputs2)
                {
                    // invalid orphan
                    vEraseQueue.push_back(orphanTxHash);
                    if(fDebugNet)
                    {
                        LogPrintf("   removed invalid orphan tx %s\n", orphanTxHash.ToString().substr(0,10).c_str());
                    }
                }
            }
        }

        BOOST_FOREACH(uint256 hash, vEraseQueue)
            EraseOrphanTx(hash);
    }
    else if (fMissingInputs)
    {
        AddOrphanTx(tx);

        // DoS prevention: do not allow mapOrphanTransactions to grow unbounded
        unsigned int nEvicted = LimitOrphanTxSize(MAX_ORPHAN_TRANSACTIONS);
        if (nEvicted > 0)
            LogPrintf("mapOrphan overflow, removed %u tx\n", nEvicted);
    }
    if (tx.nDoS) pfrom->Misbehaving(tx.nDoS);
    return true;
}

bool processBlock(CNode* pfrom, CDataStream& vRecv)
{
    CBlock block;
    vRecv >> block;
    const uint256 hashBlock = block.GetHash();

    //LogPrintf("received block %s\n", hashBlock.ToString().substr(0,20).c_str());
    //block.print();

    CInv inv(MSG_BLOCK, hashBlock);
    if(ProcessBlock(pfrom, &block))
    {
        mapAlreadyAskedFor.erase(inv);
        //pfrom->nLastBlockTime = GetTime();
    }
    if (block.nDoS)
    {
        pfrom->Misbehaving(block.nDoS);
    }
    return true;
}

bool processGetAddr(CNode* pfrom, CDataStream& vRecv)
{
    int64_t nCutOff = GetTime() - (nNodeLifespan * 24 * 60 * 60);
    pfrom->vAddrToSend.clear();
    vector<CAddress> vAddr = addrman.GetAddr();
    BOOST_FOREACH(const CAddress &addr, vAddr)
    {
        if(addr.nTime > nCutOff)
        {
            pfrom->PushAddress(addr);
        }
    }
    return true;
}

bool processMempool(CNode* pfrom, CDataStream& vRecv)
{
    std::vector<uint256> vtxid;
    mempool.queryHashes(vtxid);
    vector<CInv> vInv;
    for (unsigned int i = 0; i < vtxid.size(); i++) {
        CInv inv(MSG_TX, vtxid[i]);
        vInv.push_back(inv);
        if (i == (MAX_INV_SZ - 1))
                break;
    }
    if (vInv.size() > 0)
        pfrom->PushMessage("inv", vInv);
    return true;
}

bool processPing(CNode* pfrom, CDataStream& vRecv)
{
    if (pfrom->nVersion > BIP0031_VERSION)
    {
        uint64_t nonce = 0;
        vRecv >> nonce;
        // Echo the message back with the nonce. This allows for two useful features:
        //
        // 1) A remote node can quickly check if the connection is operational
        // 2) Remote nodes can measure the latency of the network thread. If this node
        //    is overloaded it won't respond to pings quickly and the remote node can
        //    avoid sending us more work, like chain download requests.
        //
        // The nonce stops the remote getting confused between different pings: without
        // it, if the remote node sends a ping once per second and this node takes 5
        // seconds to respond to each, the 5th ping the remote sends would appear to
        // return very quickly.
        pfrom->PushInventory(CInv(MSG_BLOCK, pindexBest->GetBlockHash()));
        pfrom->PushMessage("pong", nonce);
    }
    // Update the last seen time for this node's address
    if (pfrom->fNetworkNode)
    {
        AddressCurrentlyConnected(pfrom->addr);
        pfrom->nLastSend = GetTime();
    }
    return true;
}

bool processPong(CNode* pfrom, CDataStream& vRecv, int64_t nTimeReceived)
{
    pfrom->PushInventory(CInv(MSG_BLOCK, pindexBest->GetBlockHash()));
    int64_t pingUsecEnd = nTimeReceived;
    uint64_t nonce = 0;
    size_t nAvail = vRecv.in_avail();
    bool bPingFinished = false;
    std::string sProblem;

    if (nAvail >= sizeof(nonce)) {
        vRecv >> nonce;

        // Only process pong message if there is an outstanding ping (old ping without nonce should never pong)
        if (pfrom->nPingNonceSent != 0) {
            if (nonce == pfrom->nPingNonceSent) {
                // Matching pong received, this ping is no longer outstanding
                bPingFinished = true;
                int64_t pingUsecTime = pingUsecEnd - pfrom->nPingUsecStart;
                if (pingUsecTime > 0) {
                    // Successful ping time measurement, replace previous
                    pfrom->nPingUsecTime = pingUsecTime;
                    pfrom->nMinPingUsecTime = std::min(pfrom->nMinPingUsecTime.load(), pingUsecTime);
                } else {
                    // This should never happen
                    sProblem = "Timing mishap";
                }
            } else {
                // Nonce mismatches are normal when pings are overlapping
                sProblem = "Nonce mismatch";
                if (nonce == 0) {
                    // This is most likely a bug in another implementation somewhere; cancel this ping
                    bPingFinished = true;
                    sProblem = "Nonce zero";
                }
            }
        } else {
            sProblem = "Unsolicited pong without ping";
        }
    } else {
        // This is most likely a bug in another implementation somewhere; cancel this ping
        bPingFinished = true;
        sProblem = "Short payload";
    }

    if (!(sProblem.empty())) {
        //LogPrintf("pong peer=%d: %s, %x expected, %x received, %u bytes\n",
        //    pfrom->id,
        //    sProblem,
        //    pfrom->nPingNonceSent,
        //    nonce,
        //    nAvail);
    }
    if (bPingFinished) {
        pfrom->nPingNonceSent = 0;
    }
    return true;
}
