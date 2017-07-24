#ifndef MESSAGES_H
#define MESSAGES_H

#include "chain/checkpoints.h"
#include "wallet/db.h"
#include "init.h"
#include "mining/kernel.h"
#include "main.h"
#include "p2p/net.h"
#include "tx/txdb-leveldb.h"
#include "ui_interface.h"
#include "util/random.h"

extern std::map<uint256, std::pair<NodeId, std::list<QueuedBlock>::iterator> > mapBlocksInFlight;
extern int nPreferredDownload;
extern int nSyncStarted;
extern int nPeersWithValidatedDownloads;


void ProcessGetData(CNode* pfrom, CConnman& connman, const std::atomic<bool> &interruptMsgProc);
bool ProcessMessage(CNode* pfrom, const std::string& strCommand, CDataStream& vRecv, int64_t nTimeReceived, CConnman& connman, const std::atomic<bool>& interruptMsgProc);
bool MarkBlockAsInFlight(NodeId nodeid, const uint256& hash, const CBlockIndex* pindex = NULL, std::list<QueuedBlock>::iterator** pit = NULL);
void ProcessBlockAvailability(NodeId nodeid);
uint32_t GetFetchFlags(CNode* pfrom);

#endif // MESSAGES_H
