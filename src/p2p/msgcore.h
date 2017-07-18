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

void PushNodeVersion(CNode *pnode, int64_t nTime);

bool processVersion(CNode* pfrom, CDataStream& vRecv);
bool processVerack(CNode* pfrom, CDataStream& vRecv);
bool processAddr(CNode* pfrom, CDataStream& vRecv);
bool processInv(CNode* pfrom, CDataStream& vRecv);
bool processGetData(CNode* pfrom, CDataStream& vRecv);
bool processGetBlocks(CNode* pfrom, CDataStream& vRecv);
bool processTx(CNode* pfrom, CDataStream& vRecv);
bool processBlock(CNode* pfrom, CDataStream& vRecv);
bool processGetAddr(CNode* pfrom, CDataStream& vRecv);
bool processMempool(CNode* pfrom, CDataStream& vRecv);
bool processPing(CNode* pfrom, CDataStream& vRecv);
bool processPong(CNode* pfrom, CDataStream& vRecv, int64_t nTimeReceived);

#endif // MESSAGES_H
