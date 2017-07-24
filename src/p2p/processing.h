#ifndef NET_PROCESSING_H
#define NET_PROCESSING_H

#include "chain/checkpoints.h"
#include "wallet/db.h"
#include "init.h"
#include "mining/kernel.h"
#include "main.h"
#include "p2p/net.h"
#include "tx/txdb-leveldb.h"
#include "ui_interface.h"
#include "util/random.h"

extern unsigned char pchMessageStart[4];

bool AlreadyHave(CTxDB& txdb, const CInv& inv);
bool ProcessMessages(CNode* pfrom);
bool SendMessages(CNode* pto, bool fSendTrickle);

#endif // NET_PROCESSING_H
