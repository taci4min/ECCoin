// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_INIT_H
#define BITCOIN_INIT_H

#include "wallet/wallet.h"
#include "chain/checkpoints.h"
#include "p2p/connman.h"

extern std::unique_ptr<CConnman> pconnman;
extern CWallet* pwalletMain;
extern Checkpoints* pcheckpointMain;
extern ServiceFlags nLocalServices;


extern std::string strWalletFileName;
void StartShutdown();
void Shutdown();
std::string HelpMessage();
extern boost::thread_group ecc_threads;



extern bool fEnforceCanonical;

#endif

