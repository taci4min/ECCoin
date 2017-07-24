#ifndef TYPEDEF_H
#define TYPEDEF_H

#include <map>
#include <set>

#include "chain/block.h"
#include "chain/blockindex.h"
#include "tx/tx.h"
#include "tx/inpoint.h"
#include "tx/merkletx.h"
#include "uint256.h"
#include "arith_uint256.h"


/// Program constants ///
static const uint256 hashGenesisBlock = uint256S("a60ac43c88dbc44b826cf315352a8a7b373d2af8b6e1c4c4a0638859c5e9ecd1");
static const uint256 hashGenesisBlockTestNet = uint256S("a60ac43c88dbc44b826cf315352a8a7b373d2af8b6e1c4c4a0638859c5e9ecd1");
static const int LAST_POW_BLOCK = 86400;
static const unsigned int MAX_BLOCK_SIZE = 1000000;
static const unsigned int MAX_BLOCK_SIZE_GEN = MAX_BLOCK_SIZE/2;
static const unsigned int MAX_BLOCK_SIGOPS = MAX_BLOCK_SIZE/50;
static const unsigned int MAX_ORPHAN_TRANSACTIONS = MAX_BLOCK_SIZE/100;
static const int64_t nTargetTimespan = 30 * 45;
// Threshold for nLockTime: below this value it is interpreted as block number, otherwise as UNIX timestamp.
static const unsigned int LOCKTIME_THRESHOLD = 500000000; // Tue Nov  5 00:53:20 1985 UTC


/// The following are all defined in statics.cpp ///
extern std::map<uint256, CBlock*> mapOrphanBlocks;
extern std::multimap<uint256, CBlock*> mapOrphanBlocksByPrev;
extern std::set<std::pair<COutPoint, unsigned int> > setStakeSeenOrphan;
extern std::map<uint256, CTransaction> mapOrphanTransactions;
extern std::map<uint256, std::set<uint256> > mapOrphanTransactionsByPrev;
extern std::map<uint256, CBlockIndex*> mapBlockIndex;
extern int nCoinbaseMaturity;
extern unsigned int nTransactionsUpdated;
extern uint256 bnProofOfWorkLimit;
extern uint256 bnProofOfStakeLimit;
extern uint256 bnProofOfWorkLimitTestNet;
extern uint256 bnProofOfStakeLimitTestNet;
extern unsigned int nStakeTargetSpacing;
extern unsigned int nTargetSpacing;
extern unsigned int nStakeMinAge; // 2 hours
extern unsigned int nStakeMaxAge;           //84 days
extern unsigned int nModifierInterval;
extern unsigned int nModifierIntervalSecond;
extern CBlockIndex* pindexGenesisBlock;
extern int64_t nBestTimeReceived;
extern int64_t nChainStartTime;
extern arith_uint256 nBestChainTrust;
extern arith_uint256 nBestInvalidTrust;


#endif // TYPEDEF_H
