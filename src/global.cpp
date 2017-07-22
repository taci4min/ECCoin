#include "chain/block.h"
#include "chain/blockindex.h"
#include "tx/tx.h"
#include "tx/merkletx.h"
#include "chain/chain.h"

#include <map>
#include <set>


std::map<uint256, CBlock*> mapOrphanBlocks;
std::map<uint256, CTransaction> mapOrphanTransactions;
std::map<uint256, std::set<uint256> > mapOrphanTransactionsByPrev;
std::multimap<uint256, CBlock*> mapOrphanBlocksByPrev;
std::set<std::pair<COutPoint, unsigned int> > setStakeSeenOrphan;
std::set<std::pair<COutPoint, unsigned int> > setStakeSeen;

std::map<uint256, CBlockIndex*> mapBlockIndex;

int nCoinbaseMaturity = 30;

unsigned int nTransactionsUpdated = 0;

uint256 bnProofOfWorkLimit(uint256S("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"));
uint256 bnProofOfStakeLimit(uint256S("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"));
uint256 bnProofOfWorkLimitTestNet(uint256S("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"));
uint256 bnProofOfStakeLimitTestNet(uint256S("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"));

unsigned int nStakeTargetSpacing = 45;
unsigned int nTargetSpacing = 45;
unsigned int nStakeMinAge = 60*60*2; // 2 hours
unsigned int nStakeMaxAge = 60*60*24*84;           //84 days
unsigned int nModifierInterval = 6*60*60;
unsigned int nModifierIntervalSecond = 60*60;

CBlockIndex* pindexGenesisBlock = NULL;

int64_t nBestTimeReceived = 0;
int64_t nChainStartTime = 1393744287;

arith_uint256 nBestChainTrust = 0;
arith_uint256 nBestInvalidTrust = 0;
