#include "validation.h"
#include "chain/locator.h"

CBlockIndex* FindForkInGlobalIndex(const CBlockLocator& locator)
{
    // Find the first block the caller has in the main chain
    for (const uint256& hash : locator.vHave) {
        std::map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(hash);
        if (mi != mapBlockIndex.end())
        {
            CBlockIndex* pindex = (*mi).second;
            if (mapBlockIndex.count(pindex->GetBlockHash()))
                return pindex;
            if (pindex->pprev == pindexBest)
            {
                return pindexBest;
            }
        }
    }
    return pindexGenesisBlock;
}
