// Copyright (c) 2012 Pieter Wuille
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef _BITCOIN_ADDRMAN
#define _BITCOIN_ADDRMAN 1

#include "protocol.h"
#include "sync.h"
#include "util/util.h"
#include "util/random.h"

#include <map>
#include <vector>

#include <openssl/rand.h>


/** Extended statistics about a CAddress */
class CAddrInfo : public CAddress
{
private:
    // where knowledge about this address first came from
    CNetAddr source;

    // last successful connection by us
    int64_t nLastSuccess;

    // last try whatsoever by us:
    // int64_t CAddress::nLastTry

    // connection attempts since last successful attempt
    int nAttempts;

    // reference count in new sets (memory only)
    int nRefCount;

    // in tried set? (memory only)
    bool fInTried;

    // position in vRandom
    int nRandomPos;

    friend class CAddrMan;

public:

    ADD_SERIALIZE_METHODS

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(*(CAddress*)this);
        READWRITE(source);
        READWRITE(nLastSuccess);
        READWRITE(nAttempts);
    }


    void Init()
    {
        nLastSuccess = 0;
        nLastTry = 0;
        nAttempts = 0;
        nRefCount = 0;
        fInTried = false;
        nRandomPos = -1;
    }

    CAddrInfo(const CAddress &addrIn, const CNetAddr &addrSource) : CAddress(addrIn), source(addrSource)
    {
        Init();
    }

    CAddrInfo() : CAddress(), source()
    {
        Init();
    }

    // Calculate in which "tried" bucket this entry belongs
    int GetTriedBucket(const std::vector<unsigned char> &nKey) const;

    // Calculate in which "new" bucket this entry belongs, given a certain source
    int GetNewBucket(const std::vector<unsigned char> &nKey, const CNetAddr& src) const;

    // Calculate in which "new" bucket this entry belongs, using its default source
    int GetNewBucket(const std::vector<unsigned char> &nKey) const
    {
        return GetNewBucket(nKey, source);
    }

    //! Calculate in which "new" bucket this entry belongs, given a certain source
    int GetNewBucket(const uint256 &nKey, const CNetAddr& src) const;

    //! Calculate in which "new" bucket this entry belongs, using its default source
    int GetNewBucket(const uint256 &nKey) const
    {
        return GetNewBucket(nKey, source);
    }

    // Determine whether the statistics about this entry are bad enough so that it can just be deleted
    bool IsTerrible(int64_t nNow = GetTime()) const;

    // Calculate the relative chance this entry should be given when selecting nodes to connect to
    double GetChance(int64_t nNow = GetTime()) const;

    //! Calculate in which position of a bucket to store this entry.
    int GetBucketPosition(const uint256 &nKey, bool fNew, int nBucket) const;

    //! Calculate in which "tried" bucket this entry belongs
    int GetTriedBucket(const uint256 &nKey) const;


};

// Stochastic address manager
//
// Design goals:
//  * Only keep a limited number of addresses around, so that addr.dat and memory requirements do not grow without bound.
//  * Keep the address tables in-memory, and asynchronously dump the entire to able in addr.dat.
//  * Make sure no (localized) attacker can fill the entire table with his nodes/addresses.
//
// To that end:
//  * Addresses are organized into buckets.
//    * Address that have not yet been tried go into 256 "new" buckets.
//      * Based on the address range (/16 for IPv4) of source of the information, 32 buckets are selected at random
//      * The actual bucket is chosen from one of these, based on the range the address itself is located.
//      * One single address can occur in up to 4 different buckets, to increase selection chances for addresses that
//        are seen frequently. The chance for increasing this multiplicity decreases exponentially.
//      * When adding a new address to a full bucket, a randomly chosen entry (with a bias favoring less recently seen
//        ones) is removed from it first.
//    * Addresses of nodes that are known to be accessible go into 64 "tried" buckets.
//      * Each address range selects at random 4 of these buckets.
//      * The actual bucket is chosen from one of these, based on the full address.
//      * When adding a new good address to a full bucket, a randomly chosen entry (with a bias favoring less recently
//        tried ones) is evicted from it, back to the "new" buckets.
//    * Bucket selection is based on cryptographic hashing, using a randomly-generated 256-bit key, which should not
//      be observable by adversaries.
//    * Several indexes are kept for high performance. Defining DEBUG_ADDRMAN will introduce frequent (and expensive)
//      consistency checks for the entire data structure.

// total number of buckets for tried addresses
#define ADDRMAN_TRIED_BUCKET_COUNT 64

// maximum allowed number of entries in buckets for tried addresses
#define ADDRMAN_TRIED_BUCKET_SIZE 64

// total number of buckets for new addresses
#define ADDRMAN_NEW_BUCKET_COUNT 256

// maximum allowed number of entries in buckets for new addresses
#define ADDRMAN_NEW_BUCKET_SIZE 64

// over how many buckets entries with tried addresses from a single group (/16 for IPv4) are spread
#define ADDRMAN_TRIED_BUCKETS_PER_GROUP 4

// over how many buckets entries with new addresses originating from a single group are spread
#define ADDRMAN_NEW_BUCKETS_PER_SOURCE_GROUP 32

// in how many buckets for entries with new addresses a single address may occur
#define ADDRMAN_NEW_BUCKETS_PER_ADDRESS 4

// how many entries in a bucket with tried addresses are inspected, when selecting one to replace
#define ADDRMAN_TRIED_ENTRIES_INSPECT_ON_EVICT 4

// how old addresses can maximally be
#define ADDRMAN_HORIZON_DAYS 30

// after how many failed attempts we give up on a new node
#define ADDRMAN_RETRIES 3

// how many successive failures are allowed ...
#define ADDRMAN_MAX_FAILURES 10

// ... in at least this many days
#define ADDRMAN_MIN_FAIL_DAYS 7

// the maximum percentage of nodes to return in a getaddr call
#define ADDRMAN_GETADDR_MAX_PCT 23

// the maximum number of nodes to return in a getaddr call
#define ADDRMAN_GETADDR_MAX 2500

//! maximum allowed number of entries in buckets for new and tried addresses
#define ADDRMAN_BUCKET_SIZE_LOG2 6
#define ADDRMAN_BUCKET_SIZE (1 << ADDRMAN_BUCKET_SIZE_LOG2)


/** Stochastical (IP) address manager */
class CAddrMan
{
private:
    // critical section to protect the inner data structures
    mutable CCriticalSection cs;

    // secret key to randomize bucket select with
    uint256 nKey;

    // last used nId
    int nIdCount;

    // table with information about all nIds
    std::map<int, CAddrInfo> mapInfo;

    // find an nId based on its network address
    std::map<CNetAddr, int> mapAddr;

    // randomly-ordered vector of all nIds
    std::vector<int> vRandom;

    // number of "tried" entries
    int nTried;

    // list of "tried" buckets
    std::vector<std::vector<int> > vvTried;

    // number of (unique) "new" entries
    int nNew;

    // list of "new" buckets
    int vvNew[ADDRMAN_NEW_BUCKET_COUNT][ADDRMAN_BUCKET_SIZE];

    //! last time Good was called (memory only)
    int64_t nLastGood;

protected:

    // Find an entry.
    CAddrInfo* Find(const CNetAddr& addr, int *pnId = NULL);

    // find an entry, creating it if necessary.
    // nTime and nServices of found node is updated, if necessary.
    CAddrInfo* Create(const CAddress &addr, const CNetAddr &addrSource, int *pnId = NULL);

    // Swap two elements in vRandom.
    void SwapRandom(unsigned int nRandomPos1, unsigned int nRandomPos2);

    // Return position in given bucket to replace.
    int SelectTried(int nKBucket);

    // Remove an element from a "new" bucket.
    // This is the only place where actual deletes occur.
    // They are never deleted while in the "tried" table, only possibly evicted back to the "new" table.
    int ShrinkNew(int nUBucket);

    // Move an entry from the "new" table(s) to the "tried" table
    // @pre vvUnkown[nOrigin].count(nId) != 0
    void MakeTried(CAddrInfo& info, int nId, int nOrigin);

    // Mark an entry "good", possibly moving it from "new" to "tried".
    void Good_(const CService &addr, int64_t nTime);

    // Add an entry to the "new" table.
    bool Add_(const CAddress &addr, const CNetAddr& source, int64_t nTimePenalty);

    // Mark an entry as attempted to connect.
    void Attempt_(const CService &addr, int64_t nTime);

    // Select an address to connect to.
    // nUnkBias determines how much to favor new addresses over tried ones (min=0, max=100)
    CAddress Select_(int nUnkBias);

#ifdef DEBUG_ADDRMAN
    // Perform consistency check. Returns an error code or zero.
    int Check_();
#endif

    // Select several addresses at once.
    void GetAddr_(std::vector<CAddress> &vAddr);

    // Mark an entry as currently-connected-to.
    void Connected_(const CService &addr, int64_t nTime);

    //! Update an entry's service bits.
    void SetServices_(const CService &addr, ServiceFlags nServices);

public:

    template<typename Stream>
    void Serialize(Stream &s) const
    {
        LOCK(cs);

        unsigned char nVersion = 1;
        s << nVersion;
        s << ((unsigned char)32);
        s << nKey;
        s << nNew;
        s << nTried;

        int nUBuckets = ADDRMAN_NEW_BUCKET_COUNT ^ (1 << 30);
        s << nUBuckets;
        std::map<int, int> mapUnkIds;
        int nIds = 0;
        for (std::map<int, CAddrInfo>::const_iterator it = mapInfo.begin(); it != mapInfo.end(); it++) {
            mapUnkIds[(*it).first] = nIds;
            const CAddrInfo &info = (*it).second;
            if (info.nRefCount) {
                assert(nIds != nNew); // this means nNew was wrong, oh ow
                s << info;
                nIds++;
            }
        }
        nIds = 0;
        for (std::map<int, CAddrInfo>::const_iterator it = mapInfo.begin(); it != mapInfo.end(); it++) {
            const CAddrInfo &info = (*it).second;
            if (info.fInTried) {
                assert(nIds != nTried); // this means nTried was wrong, oh ow
                s << info;
                nIds++;
            }
        }
        for (int bucket = 0; bucket < ADDRMAN_NEW_BUCKET_COUNT; bucket++) {
            int nSize = 0;
            for (int i = 0; i < ADDRMAN_BUCKET_SIZE; i++) {
                if (vvNew[bucket][i] != -1)
                    nSize++;
            }
            s << nSize;
            for (int i = 0; i < ADDRMAN_BUCKET_SIZE; i++) {
                if (vvNew[bucket][i] != -1) {
                    int nIndex = mapUnkIds[vvNew[bucket][i]];
                    s << nIndex;
                }
            }
        }
    }

    template<typename Stream>
    void Unserialize(Stream& s)
    {
        LOCK(cs);

        Clear();

        unsigned char nVersion;
        s >> nVersion;
        unsigned char nKeySize;
        s >> nKeySize;
        if (nKeySize != 32) throw std::ios_base::failure("Incorrect keysize in addrman deserialization");
        s >> nKey;
        s >> nNew;
        s >> nTried;
        int nUBuckets = 0;
        s >> nUBuckets;
        if (nVersion != 0) {
            nUBuckets ^= (1 << 30);
        }

        if (nNew > ADDRMAN_NEW_BUCKET_COUNT * ADDRMAN_BUCKET_SIZE) {
            throw std::ios_base::failure("Corrupt CAddrMan serialization, nNew exceeds limit.");
        }

        if (nTried > ADDRMAN_TRIED_BUCKET_COUNT * ADDRMAN_BUCKET_SIZE) {
            throw std::ios_base::failure("Corrupt CAddrMan serialization, nTried exceeds limit.");
        }

        // Deserialize entries from the new table.
        for (int n = 0; n < nNew; n++) {
            CAddrInfo &info = mapInfo[n];
            s >> info;
            mapAddr[info] = n;
            info.nRandomPos = vRandom.size();
            vRandom.push_back(n);
            if (nVersion != 1 || nUBuckets != ADDRMAN_NEW_BUCKET_COUNT) {
                // In case the new table data cannot be used (nVersion unknown, or bucket count wrong),
                // immediately try to give them a reference based on their primary source address.
                int nUBucket = info.GetNewBucket(nKey);
                int nUBucketPos = info.GetBucketPosition(nKey, true, nUBucket);
                if (vvNew[nUBucket][nUBucketPos] == -1) {
                    vvNew[nUBucket][nUBucketPos] = n;
                    info.nRefCount++;
                }
            }
        }
        nIdCount = nNew;

        // Deserialize entries from the tried table.
        int nLost = 0;
        for (int n = 0; n < nTried; n++) {
            CAddrInfo info;
            s >> info;
            int nKBucket = info.GetTriedBucket(nKey);
            int nKBucketPos = info.GetBucketPosition(nKey, false, nKBucket);
            if (vvTried[nKBucket][nKBucketPos] == -1) {
                info.nRandomPos = vRandom.size();
                info.fInTried = true;
                vRandom.push_back(nIdCount);
                mapInfo[nIdCount] = info;
                mapAddr[info] = nIdCount;
                vvTried[nKBucket][nKBucketPos] = nIdCount;
                nIdCount++;
            } else {
                nLost++;
            }
        }
        nTried -= nLost;

        // Deserialize positions in the new table (if possible).
        for (int bucket = 0; bucket < nUBuckets; bucket++) {
            int nSize = 0;
            s >> nSize;
            for (int n = 0; n < nSize; n++) {
                int nIndex = 0;
                s >> nIndex;
                if (nIndex >= 0 && nIndex < nNew) {
                    CAddrInfo &info = mapInfo[nIndex];
                    int nUBucketPos = info.GetBucketPosition(nKey, true, bucket);
                    if (nVersion == 1 && nUBuckets == ADDRMAN_NEW_BUCKET_COUNT && vvNew[bucket][nUBucketPos] == -1 && info.nRefCount < ADDRMAN_NEW_BUCKETS_PER_ADDRESS) {
                        info.nRefCount++;
                        vvNew[bucket][nUBucketPos] = nIndex;
                    }
                }
            }
        }

        // Prune new entries with refcount 0 (as a result of collisions).
        int nLostUnk = 0;
        for (std::map<int, CAddrInfo>::const_iterator it = mapInfo.begin(); it != mapInfo.end(); ) {
            if (it->second.fInTried == false && it->second.nRefCount == 0) {
                std::map<int, CAddrInfo>::const_iterator itCopy = it++;
                Delete(itCopy->first);
                nLostUnk++;
            } else {
                it++;
            }
        }
        if (nLost + nLostUnk > 0) {
            LogPrint(BCLog::ADDRMAN, "addrman lost %i new and %i tried addresses due to collisions\n", nLostUnk, nLost);
        }

        Check();
    }

    void Delete(int nId)
    {
        assert(mapInfo.count(nId) != 0);
        CAddrInfo& info = mapInfo[nId];
        assert(!info.fInTried);
        assert(info.nRefCount == 0);

        SwapRandom(info.nRandomPos, vRandom.size() - 1);
        vRandom.pop_back();
        mapAddr.erase(info);
        mapInfo.erase(nId);
        nNew--;
    }

    void Clear()
    {
        std::vector<int>().swap(vRandom);
        nKey = GetRandHash();
        for (size_t bucket = 0; bucket < ADDRMAN_NEW_BUCKET_COUNT; bucket++) {
            for (size_t entry = 0; entry < ADDRMAN_BUCKET_SIZE; entry++) {
                vvNew[bucket][entry] = -1;
            }
        }
        for (size_t bucket = 0; bucket < ADDRMAN_TRIED_BUCKET_COUNT; bucket++) {
            for (size_t entry = 0; entry < ADDRMAN_BUCKET_SIZE; entry++) {
                vvTried[bucket][entry] = -1;
            }
        }

        nIdCount = 0;
        nTried = 0;
        nNew = 0;
        nLastGood = 1; //Initially at 1 so that "never" is strictly worse.
    }


    CAddrMan()
    {
        Clear();
    }

    ~CAddrMan()
    {
        nKey.SetNull();
    }

    // Return the number of (unique) addresses in all tables.
    int size()
    {
        return vRandom.size();
    }

    // Consistency check
    void Check()
    {
#ifdef DEBUG_ADDRMAN
        {
            LOCK(cs);
            int err;
            if ((err=Check_()))
                LogPrintf("ADDRMAN CONSISTENCY CHECK FAILED!!! err=%i\n", err);
        }
#endif
    }

    // Add a single address.
    bool Add(const CAddress &addr, const CNetAddr& source, int64_t nTimePenalty = 0)
    {
        bool fRet = false;
        {
            LOCK(cs);
            Check();
            fRet |= Add_(addr, source, nTimePenalty);
            Check();
        }
        if (fRet)
            LogPrintf("Added %s from %s: %i tried, %i new\n", addr.ToStringIPPort().c_str(), source.ToString().c_str(), nTried, nNew);
        return fRet;
    }

    // Add multiple addresses.
    bool Add(const std::vector<CAddress> &vAddr, const CNetAddr& source, int64_t nTimePenalty = 0)
    {
        int nAdd = 0;
        {
            LOCK(cs);
            Check();
            for (std::vector<CAddress>::const_iterator it = vAddr.begin(); it != vAddr.end(); it++)
                nAdd += Add_(*it, source, nTimePenalty) ? 1 : 0;
            Check();
        }
        if (nAdd)
            LogPrintf("Added %i addresses from %s: %i tried, %i new\n", nAdd, source.ToString().c_str(), nTried, nNew);
        return nAdd > 0;
    }

    // Mark an entry as accessible.
    void Good(const CService &addr, int64_t nTime = GetTime())
    {
        {
            LOCK(cs);
            Check();
            Good_(addr, nTime);
            Check();
        }
    }

    // Mark an entry as connection attempted to.
    void Attempt(const CService &addr, int64_t nTime = GetTime())
    {
        {
            LOCK(cs);
            Check();
            Attempt_(addr, nTime);
            Check();
        }
    }

    // Choose an address to connect to.
    // nUnkBias determines how much "new" entries are favored over "tried" ones (0-100).
    CAddress Select(int nUnkBias = 50)
    {
        CAddress addrRet;
        {
            LOCK(cs);
            Check();
            addrRet = Select_(nUnkBias);
            Check();
        }
        return addrRet;
    }

    // Return a bunch of addresses, selected at random.
    std::vector<CAddress> GetAddr()
    {
        Check();
        std::vector<CAddress> vAddr;
        {
            LOCK(cs);
            GetAddr_(vAddr);
        }
        Check();
        return vAddr;
    }

    // Mark an entry as currently-connected-to.
    void Connected(const CService &addr, int64_t nTime = GetTime())
    {
        {
            LOCK(cs);
            Check();
            Connected_(addr, nTime);
            Check();
        }
    }

    void SetServices(const CService &addr, ServiceFlags nServices)
    {
        LOCK(cs);
        Check();
        SetServices_(addr, nServices);
        Check();
    }

};

#endif
