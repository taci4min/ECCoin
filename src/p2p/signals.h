#ifndef SIGNALS_H
#define SIGNALS_H

#include <memory>
#include "chain/blockindex.h"
#include "connman.h"
#include "chain/locator.h"
#include "validation.h"
#include "scheduler.h"

class CValidationInterface {
protected:
    /** Notifies listeners of updated block chain tip */
    virtual void UpdatedBlockTip(const CBlockIndex *pindexNew, const CBlockIndex *pindexFork, bool fInitialDownload)
    {
        // intentionally left blank
    }
    /** Notifies listeners of a transaction having been added to mempool. */
    virtual void TransactionAddedToMempool(const std::shared_ptr<CTransaction> &ptxn)
    {
        // intentionally left blank
    }
    /**
     * Notifies listeners of a block being connected.
     * Provides a vector of transactions evicted from the mempool as a result.
     */
    virtual void BlockConnected(const std::shared_ptr<const CBlock> &block, const CBlockIndex *pindex, const std::vector<std::shared_ptr<CTransaction>> &txnConflicted)
    {
        // intentionally left blank
    }
    /** Notifies listeners of a block being disconnected */
    virtual void BlockDisconnected(const std::shared_ptr<const CBlock> &block)
    {
        // intentionally left blank
    }
    /** Notifies listeners of the new active block chain on-disk. */
    virtual void SetBestChain(const CBlockLocator &locator)
    {
        // intentionally left blank
    }
    /** Notifies listeners about an inventory item being seen on the network. */
    virtual void Inventory(const uint256 &hash)
    {
        // intentionally left blank
    }
    /** Tells listeners to broadcast their data. */
    virtual void ResendWalletTransactions(int64_t nBestBlockTime, CConnman* connman)
    {
        // intentionally left blank
    }
    /**
     * Notifies listeners of a block validation result.
     * If the provided CValidationState IsValid, the provided block
     * is guaranteed to be the current best block at the time the
     * callback was generated (not necessarily now)
     */
    virtual void BlockChecked(const CBlock&, const CValidationState&)
    {
        // intentionally left blank
    }
    /**
     * Notifies listeners that a block which builds directly on our current tip
     * has been received and connected to the headers tree, though not validated yet */
    virtual void NewPoWValidBlock(const CBlockIndex *pindex, const std::shared_ptr<const CBlock>& block)
    {
        // intentionally left blank
    }
    friend void ::RegisterValidationInterface(CValidationInterface*);
    friend void ::UnregisterValidationInterface(CValidationInterface*);
    friend void ::UnregisterAllValidationInterfaces();
};

struct MainSignalsInstance;
class CMainSignals {
private:
    std::unique_ptr<MainSignalsInstance> m_internals;

    friend void ::RegisterValidationInterface(CValidationInterface*);
    friend void ::UnregisterValidationInterface(CValidationInterface*);
    friend void ::UnregisterAllValidationInterfaces();

public:

    // Register a CScheduler to give callbacks which should run in the background (may only be called once)
    void RegisterBackgroundSignalScheduler(CScheduler& scheduler);
    /// Unregister a CScheduler to give callbacks which should run in the background - these callbacks will now be dropped!
    void UnregisterBackgroundSignalScheduler();
    /// Call any remaining callbacks on the calling thread
    void FlushBackgroundCallbacks();

    void UpdatedBlockTip(const CBlockIndex *, const CBlockIndex *, bool fInitialDownload);
    void TransactionAddedToMempool(const std::shared_ptr<CTransaction> &);
    void BlockConnected(const std::shared_ptr<const CBlock> &, const CBlockIndex *pindex, const std::vector<std::shared_ptr<CTransaction>> &);
    void BlockDisconnected(const std::shared_ptr<const CBlock> &);
    void SetBestChain(const CBlockLocator &);
    void Inventory(const uint256 &);
    void Broadcast(int64_t nBestBlockTime, CConnman* connman);
    void BlockChecked(const CBlock&, const CValidationState&);
    void NewPoWValidBlock(const CBlockIndex *, const std::shared_ptr<const CBlock>&);
};

// These functions dispatch to one or all registered wallets

/** Register a wallet to receive updates from core */
void RegisterValidationInterface(CValidationInterface* pwalletIn);
/** Unregister a wallet from core */
void UnregisterValidationInterface(CValidationInterface* pwalletIn);
/** Unregister all wallets from core */
void UnregisterAllValidationInterfaces();

CMainSignals& GetMainSignals();

#endif // SIGNALS_H
