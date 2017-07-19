#include <thread>

//////////////////////////////////////////////////////////////////////////////
//
// Shutdown Node
//

void ExitTimeout()
{
#ifdef WIN32
    MilliSleep(5000);
    ExitProcess(0);
#endif
}

void StartShutdown()
{
    // Without UI, Shutdown() can simply be started in a new thread
    boost::thread* shutdown = new boost::thread(&Shutdown);
    ecc_threads.add_thread(shutdown);
}

bool StopNode()
{
    LogPrintf("StopNode()\n");
    fShutdown = true;
    nTransactionsUpdated++;
    if (semOutbound)
    {
        for (int i=0; i<MAX_OUTBOUND_CONNECTIONS; i++)
        {
            semOutbound->post();
        }
    }
    ecc_threads.join_all();
    MilliSleep(500);
    int64_t nStart = GetTimeMillis();
    CAddrDB adb;
    adb.Write(addrman);
    LogPrintf("Flushed %d addresses to peers.dat  %d ms\n",
           addrman.size(), GetTimeMillis() - nStart);
    return true;
}

void Shutdown()
{
    static CCriticalSection cs_Shutdown;
    static bool fTaken;

    // Make this thread recognisable as the shutdown thread
    RenameThread("ECCoin-shutoff");

    bool fFirstThread = false;
    {
        TRY_LOCK(cs_Shutdown, lockShutdown);
        if (lockShutdown)
        {
            fFirstThread = !fTaken;
            fTaken = true;
        }
    }
    if (fFirstThread)
    {
        fShutdown = true;
        nTransactionsUpdated++;
        CTxDB().Close();
        CHeaderChainDB().Close();
        bitdb.Flush(false);
        StopNode();
        bitdb.Flush(true);
        boost::filesystem::remove(GetPidFile());
        UnregisterWallet(pwalletMain);
        delete pwalletMain;
        boost::thread* exitTimeout = new boost::thread(&ExitTimeout);
        ecc_threads.add_thread(exitTimeout);
        MilliSleep(50);
        LogPrintf("ECCoin exited\n\n");
        exit(0);
    }
}
