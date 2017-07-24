#include "p2p/node.h"
#include "wallet/wallet.h"
#include "mining/miner.h"

void ThreadStakeMinter_Scrypt(void* parg)
{
    LogPrintf("ThreadStakeMinter started\n");
    CWallet* pwallet = (CWallet*)parg;
    try
    {
        ScryptMiner(pwallet, true);
    }
    catch (std::exception& e) {
        PrintException(&e, "ThreadStakeMinter()");
    } catch (...) {
        PrintException(NULL, "ThreadStakeMinter()");
    }
    LogPrintf("ThreadStakeMinter exiting");
}
