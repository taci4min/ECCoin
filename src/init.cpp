// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chain/checkpoints.h"
#include "init.h"
#include "p2p/connman.h"
#include "tx/txdb-leveldb.h"
#include "uint256.h"
#include "ui_interface.h"
#include "wallet/wallet.h"
#include "wallet/walletdb.h"
#include "chain/chain.h"
#include "rpc/bitcoinrpc.h"
#include "noui.h"

#include "util/util.h"
#include "util/utilexceptions.h"
#include "util/random.h"

#include "p2p/netutils.h"
#include "p2p/proxyutils.h"

#include "daemon.h"

#include <string>
#include <string.h>

#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>
#include <boost/filesystem/convenience.hpp>
#include <boost/interprocess/sync/file_lock.hpp>
#include <boost/algorithm/string/predicate.hpp>
#include <openssl/crypto.h>

#include <boost/thread/thread.hpp>
#include <boost/algorithm/string/replace.hpp>

#ifndef WIN32
#include <signal.h>
#endif

using namespace std;
using namespace boost;

std::unique_ptr<CConnman> pconnman;
CWallet* pwalletMain;
Checkpoints* pcheckpointMain;
ServiceFlags nLocalServices = NODE_NETWORK;
CClientUIInterface uiInterface;

std::string strWalletFileName;
bool fConfChange;
bool fEnforceCanonical;
unsigned int nNodeLifespan;
unsigned int nDerivationMethodIndex;
bool fUseFastIndex;
boost::condition_variable cvBlockChange;

bool static InitWarning(const std::string &str)
{
    uiInterface.ThreadSafeMessageBox(str, _("ECCoin"), CClientUIInterface::BTN_OK | CClientUIInterface::ICON_WARNING | CClientUIInterface::MODAL);
    return true;
}

/** Show error message **/
bool InitError(const std::string& str)
{
    uiInterface.ThreadSafeMessageBox(str, "", CClientUIInterface::MSG_ERROR);
    return false;
}



void HandleSIGTERM(int)
{
    fRequestShutdown = true;
}

void HandleSIGHUP(int)
{
    fReopenDebugLog = true;
}

boost::thread_group ecc_threads;


bool AppInitBasicSetup()
{
    // ********************************************************* Step 1: setup
#ifdef _MSC_VER
    // Turn off Microsoft heap dump noise
    _CrtSetReportMode(_CRT_WARN, _CRTDBG_MODE_FILE);
    _CrtSetReportFile(_CRT_WARN, CreateFileA("NUL", GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, 0));
#endif
#if _MSC_VER >= 1400
    // Disable confusing "helpful" text message on abort, Ctrl-C
    _set_abort_behavior(0, _WRITE_ABORT_MSG | _CALL_REPORTFAULT);
#endif
#ifdef WIN32
    // Enable Data Execution Prevention (DEP)
    // Minimum supported OS versions: WinXP SP3, WinVista >= SP1, Win Server 2008
    // A failure is non-critical and needs no further attention!
#ifndef PROCESS_DEP_ENABLE
    // We define this here, because GCCs winbase.h limits this to _WIN32_WINNT >= 0x0601 (Windows 7),
    // which is not correct. Can be removed, when GCCs winbase.h is fixed!
#define PROCESS_DEP_ENABLE 0x00000001
#endif
    typedef BOOL (WINAPI *PSETPROCDEPPOL)(DWORD);
    PSETPROCDEPPOL setProcDEPPol = (PSETPROCDEPPOL)GetProcAddress(GetModuleHandleA("Kernel32.dll"), "SetProcessDEPPolicy");
    if (setProcDEPPol != NULL) setProcDEPPol(PROCESS_DEP_ENABLE);
#endif

#ifdef WIN32
    // Initialize Windows Sockets
    WSADATA wsadata;
    int ret = WSAStartup(MAKEWORD(2,2), &wsadata);
    if (ret != NO_ERROR || LOBYTE(wsadata.wVersion ) != 2 || HIBYTE(wsadata.wVersion) != 2)
        return InitError("Initializing networking failed");
#endif

#ifndef WIN32
    umask(077);

    // Clean shutdown on SIGTERM
    struct sigaction sa;
    sa.sa_handler = HandleSIGTERM;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);

    // Reopen debug.log on SIGHUP
    struct sigaction sa_hup;
    sa_hup.sa_handler = HandleSIGHUP;
    sigemptyset(&sa_hup.sa_mask);
    sa_hup.sa_flags = 0;
    sigaction(SIGHUP, &sa_hup, NULL);
#endif

    return true;
}

// Parameter interaction based on rules
bool InitParameterInteraction()
{
    pcheckpointMain = new Checkpoints();
    nNodeLifespan = GetArg("-addrlifespan", 7);
    fUseFastIndex = GetBoolArg("-fastindex", true);

    nDerivationMethodIndex = 0;

    // when specifying an explicit binding address, you want to listen on it
    // even when -connect or -proxy is specified
    if (IsArgSet("-bind")) {
        if (SoftSetBoolArg("-listen", true))
            LogPrintf("%s: parameter interaction: -bind set -> setting -listen=1\n", __func__);
    }

    if (IsArgSet("-connect")) {
        // when only connecting to trusted nodes, do not seed via DNS, or listen by default
        if (SoftSetBoolArg("-dnsseed", false))
            LogPrintf("%s: parameter interaction: -connect set -> setting -dnsseed=0\n", __func__);
        if (SoftSetBoolArg("-listen", false))
            LogPrintf("%s: parameter interaction: -connect set -> setting -listen=0\n", __func__);
    }

    if (IsArgSet("-proxy")) {
        // to protect privacy, do not listen by default if a default proxy server is specified
        if (SoftSetBoolArg("-listen", false))
            LogPrintf("%s: parameter interaction: -proxy set -> setting -listen=0\n", __func__);
        // to protect privacy, do not use UPNP when a proxy is set. The user may still specify -listen=1
        // to listen locally, so don't rely on this happening through -listen below.
        if (SoftSetBoolArg("-upnp", false))
            LogPrintf("%s: parameter interaction: -proxy set -> setting -upnp=0\n", __func__);
        // to protect privacy, do not discover addresses by default
        if (SoftSetBoolArg("-discover", false))
            LogPrintf("%s: parameter interaction: -proxy set -> setting -discover=0\n", __func__);
    }

    if (!GetBoolArg("-listen", true)) {
        // do not map ports or try to retrieve public IP when not listening (pointless)
        if (SoftSetBoolArg("-upnp", false))
            LogPrintf("%s: parameter interaction: -listen=0 -> setting -upnp=0\n", __func__);
        if (SoftSetBoolArg("-discover", false))
            LogPrintf("%s: parameter interaction: -listen=0 -> setting -discover=0\n", __func__);
        if (SoftSetBoolArg("-listenonion", false))
            LogPrintf("%s: parameter interaction: -listen=0 -> setting -listenonion=0\n", __func__);
    }

    if (IsArgSet("-externalip")) {
        // if an explicit public IP is specified, do not try to find others
        if (SoftSetBoolArg("-discover", false))
            LogPrintf("%s: parameter interaction: -externalip set -> setting -discover=0\n", __func__);
    }

    // ********************************************************* Step 3: parameter-to-internal-flags

    if(GetBoolArg("-debug", false))
    {
        fDebugNet = true;
    }
    else
    {
        fDebugNet = GetBoolArg("-debugnet", false);
    }

    fDaemon = GetBoolArg("-daemon");

    if (IsArgSet("-paytxfee"))
    {
        if (!ParseMoney(GetArg("-paytxfee", "0"), nTransactionFee))
            return InitError(strprintf(_("Invalid amount for -paytxfee=<amount>: '%s'"), GetArg("-paytxfee", "0").c_str()));
        if (nTransactionFee > 0.25 * COIN)
            InitWarning(_("Warning: -paytxfee is set very high! This is the transaction fee you will pay if you send a transaction."));
    }

    fConfChange = GetBoolArg("-confchange", false);
    fEnforceCanonical = GetBoolArg("-enforcecanonical", true);

    if (IsArgSet("-mininput"))
    {
        if (!ParseMoney(GetArg("-mininput", "0"), nMinimumInputValue))
            return InitError(strprintf(_("Invalid amount for -mininput=<amount>: '%s'"), GetArg("-mininput", "0").c_str()));
    }
    return true;
}

std::string LicenseInfo()
{
    const std::string URL_SOURCE_CODE = "<https://github.com/greg-griffith/eccoin>";
    const std::string URL_WEBSITE = "<https://www.cryptounited.io>";

    return "\n" +
           strprintf(_("Please contribute if you find %s useful. "
                       "Visit %s for further information about the software."),
               "", URL_WEBSITE) +
           "\n" +
           strprintf(_("The source code is available from %s."),
               URL_SOURCE_CODE) +
           "\n" +
           "\n" +
           _("This is experimental software.") + "\n" +
           strprintf(_("Distributed under the MIT software license, see the accompanying file %s or %s"), "COPYING", "<https://opensource.org/licenses/MIT>") + "\n" +
           "\n" +
           strprintf(_("This product includes software developed by the OpenSSL Project for use in the OpenSSL Toolkit %s and cryptographic software written by Eric Young and UPnP software written by Thomas Bernard."), "<https://www.openssl.org>") +
           "\n";
}


bool static Bind(const CService &addr, bool fError = true) {
    if (IsLimited(addr))
        return false;
    std::string strError;
    if (!BindListenPort(addr, strError)) {
        if (fError)
            return InitError(strError);
        return false;
    }
    return true;
}

// Core-specific options shared between UI and daemon
std::string HelpMessage()
{   
    string strUsage = _("Options:") + "\n" +
        "  -?                     " + _("This help message") + "\n" +
        "  -conf=<file>           " + _("Specify configuration file (default: ECCoin.conf)") + "\n" +
        "  -pid=<file>            " + _("Specify pid file (default: ECCoind.pid)") + "\n" +
        "  -datadir=<dir>         " + _("Specify data directory") + "\n" +
        "  -wallet=<dir>          " + _("Specify wallet file (within data directory)") + "\n" +
        "  -dbcache=<n>           " + _("Set database cache size in megabytes (default: 25)") + "\n" +
        "  -dblogsize=<n>         " + _("Set database disk log size in megabytes (default: 100)") + "\n" +
        "  -timeout=<n>           " + _("Specify connection timeout in milliseconds (default: 5000)") + "\n" +
        "  -proxy=<ip:port>       " + _("Connect through socks proxy") + "\n" +
        "  -socks=<n>             " + _("Select the version of socks proxy to use (4-5, default: 5)") + "\n" +
        "  -tor=<ip:port>         " + _("Use proxy to reach tor hidden services (default: same as -proxy)") + "\n"
        "  -dns                   " + _("Allow DNS lookups for -addnode, -seednode and -connect") + "\n" +
        "  -port=<port>           " + _("Listen for connections on <port> (default: 19118 or testnet: 29118)") + "\n" +
        "  -maxconnections=<n>    " + _("Maintain at most <n> connections to peers (default: 125)") + "\n" +
        "  -addnode=<ip>          " + _("Add a node to connect to and attempt to keep the connection open") + "\n" +
        "  -connect=<ip>          " + _("Connect only to the specified node(s)") + "\n" +
        "  -seednode=<ip>         " + _("Connect to a node to retrieve peer addresses, and disconnect") + "\n" +
        "  -externalip=<ip>       " + _("Specify your own public address") + "\n" +
        "  -onlynet=<net>         " + _("Only connect to nodes in network <net> (IPv4, IPv6 or Tor)") + "\n" +
        "  -discover              " + _("Discover own IP address (default: 1 when listening and no -externalip)") + "\n" +
        "  -irc                   " + _("Find peers using internet relay chat (default: 0)") + "\n" +
        "  -listen                " + _("Accept connections from outside (default: 1 if no -proxy or -connect)") + "\n" +
        "  -bind=<addr>           " + _("Bind to given address. Use [host]:port notation for IPv6") + "\n" +
        "  -dnsseed               " + _("Find peers using DNS lookup (default: 1)") + "\n" +
        "  -staking               " + _("Stake your coins to support network and gain reward (default: 1)") + "\n" +
        "  -synctime              " + _("Sync time with other nodes. Disable if time on your system is precise e.g. syncing with NTP (default: 1)") + "\n" +
        "  -cppolicy              " + _("Sync checkpoints policy (default: strict)") + "\n" +
        "  -banscore=<n>          " + _("Threshold for disconnecting misbehaving peers (default: 100)") + "\n" +
        "  -bantime=<n>           " + _("Number of seconds to keep misbehaving peers from reconnecting (default: 86400)") + "\n" +
        "  -maxreceivebuffer=<n>  " + _("Maximum per-connection receive buffer, <n>*1000 bytes (default: 5000)") + "\n" +
        "  -maxsendbuffer=<n>     " + _("Maximum per-connection send buffer, <n>*1000 bytes (default: 1000)") + "\n" +
#ifdef USE_UPNP
#if USE_UPNP
        "  -upnp                  " + _("Use UPnP to map the listening port (default: 1 when listening)") + "\n" +
#else
        "  -upnp                  " + _("Use UPnP to map the listening port (default: 0)") + "\n" +
#endif
#endif
        "  -detachdb              " + _("Detach block and address databases. Increases shutdown time (default: 0)") + "\n" +
        "  -paytxfee=<amt>        " + _("Fee per KB to add to transactions you send") + "\n" +
        "  -mininput=<amt>        " + _("When creating transactions, ignore inputs with value less than this (default: 0.01)") + "\n" +
#ifdef QT_GUI
        "  -server                " + _("Accept command line and JSON-RPC commands") + "\n" +
#endif
#if !defined(WIN32) && !defined(QT_GUI)
        "  -daemon                " + _("Run in the background as a daemon and accept commands") + "\n" +
#endif
        "  -testnet               " + _("Use the test network") + "\n" +
        "  -debug                 " + _("Output extra debugging information. Implies all other -debug* options") + "\n" +
        "  -debugnet              " + _("Output extra network debugging information") + "\n" +
        "  -logtimestamps         " + _("Prepend debug output with timestamp") + "\n" +
        "  -shrinkdebugfile       " + _("Shrink debug.log file on client startup (default: 1 when no -debug)") + "\n" +
        "  -fDebugNet          " + _("Print messaging debug statements to log file (default: 0 (will not do it unless it is enabled)") + "\n" +
        "  -printtoconsole        " + _("Send trace/debug info to console instead of debug.log file") + "\n" +
#ifdef WIN32
        "  -printtodebugger       " + _("Send trace/debug info to debugger") + "\n" +
#endif
        "  -rpcuser=<user>        " + _("Username for JSON-RPC connections") + "\n" +
        "  -rpcpassword=<pw>      " + _("Password for JSON-RPC connections") + "\n" +
        "  -rpcport=<port>        " + _("Listen for JSON-RPC connections on <port> (default: 52015 or testnet: 52017)") + "\n" +
        "  -rpcallowip=<ip>       " + _("Allow JSON-RPC connections from specified IP address") + "\n" +
        "  -rpcconnect=<ip>       " + _("Send commands to node running on <ip> (default: 127.0.0.1)") + "\n" +
        "  -blocknotify=<cmd>     " + _("Execute command when the best block changes (%s in cmd is replaced by block hash)") + "\n" +
        "  -walletnotify=<cmd>    " + _("Execute command when a wallet transaction changes (%s in cmd is replaced by TxID)") + "\n" +
        "  -confchange            " + _("Require a confirmations for change (default: 0)") + "\n" +
        "  -enforcecanonical      " + _("Enforce transaction scripts to use canonical PUSH operators (default: 1)") + "\n" +
        "  -alertnotify=<cmd>     " + _("Execute command when a relevant alert is received (%s in cmd is replaced by message)") + "\n" +
        "  -upgradewallet         " + _("Upgrade wallet to latest format") + "\n" +
        "  -keypool=<n>           " + _("Set key pool size to <n> (default: 100)") + "\n" +
        "  -rescan                " + _("Rescan the block chain for missing wallet transactions") + "\n" +
        "  -salvagewallet         " + _("Attempt to recover private keys from a corrupt wallet.dat") + "\n" +
        "  -checkblocks=<n>       " + _("How many blocks to check at startup (default: 2500, 0 = all)") + "\n" +
        "  -checklevel=<n>        " + _("How thorough the block verification is (0-6, default: 1)") + "\n" +
        "  -loadblock=<file>      " + _("Imports blocks from external blk000?.dat file") + "\n" +

        "\n" + _("Block creation options:") + "\n" +
        "  -blockminsize=<n>      "   + _("Set minimum block size in bytes (default: 0)") + "\n" +
        "  -blockmaxsize=<n>      "   + _("Set maximum block size in bytes (default: 250000)") + "\n" +
        "  -blockprioritysize=<n> "   + _("Set maximum size of high-priority/low-fee transactions in bytes (default: 27000)") + "\n" +

        "\n" + _("SSL options: (see the Bitcoin Wiki for SSL setup instructions)") + "\n" +
        "  -rpcssl                                  " + _("Use OpenSSL (https) for JSON-RPC connections") + "\n" +
        "  -rpcsslcertificatechainfile=<file.cert>  " + _("Server certificate file (default: server.cert)") + "\n" +
        "  -rpcsslprivatekeyfile=<file.pem>         " + _("Server private key (default: server.pem)") + "\n" +
        "  -rpcsslciphers=<ciphers>                 " + _("Acceptable ciphers (default: TLSv1+HIGH:!SSLv2:!aNULL:!eNULL:!AH:!3DES:@STRENGTH)") + "\n";

    return strUsage;
}

bool AppInit2()
{
    // ********************************************************* Step 4: application initialization: dir lock, daemonize, pidfile, debug log

    std::string strDataDir = GetDataDir().string();
    std::string strWalletFileName = GetArg("-wallet", "wallet.dat");
    // strWalletFileName must be a plain filename without a directory
    if (strWalletFileName != boost::filesystem::basename(strWalletFileName) + boost::filesystem::extension(strWalletFileName))
        return InitError(strprintf(_("Wallet %s resides outside data directory %s."), strWalletFileName.c_str(), strDataDir.c_str()));
    // Make sure only a single E-CurrencyCoin process is using the data directory.
    boost::filesystem::path pathLockFile = GetDataDir() / ".lock";
    FILE* file = fopen(pathLockFile.string().c_str(), "a"); // empty lock file; created if it doesn't exist.
    if (file) fclose(file);
    static boost::interprocess::file_lock lock(pathLockFile.string().c_str());
    if (!lock.try_lock())
        return InitError(strprintf(_("Cannot obtain a lock on data directory %s. This Coin is probably already running."), strDataDir.c_str()));
#if !defined(WIN32)
    if (fDaemon)
    {
        // Daemonize
        pid_t pid = fork();
        if (pid < 0)
        {
            fprintf(stderr, "Error: fork() returned %d errno %d\n", pid, errno);
            return false;
        }
        if (pid > 0)
        {
            CreatePidFile(GetPidFile(), pid);
            return true;
        }

        pid_t sid = setsid();
        if (sid < 0)
            fprintf(stderr, "Error: setsid() returned %d errno %d\n", sid, errno);
    }
#endif
    ShrinkDebugFile();
    if (fPrintToDebugLog)
        OpenDebugLog();
    LogPrintf("\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n");
    LogPrintf("ECCoin version %s (%s)\n", FormatFullVersion().c_str(), CLIENT_DATE.c_str());
    LogPrintf("Using OpenSSL version %s\n", SSLeay_version(SSLEAY_VERSION));
    if (!fLogTimestamps)
        LogPrintf("Startup time: %s\n", DateTimeStrFormat("%x %H:%M:%S", GetTime()).c_str());
    LogPrintf("Default data directory %s\n", GetDefaultDataDir().string().c_str());
    LogPrintf("Used data directory %s\n", strDataDir.c_str());
    std::ostringstream strErrors;
    if (fDaemon)
        fprintf(stdout, "ECCoin server starting\n");
    int64_t nStart;

    // ********************************************************* Step 5: verify database integrity

    if (!bitdb.Open(GetDataDir()))
    {
        string msg = strprintf(_("Error initializing database environment %s!"
                                 " To recover, BACKUP THAT DIRECTORY, then remove"
                                 " everything fseedsat."), strDataDir.c_str());
        return InitError(msg);
    }
    if (GetBoolArg("-salvagewallet", false))
    {
        // Recover readable keypairs:
        if (!CWalletDB::Recover(bitdb, strWalletFileName, true))
            return false;
    }
    if (filesystem::exists(GetDataDir() / strWalletFileName))
    {
        CDBEnv::VerifyResult r = bitdb.Verify(strWalletFileName, CWalletDB::Recover);
        if (r == CDBEnv::RECOVER_OK)
        {
            string msg = strprintf(_("Warning: wallet.dat corrupt, data salvaged!"
                                     " Original wallet.dat saved as wallet.{timestamp}.bak in %s; if"
                                     " your balance or transactions are incorrect you should"
                                     " restore from a backup."), strDataDir.c_str());
            uiInterface.ThreadSafeMessageBox(msg, _("ECCoin"), CClientUIInterface::BTN_OK | CClientUIInterface::ICON_WARNING | CClientUIInterface::MODAL);
        }
        if (r == CDBEnv::RECOVER_FAIL)
            return InitError(_("wallet.dat corrupt, salvage failed"));
    }

    // ********************************************************* Step 6: network initialization

    int nSocksVersion = GetArg("-socks", 5);
    if (nSocksVersion != 4 && nSocksVersion != 5)
        return InitError(strprintf(_("Unknown -socks proxy version requested: %i"), nSocksVersion));
    if (IsArgSet("-onlynet")) {
        std::set<enum Network> nets;
        BOOST_FOREACH(std::string snet, gArgs.GetArgs("-onlynet")) {
            enum Network net = ParseNetwork(snet);
            if (net == NET_UNROUTABLE)
                return InitError(strprintf(_("Unknown network specified in -onlynet: '%s'"), snet.c_str()));
            nets.insert(net);
        }
        for (int n = 0; n < NET_MAX; n++) {
            enum Network net = (enum Network)n;
            if (!nets.count(net))
                SetLimited(net);
        }
    }
#if defined(USE_IPV6)
#if ! USE_IPV6
    else
        SetLimited(NET_IPV6);
#endif
#endif
    CService addrProxy;
    bool fProxy = false;
    if (IsArgSet("-proxy")) {
        addrProxy = CService(GetArg("-proxy", "0"), 9050);
        if (!addrProxy.IsValid())
            return InitError(strprintf(_("Invalid -proxy address: '%s'"), GetArg("-proxy", "0").c_str()));

        if (!IsLimited(NET_IPV4))
            SetProxy(NET_IPV4, addrProxy, nSocksVersion);
        if (nSocksVersion > 4) {
#ifdef USE_IPV6
            if (!IsLimited(NET_IPV6))
                SetProxy(NET_IPV6, addrProxy, nSocksVersion);
#endif
            SetNameProxy(addrProxy, nSocksVersion);
        }
        fProxy = true;
    }
    // -tor can override normal proxy, -notor disables tor entirely
    if (!(IsArgSet("-tor") && GetArg("-tor", "") == "0") && (fProxy || IsArgSet("-tor"))) {
        CService addrOnion;
        if (!IsArgSet("-tor"))
            addrOnion = addrProxy;
        else
            addrOnion = CService(GetArg("-tor", "0"), 9050);
        if (!addrOnion.IsValid())
            return InitError(strprintf(_("Invalid -tor address: '%s'"), GetArg("-tor", "0").c_str()));
        SetProxy(NET_TOR, addrOnion, 5);
        SetReachable(NET_TOR);
   }
    // see Step 2: parameter interactions for more information about these
    fNoListen = !GetBoolArg("-listen", true);
    fDiscover = GetBoolArg("-discover", true);
    fNameLookup = GetBoolArg("-dns", true);
#ifdef USE_UPNP
    fUseUPnP = GetBoolArg("-upnp", USE_UPNP);
#endif
    bool fBound = false;
    if (!fNoListen)
    {
        std::string strError;
        if (IsArgSet("-bind")) {
				std::vector<std::string> binds = gArgs.GetArgs("-bind");
            BOOST_FOREACH(std::string strBind, binds) {
                CService addrBind;
                if (!Lookup(strBind.c_str(), addrBind, GetListenPort(), false))
                    return InitError(strprintf(_("Cannot resolve -bind address: '%s'"), strBind.c_str()));
                fBound |= Bind(addrBind);
            }
        } else {
            struct in_addr inaddr_any;
            inaddr_any.s_addr = INADDR_ANY;
#ifdef USE_IPV6
            if (!IsLimited(NET_IPV6))
                fBound |= Bind(CService(in6addr_any, GetListenPort()), false);
#endif
            if (!IsLimited(NET_IPV4))
                fBound |= Bind(CService(inaddr_any, GetListenPort()), !fBound);
        }
        if (!fBound)
            return InitError(_("Failed to listen on any port. Use -listen=0 if you want this."));
    }
    if (IsArgSet("-externalip"))
    {
		  std::vector<std::string> externals = gArgs.GetArgs("-externalip");
        BOOST_FOREACH(string strAddr, externals) {
            CService addrLocal(strAddr, GetListenPort(), fNameLookup);
            if (!addrLocal.IsValid())
                return InitError(strprintf(_("Cannot resolve -externalip address: '%s'"), strAddr.c_str()));
            AddLocal(CService(strAddr, GetListenPort(), fNameLookup), LOCAL_MANUAL);
        }
    }
    if(IsArgSet("-seednode"))
    {
        std::vector<std::string> seeds = gArgs.GetArgs("-seednode");
    	BOOST_FOREACH(string strDest, seeds)
        	AddOneShot(strDest);
    }

    // ********************************************************* Step 7: load blockchain

    if (!bitdb.Open(GetDataDir()))
    {
        string msg = strprintf(_("Error initializing database environment %s!"
                                 " To recover, BACKUP THAT DIRECTORY, then remove"
                                 " everything from it except for wallet.dat."), strDataDir.c_str());
        return InitError(msg);
    }
    LogPrintf("Loading block index...\n");
    nStart = GetTimeMillis();
    if (!LoadBlockIndex())
        return InitError(_("Error loading blkindex.dat"));
    LogPrintf(" block index %d ms\n", GetTimeMillis() - nStart);

    // ********************************************************* Step 8: load wallet

    LogPrintf("Loading wallet...\n");
    nStart = GetTimeMillis();
    bool fFirstRun = true;
    pwalletMain = new CWallet(strWalletFileName);
    DBErrors nLoadWalletRet = pwalletMain->LoadWallet(fFirstRun);
    if (nLoadWalletRet != DB_LOAD_OK)
    {
        if (nLoadWalletRet == DB_CORRUPT)
            strErrors << _("Error loading wallet.dat: Wallet corrupted") << "\n";
        else if (nLoadWalletRet == DB_NONCRITICAL_ERROR)
        {
            string msg(_("Warning: error reading wallet.dat! All keys read correctly, but transaction data"
                         " or address book entries might be missing or incorrect."));
            uiInterface.ThreadSafeMessageBox(msg, _("ECCoin"), CClientUIInterface::BTN_OK | CClientUIInterface::ICON_WARNING | CClientUIInterface::MODAL);
        }
        else if (nLoadWalletRet == DB_TOO_NEW)
            strErrors << _("Error loading wallet.dat: Wallet requires newer version, try running wallet with upgradewallet one time") << "\n";
        else if (nLoadWalletRet == DB_NEED_REWRITE)
        {
            strErrors << _("Wallet needed to be rewritten: restart ECCoin to complete") << "\n";
            LogPrintf("%s", strErrors.str().c_str());
            return InitError(strErrors.str());
        }
        else
        {
            strErrors << _("Error loading wallet.dat") << "\n";
        }
        if (!strErrors.str().empty())
            return InitError(strErrors.str());
    }
    if (GetBoolArg("-upgradewallet", fFirstRun))
    {
        int nMaxVersion = GetArg("-upgradewallet", 0);
        if (nMaxVersion == 0) // the -upgradewallet without argument case
        {
            LogPrintf("Performing wallet upgrade to %i\n", FEATURE_LATEST);
            nMaxVersion = CLIENT_VERSION;
            pwalletMain->SetMinVersion(FEATURE_LATEST); // permanently upgrade the wallet immediately
        }
        else
            LogPrintf("Allowing wallet upgrade up to %i\n", nMaxVersion);
        if (nMaxVersion < pwalletMain->GetVersion())
        {
            strErrors << _("Cannot downgrade wallet") << "\n";
        }
        pwalletMain->SetMaxVersion(nMaxVersion);
        if (!strErrors.str().empty())
            return InitError(strErrors.str());
    }
    if (fFirstRun)
    {
        // Create new keyUser and set as default key
        RandAddSeedPerfmon();
        CPubKey newDefaultKey;
        if (!pwalletMain->GetKeyFromPool(newDefaultKey, false))
            strErrors << _("Cannot initialize keypool") << "\n";
        pwalletMain->SetDefaultKey(newDefaultKey);
        if (!pwalletMain->SetAddressBookName(pwalletMain->vchDefaultKey.GetID(), ""))
            strErrors << _("Cannot write default address") << "\n";
    }
    LogPrintf("%s", strErrors.str().c_str());
    LogPrintf(" wallet %I64d ms\n", GetTimeMillis() - nStart);
    RegisterWallet(pwalletMain);
    CBlockIndex* pindexRescan = pindexBest;
    if (GetBoolArg("-rescan", false))
        pindexRescan = pindexGenesisBlock;
    else
    {
        CWalletDB walletdb(pwalletMain->GetDBHandle());
        CBlockLocator locator;
        if (walletdb.ReadBestBlock(locator))
            pindexRescan = pindexBest;
    }
    if (pindexBest != pindexRescan && pindexBest && pindexRescan && pindexBest->nHeight > pindexRescan->nHeight)
    {
        LogPrintf("pindexBest: %i, pindexRescan %i \n", pindexBest->nHeight, pindexRescan->nHeight);
        LogPrintf("Rescanning last %i blocks (from block %i)...\n", pindexBest->nHeight - pindexRescan->nHeight, pindexRescan->nHeight);
        nStart = GetTimeMillis();
        pwalletMain->ScanForWalletTransactions(pindexRescan, true);
        LogPrintf(" rescan %I64d ms\n", GetTimeMillis() - nStart);
    }

    // ********************************************************* Step 9: load peers

    LogPrintf("Loading addresses...\n");
    nStart = GetTimeMillis();
    {
        CAddrDB adb;
        if (!adb.Read(addrman))
            LogPrintf("Invalid or missing peers.dat; recreating\n");
    }
    LogPrintf("Loaded %i addresses from peers.dat  %I64d ms\n", addrman.size(), GetTimeMillis() - nStart);

    // ********************************************************* Step 10: start node

    if (!CheckDiskSpace())
        return false;
    RandAddSeedPerfmon();
    //// debug print
    LogPrintf("mapBlockIndex.size() = %u \n",   mapBlockIndex.size());
    LogPrintf("nBestHeight = %d\n",                     pindexBest->nHeight);
    LogPrintf("setKeyPool.size() = %u \n",      pwalletMain->setKeyPool.size());
    LogPrintf("mapWallet.size() = %u \n",       pwalletMain->mapWallet.size());
    LogPrintf("mapAddressBook.size() = %u \n",  pwalletMain->mapAddressBook.size());

    boost::thread* startNode = new boost::thread(&StartNode);
    ecc_threads.add_thread(startNode);
    boost::thread* RCPServer = new boost::thread(&ThreadRPCServer);
    ecc_threads.add_thread(RCPServer);

    // ********************************************************* Step 11: finished

    LogPrintf("Done loading\n");
    if (!strErrors.str().empty())
        return InitError(strErrors.str());
    // Add wallet transactions that aren't already in a block to mapTransactions
    pwalletMain->ReacceptWalletTransactions();
    // Loop until process is exit()ed from shutdown() function,
    // called from ThreadRPCServer thread when a "stop" command is received.
    while (1)
        MilliSleep(5000);
    return true;
}


static const int MAX_OUTBOUND_CONNECTIONS = 1000;

void StartNode()
{
        LogPrintf("NodeStarted\n");
        // Make this thread recognisable as the startup thread
        RenameThread("ECCoin-start");

        if (semOutbound == NULL)
        {
            // initialize semaphore
            int nMaxOutbound = MAX_OUTBOUND_CONNECTIONS;
            semOutbound = new CSemaphore(nMaxOutbound);
        }

        if (!fDiscover)
            return;
#ifdef WIN32
        // Get local host IP
        char pszHostName[1000] = "";
        if (gethostname(pszHostName, sizeof(pszHostName)) != SOCKET_ERROR)
        {
            vector<CNetAddr> vaddr;
            if (LookupHost(pszHostName, vaddr))
            {
                BOOST_FOREACH (const CNetAddr &addr, vaddr)
                {
                    AddLocal(addr, LOCAL_IF);
                }
            }
        }
#else
        // Get local host ip
        struct ifaddrs* myaddrs;
        if (getifaddrs(&myaddrs) == 0)
        {
            for (struct ifaddrs* ifa = myaddrs; ifa != NULL; ifa = ifa->ifa_next)
            {
                if (ifa->ifa_addr == NULL) continue;
                if ((ifa->ifa_flags & IFF_UP) == 0) continue;
                if (strcmp(ifa->ifa_name, "lo") == 0) continue;
                if (strcmp(ifa->ifa_name, "lo0") == 0) continue;
                if (ifa->ifa_addr->sa_family == AF_INET)
                {
                    struct sockaddr_in* s4 = (struct sockaddr_in*)(ifa->ifa_addr);
                    CNetAddr addr(s4->sin_addr);
                    if (AddLocal(addr, LOCAL_IF))
                        LogPrintf("IPv4 %s: %s\n", ifa->ifa_name, addr.ToString().c_str());
                }
#ifdef USE_IPV6
                else if (ifa->ifa_addr->sa_family == AF_INET6)
                {
                    struct sockaddr_in6* s6 = (struct sockaddr_in6*)(ifa->ifa_addr);
                    CNetAddr addr(s6->sin6_addr);
                    if (AddLocal(addr, LOCAL_IF))
                        LogPrintf("IPv6 %s: %s\n", ifa->ifa_name, addr.ToString().c_str());
                }
#endif
            }
            freeifaddrs(myaddrs);
        }
#endif

        // Don't use external IPv4 discovery, when -onlynet="IPv6"
        if (!IsLimited(NET_IPV4))
        {
            CNetAddr addrLocalHost;
            if (GetMyExternalIP(addrLocalHost))
            {
                LogPrintf("GetMyExternalIP() returned %s\n", addrLocalHost.ToStringIP().c_str());
                AddLocal(addrLocalHost, LOCAL_HTTP);
            }
        }
        //
        // Start threads
        //

        // Map ports with UPnP
        if (fUseUPnP)
            MapPort();


        // Mine proof-of-stake blocks in the background
        if (!GetBoolArg("-staking", false))
            LogPrintf("Staking disabled\n");
        else
        {
        //    boost::thread* StakeMinter_Scrypt = new boost::thread(boost::bind(&ThreadStakeMinter_Scrypt, pwalletMain));
        //    ecc_threads.add_thread(StakeMinter_Scrypt);
        }
}




/////////////////////////////////////////////////////////////////////
//
// Start
//
int main(int argc, char* argv[])
{
#ifdef HAVE_MALLOPT_ARENA_MAX
    // glibc-specific: On 32-bit systems set the number of arenas to 1.
    // By default, since glibc 2.10, the C library will create up to two heap
    // arenas per core. This is known to cause excessive virtual address space
    // usage in our usage. Work around it by setting the maximum number of
    // arenas to 1.
    if (sizeof(void*) == 4) {
        mallopt(M_ARENA_MAX, 1);
    }
#endif
    // On most POSIX systems (e.g. Linux, but not BSD) the environment's locale
    // may be invalid, in which case the "C" locale is used as fallback.
#if !defined(WIN32) && !defined(MAC_OSX) && !defined(__FreeBSD__) && !defined(__OpenBSD__)
    try {
        std::locale(""); // Raises a runtime error if current locale is invalid
    } catch (const std::runtime_error&) {
        setenv("LC_ALL", "C", 1);
    }
#endif
    // The path locale is lazy initialized and to avoid deinitialization errors
    // in multithreading environments, it is set explicitly by the main thread.
    // A dummy locale is used to extract the internal default locale, used by
    // fs::path, which is then used to explicitly imbue the path.
    std::locale loc = fs::path::imbue(std::locale::classic());
    fs::path::imbue(loc);

    // Connect ECCoind signal handlers
    noui_connect();

    bool fRet = false;
    //
    // Parameters
    //
    ParseParameters(argc, argv);

    // Process help and version before taking care about datadir
    if (IsArgSet("-?") || IsArgSet("-h") ||  IsArgSet("-help") || IsArgSet("-version"))
    {
        std::string strUsage = strprintf(_("%s Daemon"), _("E-Currency Coin")) + " " + _("version") + " " + FormatFullVersion() + "\n";
        if (IsArgSet("-version"))
        {
            strUsage += FormatParagraph(LicenseInfo());
        }
        else
        {
            strUsage += "\n" + _("Usage:") + "\n" +
                  "  ECCoind [options]  " + strprintf(_("Start %s Daemon"), _("E-Currency Coin")) + "\n";
            strUsage += "\n" + HelpMessage();
        }
        fprintf(stdout, "%s", strUsage.c_str());
        return true;
    }
    bool fCommandLine = false;
    try
    {
        if (!fs::is_directory(GetDataDir(false)))
        {
            fprintf(stderr, "Error: Specified data directory \"%s\" does not exist.\n", GetArg("-datadir", "").c_str());
            exit(EXIT_FAILURE);
        }
        try
        {
            ReadConfigFile();
        }
        catch (const std::exception& e)
        {
            fprintf(stderr,"Error reading configuration file: %s\n", e.what());
            exit(EXIT_FAILURE);
        }
        // Command-line RPC
        for (int i = 1; i < argc; i++)
            if (!IsSwitchChar(argv[i][0]) && !boost::algorithm::istarts_with(argv[i], "ECCoin:"))
                fCommandLine = true;
        if (fCommandLine)
        {
            int ret = CommandLineRPC(argc, argv);
            exit(ret);
        }
        fPrintToConsole = GetBoolArg("-printtoconsole", false);
        fLogTimestamps = GetBoolArg("-logtimestamps", DEFAULT_LOGTIMESTAMPS);
        fLogTimeMicros = GetBoolArg("-logtimemicros", DEFAULT_LOGTIMEMICROS);
        fLogIPs = GetBoolArg("-logips", DEFAULT_LOGIPS);

        LogPrintf("\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n");
        LogPrintf("Bitcoin version %s\n", FormatFullVersion());
        if(!InitParameterInteraction())
        {
            // InitError will have been called with detailed error, which ends up on console
            exit(EXIT_FAILURE);
        }
        if (!AppInitBasicSetup())
        {
            // InitError will have been called with detailed error, which ends up on console
            exit(EXIT_FAILURE);
        }
        fRet = AppInit2();
        if (fRet && fDaemon)
            exit(EXIT_SUCCESS);
    }
    catch (const std::exception& e) {
        PrintExceptionContinue(&e, "AppInit()");
    } catch (...) {
        PrintExceptionContinue(NULL, "AppInit()");
    }
    if (!fRet)
    {
        Shutdown();
        exit(EXIT_FAILURE);
    }
    exit(EXIT_SUCCESS);
}
