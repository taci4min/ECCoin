#include "p2p/node.h"


void ThreadMessageHandler()
{
    try
    {
        ThreadMessageHandler2();
    }
    catch (std::exception& e) {
        PrintException(&e, "ThreadMessageHandler()");
    } catch (...) {
        PrintException(NULL, "ThreadMessageHandler()");
    }
    LogPrintf("ThreadMessageHandler exited\n");
}

void ThreadMessageHandler2()
{
    LogPrintf("ThreadMessageHandler started\n");
    SetThreadPriority(THREAD_PRIORITY_ABOVE_NORMAL);
    while (true)
    {
        vector<CNode*> vNodesCopy;
        {
            LOCK(cs_vNodes);
            vNodesCopy = vNodes;
            BOOST_FOREACH(CNode* pnode, vNodesCopy)
                pnode->AddRef();
        }
        // Poll the connected nodes for messages
        CNode* pnodeTrickle = NULL;
        if (!vNodesCopy.empty())
            pnodeTrickle = vNodesCopy[GetRand(vNodesCopy.size())];
        BOOST_FOREACH(CNode* pnode, vNodesCopy)
        {
            // Receive messages
            {
                TRY_LOCK(pnode->cs_vRecv, lockRecv);
                if (lockRecv)
                {
                    ProcessMessages(pnode);
                }
            }
            // Send messages
            {
                TRY_LOCK(pnode->cs_vSend, lockSend);
                if (lockSend)
                {
                    SendMessages(pnode, pnode == pnodeTrickle);
                }
            }
            if (fShutdown)
                return;
        }
        {
            LOCK(cs_vNodes);
            BOOST_FOREACH(CNode* pnode, vNodesCopy)
                pnode->Release();
        }
        MilliSleep(250);
        if (fRequestShutdown)
            StartShutdown();
        if (fShutdown)
            return;
    }
}


void ThreadOpenAddedConnections()
{
    try
    {
        ThreadOpenAddedConnections2();
    }
    catch (std::exception& e) {
        PrintException(&e, "ThreadOpenAddedConnections()");
    } catch (...) {
        PrintException(NULL, "ThreadOpenAddedConnections()");
    }
    LogPrintf("ThreadOpenAddedConnections exited\n");
}

void ThreadOpenAddedConnections2()
{
    LogPrintf("ThreadOpenAddedConnections started\n");
    if (IsArgSet("-addnode") == 0)
        return;
    if (HaveNameProxy()) {
        while(!fShutdown) {
                std::vector<std::string> strAddNodes = gArgs.GetArgs("-addnode");
            BOOST_FOREACH(string& strAddNode, strAddNodes) {
                CAddress addr;
                CSemaphoreGrant grant(*semOutbound);
                OpenNetworkConnection(addr, &grant, strAddNode.c_str());
                MilliSleep(500);
            }
            MilliSleep(120000); // Retry every 2 minutes
        }
        return;
    }
    std::vector<std::vector<CService> > vservAddressesToAdd(0);
    std::vector<std::string> strAddNodes = gArgs.GetArgs("-addnode");
    BOOST_FOREACH(string& strAddNode, strAddNodes)
    {
        vector<CService> vservNode(0);
        if(Lookup(strAddNode.c_str(), vservNode, GetDefaultPort(), fNameLookup, 0))
        {
            vservAddressesToAdd.push_back(vservNode);
            {
                LOCK(cs_setservAddNodeAddresses);
                BOOST_FOREACH(CService& serv, vservNode)
                    setservAddNodeAddresses.insert(serv);
            }
        }
    }
    while (true)
    {
        std::vector<std::vector<CService> > vservConnectAddresses = vservAddressesToAdd;
        // Attempt to connect to each IP for each addnode entry until at least one is successful per addnode entry
        // (keeping in mind that addnode entries can have many IPs if fNameLookup)
        {
            LOCK(cs_vNodes);
            BOOST_FOREACH(CNode* pnode, vNodes)
            {
                for (vector<vector<CService> >::iterator it = vservConnectAddresses.begin(); it != vservConnectAddresses.end(); it++)
                {
                    BOOST_FOREACH(CService& addrNode, *(it))
                    {
                        if (pnode->addr == addrNode)
                        {
                            it = vservConnectAddresses.erase(it);
                            it--;
                            break;
                        }
                    }
                }
            }
        }
        BOOST_FOREACH(vector<CService>& vserv, vservConnectAddresses)
        {
            CSemaphoreGrant grant(*semOutbound);
            OpenNetworkConnection(CAddress(*(vserv.begin())), &grant);
            MilliSleep(500);
            if (fShutdown)
                return;
        }
        if (fShutdown)
            return;
        MilliSleep(120000); // Retry every 2 minutes
        if (fShutdown)
            return;
    }
}

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

void ThreadOpenConnections()
{
    LogPrintf("ThreadOpenConnections started\n");
    try
    {
        ThreadOpenConnections2();
    }
    catch (std::exception& e) {
        PrintException(&e, "ThreadOpenConnections()");
    } catch (...) {
        PrintException(NULL, "ThreadOpenConnections()");
    }
    LogPrintf("ThreadOpenConnections exited\n");
}

void ThreadOpenConnections2()
{
    if (IsArgSet("-connect") && gArgs.GetArgs("-connect").size() > 0)
    {
        for (int64_t nLoop = 0;; nLoop++)
        {
            ProcessOneShot();
            std::vector<std::string> strAddrs = gArgs.GetArgs("-connect");
            BOOST_FOREACH(std::string strAddr, strAddrs)
            {
                CAddress addr;
                OpenNetworkConnection(addr, NULL, strAddr.c_str());
                for (int i = 0; i < 10 && i < nLoop; i++)
                {
                    MilliSleep(500);
                    if (fShutdown)
                        return;
                }
            }
            MilliSleep(1000);
        }
    }
    int64_t nStart = GetTime();
    while (true)
    {
        ProcessOneShot();
        MilliSleep(1000);
        if (fShutdown)
            return;
        CSemaphoreGrant grant(*semOutbound);
        if (fShutdown)
            return;
        CAddress addrConnect;
        int nOutbound = 0;
        std::set<std::vector<unsigned char> > setConnected;
        {
            LOCK(cs_vNodes);
            BOOST_FOREACH(CNode* pnode, vNodes) {
                if (!pnode->fInbound) {
                    setConnected.insert(pnode->addr.GetGroup());
                    nOutbound++;
                }
            }
        }
        int64_t nANow = GetAdjustedTime();
        int nTries = 0;
        while (true)
        {
            // use an nUnkBias between 10 (no outgoing connections) and 90 (8 outgoing connections)
            CAddress addr = addrman.Select(10 + min(nOutbound,8)*10);
            // if we selected an invalid address, restart
            if (!addr.IsValid() || setConnected.count(addr.GetGroup()) || IsLocal(addr))
                break;
            // If we didn't find an appropriate destination after trying 30 addresses fetched from addrman,
            // stop this loop, and let the outer loop run again (which sleeps, adds seed nodes, recalculates
            // already-connected network ranges, ...) before trying new addrman addresses.
            nTries++;
            if (nTries > 30)
                break;
            if (IsLimited(addr))
                continue;
            // only consider very recently tried nodes after 10 failed attempts
            if (nANow - addr.nLastTry < 600 && nTries < 10)
                continue;
            // do not allow non-default ports, unless after 20 invalid addresses selected already
            if (addr.GetPort() != GetDefaultPort() && nTries < 20)
                continue;
            addrConnect = addr;
            break;
        }
        if (addrConnect.IsValid())
            OpenNetworkConnection(addrConnect, &grant);
    }
}

void ThreadDumpAddress2()
{
    while (!fShutdown)
    {
        int64_t nStart = GetTimeMillis();
        CAddrDB adb;
        adb.Write(addrman);
        LogPrintf("Flushed %d addresses to peers.dat  %d ms\n",
               addrman.size(), GetTimeMillis() - nStart);
        MilliSleep(600000);
    }
}

void ThreadDumpAddress()
{
    try
    {
        ThreadDumpAddress2();
    }
    catch (std::exception& e) {
        PrintException(&e, "ThreadDumpAddress()");
    }
    LogPrintf("ThreadDumpAddress exited\n");
}



// DNS seeds
// Each pair gives a source name and a seed name.
// The first name is used as information source for addrman.
// The second name should resolve to a list of seed addresses.
static const char* strDNSSeed[][2] = {
    {"CryptoUnitedSeed", "www.cryptounited.io"},
    {"ECC-Seed1", "138.197.100.45"},
    {"ECC-Seed2", "159.203.172.212"},
};

void ThreadDNSAddressSeed()
{
    try
    {
        ThreadDNSAddressSeed2();
    }
    catch (std::exception& e) {
        PrintException(&e, "ThreadDNSAddressSeed()");
    } catch (...) {
        throw; // support pthread_cancel()
    }
    LogPrintf("ThreadDNSAddressSeed exited\n");
}

void ThreadDNSAddressSeed2()
{
    LogPrintf("ThreadDNSAddressSeed started\n");
    int found = 0;
    if (!fTestNet)
    {
        LogPrintf("Loading addresses from DNS seeds (could take a while)\n");
        for (unsigned int seed_idx = 0; seed_idx < ARRAYLEN(strDNSSeed); seed_idx++) {
            if (HaveNameProxy())
            {
                AddOneShot(strDNSSeed[seed_idx][1]);
            }
            else
            {
                vector<CNetAddr> vaddr;
                vector<CAddress> vAdd;
                if (LookupHost(strDNSSeed[seed_idx][1], vaddr))
                {
                    BOOST_FOREACH(CNetAddr& ip, vaddr)
                    {
                        int nOneDay = 24*3600;
                        CAddress addr = CAddress(CService(ip, GetDefaultPort()));
                        addr.nTime = GetTime() - 3*nOneDay - GetRand(4*nOneDay); // use a random age between 3 and 7 days old
                        vAdd.push_back(addr);
                        found++;
                    }
                }
                addrman.Add(vAdd, CNetAddr(strDNSSeed[seed_idx][0], true));
            }
        }
    }
    LogPrintf("%d addresses found from DNS seeds\n", found);
}




void ThreadSocketHandler()
{
    try
    {
        ThreadSocketHandler2();
    }
    catch (std::exception& e) {
        PrintException(&e, "ThreadSocketHandler()");
    } catch (...) {
        throw; // support pthread_cancel()
    }
    LogPrintf("ThreadSocketHandler exited\n");
}

void ThreadSocketHandler2()
{
    LogPrintf("ThreadSocketHandler started\n");
    list<CNode*> vNodesDisconnected;
    while (true)
    {
        //
        // Disconnect nodes
        //
        {
            LOCK(cs_vNodes);
            // Disconnect unused nodes
            vector<CNode*> vNodesCopy = vNodes;
            BOOST_FOREACH(CNode* pnode, vNodesCopy)
            {
                if (pnode->fDisconnect ||
                    (pnode->GetRefCount() <= 0 && pnode->vRecv.empty() && pnode->vSend.empty()))
                {
                    // remove from vNodes
                    vNodes.erase(remove(vNodes.begin(), vNodes.end(), pnode), vNodes.end());
                    // release outbound grant (if any)
                    pnode->grantOutbound.Release();
                    // close socket and cleanup
                    pnode->CloseSocketDisconnect();
                    pnode->Cleanup();
                    // hold in disconnected pool until all refs are released
                    if (pnode->fNetworkNode || pnode->fInbound)
                        pnode->Release();
                    vNodesDisconnected.push_back(pnode);
                }
            }

            // Delete disconnected nodes
            list<CNode*> vNodesDisconnectedCopy = vNodesDisconnected;
            BOOST_FOREACH(CNode* pnode, vNodesDisconnectedCopy)
            {
                // wait until threads are done using it
                if (pnode->GetRefCount() <= 0)
                {
                    bool fDelete = false;
                    {
                        TRY_LOCK(pnode->cs_vSend, lockSend);
                        if (lockSend)
                        {
                            TRY_LOCK(pnode->cs_vRecv, lockRecv);
                            if (lockRecv)
                            {
                                TRY_LOCK(pnode->cs_mapRequests, lockReq);
                                if (lockReq)
                                {
                                    TRY_LOCK(pnode->cs_inventory, lockInv);
                                    if (lockInv)
                                    {
                                        fDelete = true;
                                    }
                                }
                            }
                        }
                    }
                    if (fDelete)
                    {
                        vNodesDisconnected.remove(pnode);
                        delete pnode;
                    }
                }
            }
        }
        //
        // Find which sockets have data to receive
        //
        struct timeval timeout;
        timeout.tv_sec  = 0;
        timeout.tv_usec = 50000; // frequency to poll pnode->vSend

        fd_set fdsetRecv;
        fd_set fdsetSend;
        fd_set fdsetError;
        FD_ZERO(&fdsetRecv);
        FD_ZERO(&fdsetSend);
        FD_ZERO(&fdsetError);
        SOCKET hSocketMax = 0;
        bool have_fds = false;

        BOOST_FOREACH(SOCKET hListenSocket, vhListenSocket) {
            FD_SET(hListenSocket, &fdsetRecv);
            hSocketMax = max(hSocketMax, hListenSocket);
            have_fds = true;
        }
        {
            LOCK(cs_vNodes);
            BOOST_FOREACH(CNode* pnode, vNodes)
            {
                if (pnode->hSocket == INVALID_SOCKET)
                    continue;
                FD_SET(pnode->hSocket, &fdsetRecv);
                FD_SET(pnode->hSocket, &fdsetError);
                hSocketMax = max(hSocketMax, pnode->hSocket);
                have_fds = true;
                {
                    TRY_LOCK(pnode->cs_vSend, lockSend);
                    if (lockSend && !pnode->vSend.empty())
                        FD_SET(pnode->hSocket, &fdsetSend);
                }
            }
        }

        int nSelect = select(have_fds ? hSocketMax + 1 : 0,
                             &fdsetRecv, &fdsetSend, &fdsetError, &timeout);
        if (fShutdown)
            return;
        if (nSelect == SOCKET_ERROR)
        {
            if (have_fds)
            {
                int nErr = WSAGetLastError();
                LogPrintf("socket select error %d\n", nErr);
                for (unsigned int i = 0; i <= hSocketMax; i++)
                    FD_SET(i, &fdsetRecv);
            }
            FD_ZERO(&fdsetSend);
            FD_ZERO(&fdsetError);
            MilliSleep(timeout.tv_usec/1000);
        }


        //
        // Accept new connections
        //
        BOOST_FOREACH(SOCKET hListenSocket, vhListenSocket)
        if (hListenSocket != INVALID_SOCKET && FD_ISSET(hListenSocket, &fdsetRecv))
        {
#ifdef USE_IPV6
            struct sockaddr_storage sockaddr;
#else
            struct sockaddr sockaddr;
#endif
            socklen_t len = sizeof(sockaddr);
            SOCKET hSocket = accept(hListenSocket, (struct sockaddr*)&sockaddr, &len);
            CAddress addr;
            int nInbound = 0;

            if (hSocket != INVALID_SOCKET)
                if (!addr.SetSockAddr((const struct sockaddr*)&sockaddr))
                    LogPrintf("Warning: Unknown socket family\n");

            {
                LOCK(cs_vNodes);
                BOOST_FOREACH(CNode* pnode, vNodes)
                    if (pnode->fInbound)
                        nInbound++;
            }

            if (hSocket == INVALID_SOCKET)
            {
                int nErr = WSAGetLastError();
                if (nErr != WSAEWOULDBLOCK)
                    LogPrintf("socket error accept failed: %d\n", nErr);
            }
            else if (nInbound >= MAX_OUTBOUND_CONNECTIONS)
            {
                closesocket(hSocket);
            }
            else if (CNode::IsBanned(addr))
            {
                LogPrintf("connection from %s dropped (banned)\n", addr.ToString().c_str());
                closesocket(hSocket);
            }
            else
            {
                LogPrintf("accepted connection %s\n", addr.ToString().c_str());
                NodeId id = GetNewNodeId();
                CNode* pnode = new CNode(id, nLocalServices, pindexBest->nHeight, hSocket, addr, "", true);
                InitializeNode(pnode);
                pnode->AddRef();
                {
                    LOCK(cs_vNodes);
                    vNodes.push_back(pnode);
                }
            }
        }
        //
        // Service each socket
        //
        vector<CNode*> vNodesCopy;
        {
            LOCK(cs_vNodes);
            vNodesCopy = vNodes;
            BOOST_FOREACH(CNode* pnode, vNodesCopy)
                pnode->AddRef();
        }
        BOOST_FOREACH(CNode* pnode, vNodesCopy)
        {
            if (fShutdown)
                return;
            //
            // Receive
            //
            if (pnode->hSocket == INVALID_SOCKET)
                continue;
            if (FD_ISSET(pnode->hSocket, &fdsetRecv) || FD_ISSET(pnode->hSocket, &fdsetError))
            {
                TRY_LOCK(pnode->cs_vRecv, lockRecv);
                if (lockRecv)
                {
                    CDataStream& vRecv = pnode->vRecv;
                    unsigned int nPos = vRecv.size();

                    if (nPos > ReceiveBufferSize()) {
                        if (!pnode->fDisconnect)
                            LogPrintf("socket recv flood control disconnect (%u bytes)\n", vRecv.size());
                        pnode->CloseSocketDisconnect();
                    }
                    else {
                        // typical socket buffer is 8K-64K
                        char pchBuf[0x10000];
                        int nBytes = recv(pnode->hSocket, pchBuf, sizeof(pchBuf), MSG_DONTWAIT);
                        if (nBytes > 0)
                        {
                            vRecv.resize(nPos + nBytes);
                            memcpy(&vRecv[nPos], pchBuf, nBytes);
                            pnode->nLastRecv = GetTime();
                        }
                        else if (nBytes == 0)
                        {
                            // socket closed gracefully
                            if (!pnode->fDisconnect)
                                LogPrintf("socket closed\n");
                            pnode->CloseSocketDisconnect();
                        }
                        else if (nBytes < 0)
                        {
                            // error
                            int nErr = WSAGetLastError();
                            if (nErr != WSAEWOULDBLOCK && nErr != WSAEMSGSIZE && nErr != WSAEINTR && nErr != WSAEINPROGRESS)
                            {
                                if (!pnode->fDisconnect)
                                    LogPrintf("socket recv error %d\n", nErr);
                                pnode->CloseSocketDisconnect();
                            }
                        }
                    }
                }
            }
            //
            // Send
            //
            if (pnode->hSocket == INVALID_SOCKET)
                continue;
            if (FD_ISSET(pnode->hSocket, &fdsetSend))
            {
                TRY_LOCK(pnode->cs_vSend, lockSend);
                if (lockSend)
                {
                    CDataStream& vSend = pnode->vSend;
                    if (!vSend.empty())
                    {
                        int nBytes = send(pnode->hSocket, &vSend[0], vSend.size(), MSG_NOSIGNAL | MSG_DONTWAIT);
                        if (nBytes > 0)
                        {
                            vSend.erase(vSend.begin(), vSend.begin() + nBytes);
                            pnode->nLastSend = GetTime();
                        }
                        else if (nBytes < 0)
                        {
                            // error
                            int nErr = WSAGetLastError();
                            if (nErr != WSAEWOULDBLOCK && nErr != WSAEMSGSIZE && nErr != WSAEINTR && nErr != WSAEINPROGRESS)
                            {
                                LogPrintf("socket send error %d\n", nErr);
                                pnode->CloseSocketDisconnect();
                            }
                        }
                    }
                }
            }

            //
            // Inactivity checking
            //
            if (pnode->vSend.empty())
                pnode->nLastSendEmpty = GetTime();
            if (GetTime() - pnode->nTimeConnected > 60)
            {
                if (pnode->nLastRecv == 0 || pnode->nLastSend == 0)
                {
                    LogPrintf("socket no message in first 60 seconds, %d %d\n", pnode->nLastRecv != 0, pnode->nLastSend != 0);
                    pnode->fDisconnect = true;
                }
                else if (GetTime() - pnode->nLastSend > 90*60 && GetTime() - pnode->nLastSendEmpty > 90*60)
                {
                    LogPrintf("socket not sending\n");
                    pnode->fDisconnect = true;
                }
                else if (GetTime() - pnode->nLastRecv > 90*60)
                {
                    LogPrintf("socket inactivity timeout\n");
                    pnode->fDisconnect = true;
                }
            }
        }
        {
            LOCK(cs_vNodes);
            BOOST_FOREACH(CNode* pnode, vNodesCopy)
                pnode->Release();
        }
        MilliSleep(100);
    }
}

#ifdef USE_UPNP
void ThreadMapPort()
{
    // Make this thread recognisable as the UPnP thread
    RenameThread("ECCoin-UPnP");

    try
    {
        ThreadMapPort2();
    }
    catch (std::exception& e) {
        PrintException(&e, "ThreadMapPort()");
    } catch (...) {
        PrintException(NULL, "ThreadMapPort()");
    }
    LogPrintf("ThreadMapPort exited\n");
}

void ThreadMapPort2()
{
    LogPrintf("ThreadMapPort started\n");

    std::string port = strprintf("%u", GetListenPort());
    const char * multicastif = 0;
    const char * minissdpdpath = 0;
    struct UPNPDev * devlist = 0;
    char lanaddr[64];

#ifndef UPNPDISCOVER_SUCCESS
    /* miniupnpc 1.5 */
    devlist = upnpDiscover(2000, multicastif, minissdpdpath, 0);
#elif MINIUPNPC_API_VERSION < 14
    /* miniupnpc 1.6 */
    int error = 0;
    devlist = upnpDiscover(2000, multicastif, minissdpdpath, 0, 0, &error);
#else
    /* miniupnpc 1.9.xxx */
    int error = 0;
    devlist = upnpDiscover(2000, multicastif, minissdpdpath, 0, 0, 2, &error);
#endif

    struct UPNPUrls urls;
    struct IGDdatas data;
    int r;

    r = UPNP_GetValidIGD(devlist, &urls, &data, lanaddr, sizeof(lanaddr));
    if (r == 1)
    {
        if (fDiscover) {
            char externalIPAddress[40];
            r = UPNP_GetExternalIPAddress(urls.controlURL, data.first.servicetype, externalIPAddress);
            if(r != UPNPCOMMAND_SUCCESS)
                LogPrintf("UPnP: GetExternalIPAddress() returned %d\n", r);
            else
            {
                if(externalIPAddress[0])
                {
                    LogPrintf("UPnP: ExternalIPAddress = %s\n", externalIPAddress);
                    AddLocal(CNetAddr(externalIPAddress), LOCAL_UPNP);
                }
                else
                    LogPrintf("UPnP: GetExternalIPAddress failed.\n");
            }
        }

        string strDesc = "ECCoin " + FormatFullVersion();
#ifndef UPNPDISCOVER_SUCCESS
        /* miniupnpc 1.5 */
        r = UPNP_AddPortMapping(urls.controlURL, data.first.servicetype,
                            port.c_str(), port.c_str(), lanaddr, strDesc.c_str(), "TCP", 0);
#else
        /* miniupnpc 1.6 */
        r = UPNP_AddPortMapping(urls.controlURL, data.first.servicetype,
                            port.c_str(), port.c_str(), lanaddr, strDesc.c_str(), "TCP", 0, "0");
#endif

        if(r!=UPNPCOMMAND_SUCCESS)
            LogPrintf("AddPortMapping(%s, %s, %s) failed with code %d (%s)\n",
                port.c_str(), port.c_str(), lanaddr, r, strupnperror(r));
        else
            LogPrintf("UPnP Port Mapping successful.\n");
        int i = 1;
        while (true)
        {
            if (fShutdown || !fUseUPnP)
            {
                r = UPNP_DeletePortMapping(urls.controlURL, data.first.servicetype, port.c_str(), "TCP", 0);
                LogPrintf("UPNP_DeletePortMapping() returned : %d\n", r);
                freeUPNPDevlist(devlist); devlist = 0;
                FreeUPNPUrls(&urls);
                return;
            }
            if (i % 600 == 0) // Refresh every 20 minutes
            {
#ifndef UPNPDISCOVER_SUCCESS
                /* miniupnpc 1.5 */
                r = UPNP_AddPortMapping(urls.controlURL, data.first.servicetype,
                                    port.c_str(), port.c_str(), lanaddr, strDesc.c_str(), "TCP", 0);
#else
                /* miniupnpc 1.6 */
                r = UPNP_AddPortMapping(urls.controlURL, data.first.servicetype,
                                    port.c_str(), port.c_str(), lanaddr, strDesc.c_str(), "TCP", 0, "0");
#endif

                if(r!=UPNPCOMMAND_SUCCESS)
                    LogPrintf("AddPortMapping(%s, %s, %s) failed with code %d (%s)\n",
                        port.c_str(), port.c_str(), lanaddr, r, strupnperror(r));
                else
                    LogPrintf("UPnP Port Mapping successful.\n");;
            }
            MilliSleep(2000);
            i++;
        }
    } else {
        LogPrintf("No valid UPnP IGDs found\n");
        freeUPNPDevlist(devlist); devlist = 0;
        if (r != 0)
            FreeUPNPUrls(&urls);
        while (true)
        {
            if (fShutdown || !fUseUPnP)
                return;
            MilliSleep(2000);
        }
    }
}

void MapPort()
{
    if (fUseUPnP)
    {
        boost::thread* MapPort = new boost::thread(&ThreadMapPort);
        ecc_threads.add_thread(MapPort);
    }
}
#else
void MapPort()
{
    // Intentionally left blank.
}
#endif
