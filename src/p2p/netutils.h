#ifndef NETUTILS_H
#define NETUTILS_H

#include "service.h"
#include "subnet.h"
#include "tx/tx.h"
#include "net.h"
#include "protocol.h"

class CNode;
class CAddress;

enum Network ParseNetwork(std::string net);
unsigned short GetListenPort();
void SplitHostPort(std::string in, int &portOut, std::string &hostOut);
bool Lookup(const char *pszName, CService& addr, int portDefault = 0, bool fAllowLookup = true);
bool Lookup(const char *pszName, std::vector<CService>& vAddr, int portDefault = 0, bool fAllowLookup = true, unsigned int nMaxSolutions = 0);
bool LookupHost(const char *pszName, std::vector<CNetAddr>& vIP, unsigned int nMaxSolutions = 0, bool fAllowLookup = true);
bool LookupHost(const char *pszName, CNetAddr& addr, bool fAllowLookup);
bool LookupHostNumeric(const char *pszName, std::vector<CNetAddr>& vIP, unsigned int nMaxSolutions = 0);
bool LookupNumeric(const char *pszName, CService& addr, int portDefault = 0);
CService LookupNumeric(const char *pszName, int portDefault = 0);
bool LookupIntern(const char *pszName, std::vector<CNetAddr>& vIP, unsigned int nMaxSolutions, bool fAllowLookup);
bool LookupSubNet(const char *pszName, CSubNet& subnet);
bool IsLimited(enum Network net);
bool IsLimited(const CNetAddr& addr);
bool AddLocal(const CService& addr, int nScore = LOCAL_NONE);
bool AddLocal(const CNetAddr& addr, int nScore = LOCAL_NONE);
void SetLimited(enum Network net, bool fLimited = true);
void SetReachable(enum Network net, bool fFlag = true);
bool GetMyExternalIP(CNetAddr& ipRet);
void RelayTransaction(const CTransaction& tx, const uint256& hash);
void RelayTransaction(const CTransaction& tx, const uint256& hash, const CDataStream& ss);
bool SeenLocal(const CService& addr);
void AdvertiseLocal(CNode *pnode);
bool RecvLine(SOCKET hSocket, std::string& strLine);
CAddress GetLocalAddress(const CNetAddr *paddrPeer, ServiceFlags nLocalServices);
bool IsPeerAddrLocalGood(CNode *pnode);
/** Close socket and set hSocket to INVALID_SOCKET */
bool CloseSocket(SOCKET& hSocket);
/** Return readable error string for a network error code */
std::string NetworkErrorString(int err);
std::string GetDNSHost(const CDNSSeedData& data, ServiceFlags* requiredServiceBits);
/** Return a timestamp in the future (in microseconds) for exponentially distributed events. */
int64_t PoissonNextSend(int64_t nNow, int average_interval_seconds);

bool CompareNodeBlockTime(const NodeEvictionCandidate &a, const NodeEvictionCandidate &b);
bool CompareNodeTXTime(const NodeEvictionCandidate &a, const NodeEvictionCandidate &b);
bool ReverseCompareNodeMinPingTime(const NodeEvictionCandidate &a, const NodeEvictionCandidate &b);
bool ReverseCompareNodeTimeConnected(const NodeEvictionCandidate &a, const NodeEvictionCandidate &b);

/** Disable or enable blocking-mode for a socket */
bool SetSocketNonBlocking(SOCKET& hSocket, bool fNonBlocking);
/** Set the TCP_NODELAY flag on a socket */
bool SetSocketNoDelay(SOCKET& hSocket);
/** Get the bind address for a socket as CAddress */
CAddress GetBindAddress(SOCKET sock);
bool CompareNetGroupKeyed(const NodeEvictionCandidate &a, const NodeEvictionCandidate &b);
void MapPort(bool fUseUPnP);
#endif // NETUTILS_H
