#include "outpoint.h"
#include "util/util.h"

COutPoint::COutPoint()
{
    SetNull();
}
COutPoint::COutPoint(uint256 hashIn, unsigned int nIn)
{
    hash = hashIn;
    n = nIn;
}

void COutPoint::SetNull()
{
    hash = 0;
    n = (unsigned int) -1;
}
bool COutPoint::IsNull() const
{
    return (hash == 0 && n == (unsigned int) -1);
}

std::string COutPoint::ToString() const
{
    return strprintf("COutPoint(%s, %u)", hash.ToString().substr(0,10).c_str(), n);
}

void COutPoint::print() const
{
    LogPrintf("%s\n", ToString().c_str());
}
