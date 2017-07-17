#include "inpoint.h"

CInPoint::CInPoint()
{
    SetNull();
}
CInPoint::CInPoint(CTransaction* ptxIn, unsigned int nIn)
{
    ptx = ptxIn;
    n = nIn;
}
void CInPoint::SetNull()
{
    ptx = NULL;
    n = (unsigned int) -1;
}
bool CInPoint::IsNull() const
{
    return (ptx == NULL && n == (unsigned int) -1);
}
