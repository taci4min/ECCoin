#ifndef OUTPOINT_H
#define OUTPOINT_H

#include "serialize.h"
#include "uint256.h"

/** An outpoint - a combination of a transaction hash and an index n into its vout */
class COutPoint
{
public:
    uint256 hash;
    unsigned int n;

    COutPoint();
    COutPoint(uint256 hashIn, unsigned int nIn);
    IMPLEMENT_SERIALIZE
    (
            READWRITE(FLATDATA(*this));
    )

    friend bool operator<(const COutPoint& a, const COutPoint& b)
    {
        return (a.hash < b.hash || (a.hash == b.hash && a.n < b.n));
    }

    friend bool operator==(const COutPoint& a, const COutPoint& b)
    {
        return (a.hash == b.hash && a.n == b.n);
    }

    friend bool operator!=(const COutPoint& a, const COutPoint& b)
    {
        return !(a == b);
    }

    void SetNull();
    bool IsNull() const;
    std::string ToString() const;
    void print() const;
};

#endif // OUTPOINT_H
