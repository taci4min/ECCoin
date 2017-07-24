#ifndef DISK_H
#define DISK_H

#include "serialize.h"
#include "util/util.h"

/** Position on disk for a particular transaction. */
class CDiskTxPos
{
public:
    uint32_t nFile;
    uint32_t nBlockPos;
    uint32_t nTxPos;

    CDiskTxPos();
    CDiskTxPos(unsigned int nFileIn, unsigned int nBlockPosIn, unsigned int nTxPosIn);

    ADD_SERIALIZE_METHODS

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(nFile);
        READWRITE(nBlockPos);
        READWRITE(nTxPos);
    }
/*
    template <typename Stream>
    inline void Serialize(Stream& s) const {
        s << nFile;
        s << nBlockPos;
        s << nTxPos;
    }


    template <typename Stream>
    inline void Unserialize(Stream& s) {
        s >> nFile;
        s >> nBlockPos;
        s >> nTxPos;
    }
*/
    void SetNull();
    bool IsNull() const;

    friend bool operator==(const CDiskTxPos& a, const CDiskTxPos& b)
    {
        return (a.nFile     == b.nFile &&
                a.nBlockPos == b.nBlockPos &&
                a.nTxPos    == b.nTxPos);
    }

    friend bool operator!=(const CDiskTxPos& a, const CDiskTxPos& b)
    {
        return !(a == b);
    }

    std::string ToString() const;
    void print() const;
};

#endif // DISK_H
