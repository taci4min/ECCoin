// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_SERIALIZE_H
#define BITCOIN_SERIALIZE_H

#include <string>
#include <vector>
#include <map>
#include <set>
#include <cassert>
#include <limits>
#include <stdint.h>
#include <cstring>
#include <cstdio>

#include <boost/type_traits/is_fundamental.hpp>
#include <boost/tuple/tuple.hpp>

#include "allocators.h"
#include "version.h"
#include "prevector.h"
#include "crypto/crypto_endian.h"

#ifdef _MSC_VER
# ifdef max
#   undef max
# endif
# ifdef min
#   undef min
# endif
#endif



class CAutoFile;
class CDataStream;
class CScript;
class CVectorWriter;


static const unsigned int MAX_SIZE = 0x02000000;

/**
 * Dummy data type to identify deserializing constructors.
 *
 * By convention, a constructor of a type T with signature
 *
 *   template <typename Stream> T::T(deserialize_type, Stream& s)
 *
 * is a deserializing constructor, which builds the type by
 * deserializing it from s. If T contains const fields, this
 * is likely the only way to do so.
 */
struct deserialize_type {};
constexpr deserialize_type deserialize {};

/**
 * Used to bypass the rule against non-const reference to temporary
 * where it makes sense with wrappers such as CFlatData or CTxDB
 */
template<typename T>
inline T& REF(const T& val)
{
    return const_cast<T&>(val);
}

/**
 * Used to acquire a non-const pointer "this" to generate bodies
 * of const serialization operations from a template
 */
template<typename T>
inline T* NCONST_PTR(const T* val)
{
    return const_cast<T*>(val);
}

/*
 * Lowest-level serialization and conversion.
 * @note Sizes of these types are verified in the tests
 */
template<typename Stream> inline void ser_writedata8(Stream &s, uint8_t obj)
{
    s.write((char*)&obj, 1);
}
template<typename Stream> inline void ser_writedata16(Stream &s, uint16_t obj)
{
    obj = htole16(obj);
    s.write((char*)&obj, 2);
}
template<typename Stream> inline void ser_writedata32(Stream &s, uint32_t obj)
{
    obj = htole32(obj);
    s.write((char*)&obj, 4);
}
template<typename Stream> inline void ser_writedata64(Stream &s, uint64_t obj)
{
    obj = htole64(obj);
    s.write((char*)&obj, 8);
}
template<typename Stream> inline uint8_t ser_readdata8(Stream &s)
{
    uint8_t obj;
    s.read((char*)&obj, 1);
    return obj;
}
template<typename Stream> inline uint16_t ser_readdata16(Stream &s)
{
    uint16_t obj;
    s.read((char*)&obj, 2);
    return le16toh(obj);
}
template<typename Stream> inline uint32_t ser_readdata32(Stream &s)
{
    uint32_t obj;
    s.read((char*)&obj, 4);
    return le32toh(obj);
}
template<typename Stream> inline uint64_t ser_readdata64(Stream &s)
{
    uint64_t obj;
    s.read((char*)&obj, 8);
    return le64toh(obj);
}
inline uint64_t ser_double_to_uint64(double x)
{
    union { double x; uint64_t y; } tmp;
    tmp.x = x;
    return tmp.y;
}
inline uint32_t ser_float_to_uint32(float x)
{
    union { float x; uint32_t y; } tmp;
    tmp.x = x;
    return tmp.y;
}
inline double ser_uint64_to_double(uint64_t y)
{
    union { double x; uint64_t y; } tmp;
    tmp.y = y;
    return tmp.x;
}
inline float ser_uint32_to_float(uint32_t y)
{
    union { float x; uint32_t y; } tmp;
    tmp.y = y;
    return tmp.x;
}


/////////////////////////////////////////////////////////////////
//
// Templates for serializing to anything that looks like a stream,
// i.e. anything that supports .read(char*, size_t) and .write(char*, size_t)
//

class CSizeComputer;

enum
{
    // primary actions
    SER_NETWORK         = (1 << 0),
    SER_DISK            = (1 << 1),
    SER_GETHASH         = (1 << 2),
};

#define READWRITE(obj)        (::SerReadWrite(s, (obj), ser_action))
#define READWRITEMANY(...)    (::SerReadWriteMany(s, ser_action, __VA_ARGS__))
#define COMPACTSIZE(obj)      REF(CCompactSize(REF(obj)))
#define LIMITED_STRING(obj,n) REF(LimitedString< n >(REF(obj)))

/**
 * Implement three methods for serializable objects. These are actually wrappers over
 * "SerializationOp" template, which implements the body of each class' serialization
 * code. Adding "ADD_SERIALIZE_METHODS" in the body of the class causes these wrappers to be
 * added as members.
 */
#define ADD_SERIALIZE_METHODS                                         \
    template<typename Stream>                                         \
    void Serialize(Stream& s) const {                                 \
        NCONST_PTR(this)->SerializationOp(s, CSerActionSerialize());  \
    }                                                                 \
    template<typename Stream>                                         \
    void Unserialize(Stream& s) {                                     \
        SerializationOp(s, CSerActionUnserialize());                  \
    }




template<typename Stream> inline void Serialize(Stream& s, char a    ) { ser_writedata8(s, a); } // TODO Get rid of bare char
template<typename Stream> inline void Serialize(Stream& s, int8_t a  ) { ser_writedata8(s, a); }
template<typename Stream> inline void Serialize(Stream& s, uint8_t a ) { ser_writedata8(s, a); }
template<typename Stream> inline void Serialize(Stream& s, int16_t a ) { ser_writedata16(s, a); }
template<typename Stream> inline void Serialize(Stream& s, uint16_t a) { ser_writedata16(s, a); }
template<typename Stream> inline void Serialize(Stream& s, int32_t a ) { ser_writedata32(s, a); }
template<typename Stream> inline void Serialize(Stream& s, uint32_t a) { ser_writedata32(s, a); }
template<typename Stream> inline void Serialize(Stream& s, int64_t a ) { ser_writedata64(s, a); }
template<typename Stream> inline void Serialize(Stream& s, uint64_t a) { ser_writedata64(s, a); }
template<typename Stream> inline void Serialize(Stream& s, float a   ) { ser_writedata32(s, ser_float_to_uint32(a)); }
template<typename Stream> inline void Serialize(Stream& s, double a  ) { ser_writedata64(s, ser_double_to_uint64(a)); }

template<typename Stream> inline void Unserialize(Stream& s, char& a    ) { a = ser_readdata8(s); } // TODO Get rid of bare char
template<typename Stream> inline void Unserialize(Stream& s, int8_t& a  ) { a = ser_readdata8(s); }
template<typename Stream> inline void Unserialize(Stream& s, uint8_t& a ) { a = ser_readdata8(s); }
template<typename Stream> inline void Unserialize(Stream& s, int16_t& a ) { a = ser_readdata16(s); }
template<typename Stream> inline void Unserialize(Stream& s, uint16_t& a) { a = ser_readdata16(s); }
template<typename Stream> inline void Unserialize(Stream& s, int32_t& a ) { a = ser_readdata32(s); }
template<typename Stream> inline void Unserialize(Stream& s, uint32_t& a) { a = ser_readdata32(s); }
template<typename Stream> inline void Unserialize(Stream& s, int64_t& a ) { a = ser_readdata64(s); }
template<typename Stream> inline void Unserialize(Stream& s, uint64_t& a) { a = ser_readdata64(s); }
template<typename Stream> inline void Unserialize(Stream& s, float& a   ) { a = ser_uint32_to_float(ser_readdata32(s)); }
template<typename Stream> inline void Unserialize(Stream& s, double& a  ) { a = ser_uint64_to_double(ser_readdata64(s)); }

template<typename Stream> inline void Serialize(Stream& s, bool a)    { char f=a; ser_writedata8(s, f); }
template<typename Stream> inline void Unserialize(Stream& s, bool& a) { char f=ser_readdata8(s); a=f; }

/**
 * Compact Size
 * size <  253        -- 1 byte
 * size <= USHRT_MAX  -- 3 bytes  (253 + 2 bytes)
 * size <= UINT_MAX   -- 5 bytes  (254 + 4 bytes)
 * size >  UINT_MAX   -- 9 bytes  (255 + 8 bytes)
 */
inline unsigned int GetSizeOfCompactSize(uint64_t nSize)
{
    if (nSize < 253)             return sizeof(unsigned char);
    else if (nSize <= std::numeric_limits<unsigned short>::max()) return sizeof(unsigned char) + sizeof(unsigned short);
    else if (nSize <= std::numeric_limits<unsigned int>::max())  return sizeof(unsigned char) + sizeof(unsigned int);
    else                         return sizeof(unsigned char) + sizeof(uint64_t);
}

inline void WriteCompactSize(CSizeComputer& os, uint64_t nSize);

template<typename Stream>
void WriteCompactSize(Stream& os, uint64_t nSize)
{
    if (nSize < 253)
    {
        ser_writedata8(os, nSize);
    }
    else if (nSize <= std::numeric_limits<unsigned short>::max())
    {
        ser_writedata8(os, 253);
        ser_writedata16(os, nSize);
    }
    else if (nSize <= std::numeric_limits<unsigned int>::max())
    {
        ser_writedata8(os, 254);
        ser_writedata32(os, nSize);
    }
    else
    {
        ser_writedata8(os, 255);
        ser_writedata64(os, nSize);
    }
    return;
}

template<typename Stream>
uint64_t ReadCompactSize(Stream& is)
{
    uint8_t chSize = ser_readdata8(is);
    uint64_t nSizeRet = 0;
    if (chSize < 253)
    {
        nSizeRet = chSize;
    }
    else if (chSize == 253)
    {
        nSizeRet = ser_readdata16(is);
        if (nSizeRet < 253)
            throw std::ios_base::failure("non-canonical ReadCompactSize()");
    }
    else if (chSize == 254)
    {
        nSizeRet = ser_readdata32(is);
        if (nSizeRet < 0x10000u)
            throw std::ios_base::failure("non-canonical ReadCompactSize()");
    }
    else
    {
        nSizeRet = ser_readdata64(is);
        if (nSizeRet < 0x100000000ULL)
            throw std::ios_base::failure("non-canonical ReadCompactSize()");
    }
    if (nSizeRet > (uint64_t)MAX_SIZE)
        throw std::ios_base::failure("ReadCompactSize(): size too large");
    return nSizeRet;
}

/**
 * Variable-length integers: bytes are a MSB base-128 encoding of the number.
 * The high bit in each byte signifies whether another digit follows. To make
 * sure the encoding is one-to-one, one is subtracted from all but the last digit.
 * Thus, the byte sequence a[] with length len, where all but the last byte
 * has bit 128 set, encodes the number:
 *
 *  (a[len-1] & 0x7F) + sum(i=1..len-1, 128^i*((a[len-i-1] & 0x7F)+1))
 *
 * Properties:
 * * Very small (0-127: 1 byte, 128-16511: 2 bytes, 16512-2113663: 3 bytes)
 * * Every integer has exactly one encoding
 * * Encoding does not depend on size of original integer type
 * * No redundancy: every (infinite) byte sequence corresponds to a list
 *   of encoded integers.
 *
 * 0:         [0x00]  256:        [0x81 0x00]
 * 1:         [0x01]  16383:      [0xFE 0x7F]
 * 127:       [0x7F]  16384:      [0xFF 0x00]
 * 128:  [0x80 0x00]  16511:      [0xFF 0x7F]
 * 255:  [0x80 0x7F]  65535: [0x82 0xFE 0x7F]
 * 2^32:           [0x8E 0xFE 0xFE 0xFF 0x00]
 */

template<typename I>
inline unsigned int GetSizeOfVarInt(I n)
{
    int nRet = 0;
    while(true) {
        nRet++;
        if (n <= 0x7F)
            break;
        n = (n >> 7) - 1;
    }
    return nRet;
}

template<typename I>
inline void WriteVarInt(CSizeComputer& os, I n);

template<typename Stream, typename I>
void WriteVarInt(Stream& os, I n)
{
    unsigned char tmp[(sizeof(n)*8+6)/7];
    int len=0;
    while(true) {
        tmp[len] = (n & 0x7F) | (len ? 0x80 : 0x00);
        if (n <= 0x7F)
            break;
        n = (n >> 7) - 1;
        len++;
    }
    do {
        ser_writedata8(os, tmp[len]);
    } while(len--);
}

template<typename Stream, typename I>
I ReadVarInt(Stream& is)
{
    I n = 0;
    while(true) {
        unsigned char chData = ser_readdata8(is);
        if (n > (std::numeric_limits<I>::max() >> 7)) {
           throw std::ios_base::failure("ReadVarInt(): size too large");
        }
        n = (n << 7) | (chData & 0x7F);
        if (chData & 0x80) {
            if (n == std::numeric_limits<I>::max()) {
                throw std::ios_base::failure("ReadVarInt(): size too large");
            }
            n++;
        } else {
            return n;
        }
    }
}



#define FLATDATA(obj) REF(CFlatData((char*)&(obj), (char*)&(obj) + sizeof(obj)))
#define VARINT(obj) REF(WrapVarInt(REF(obj)))
#define COMPACTSIZE(obj) REF(CCompactSize(REF(obj)))
#define LIMITED_STRING(obj,n) REF(LimitedString< n >(REF(obj)))

/**
 * Wrapper for serializing arrays and POD.
 */
class CFlatData
{
protected:
    char* pbegin;
    char* pend;
public:
    CFlatData(void* pbeginIn, void* pendIn) : pbegin((char*)pbeginIn), pend((char*)pendIn) { }
    template <class T, class TAl>
    explicit CFlatData(std::vector<T,TAl> &v)
    {
        pbegin = (char*)v.data();
        pend = (char*)(v.data() + v.size());
    }
    template <unsigned int N, typename T, typename S, typename D>
    explicit CFlatData(prevector<N, T, S, D> &v)
    {
        pbegin = (char*)v.data();
        pend = (char*)(v.data() + v.size());
    }
    char* begin() { return pbegin; }
    const char* begin() const { return pbegin; }
    char* end() { return pend; }
    const char* end() const { return pend; }

    template<typename Stream>
    void Serialize(Stream& s) const
    {
        s.write(pbegin, pend - pbegin);
    }

    template<typename Stream>
    void Unserialize(Stream& s)
    {
        s.read(pbegin, pend - pbegin);
    }
};

template<typename I>
class CVarInt
{
protected:
    I &n;
public:
    CVarInt(I& nIn) : n(nIn) { }

    template<typename Stream>
    void Serialize(Stream &s) const {
        WriteVarInt<Stream,I>(s, n);
    }

    template<typename Stream>
    void Unserialize(Stream& s) {
        n = ReadVarInt<Stream,I>(s);
    }
};

class CCompactSize
{
protected:
    uint64_t &n;
public:
    CCompactSize(uint64_t& nIn) : n(nIn) { }

    template<typename Stream>
    void Serialize(Stream &s) const {
        WriteCompactSize<Stream>(s, n);
    }

    template<typename Stream>
    void Unserialize(Stream& s) {
        n = ReadCompactSize<Stream>(s);
    }
};

template<size_t Limit>
class LimitedString
{
protected:
    std::string& string;
public:
    LimitedString(std::string& _string) : string(_string) {}

    template<typename Stream>
    void Unserialize(Stream& s)
    {
        size_t size = ReadCompactSize(s);
        if (size > Limit) {
            throw std::ios_base::failure("String length limit exceeded");
        }
        string.resize(size);
        if (size != 0)
            s.read((char*)string.data(), size);
    }

    template<typename Stream>
    void Serialize(Stream& s) const
    {
        WriteCompactSize(s, string.size());
        if (!string.empty())
            s.write((char*)string.data(), string.size());
    }
};

template<typename I>
CVarInt<I> WrapVarInt(I& n) { return CVarInt<I>(n); }

//
// Forward declarations
//

// string
template<typename Stream, typename C> void Serialize(Stream& os, const std::basic_string<C>& str);
template<typename Stream, typename C> void Unserialize(Stream& is, std::basic_string<C>& str);

/**
 * prevector
 * prevectors of unsigned char are a special case and are intended to be serialized as a single opaque blob.
 */
template<typename Stream, unsigned int N, typename T> void Serialize_impl(Stream& os, const prevector<N, T>& v, const unsigned char&);
template<typename Stream, unsigned int N, typename T, typename V> void Serialize_impl(Stream& os, const prevector<N, T>& v, const V&);
template<typename Stream, unsigned int N, typename T> inline void Serialize(Stream& os, const prevector<N, T>& v);
template<typename Stream, unsigned int N, typename T> void Unserialize_impl(Stream& is, prevector<N, T>& v, const unsigned char&);
template<typename Stream, unsigned int N, typename T, typename V> void Unserialize_impl(Stream& is, prevector<N, T>& v, const V&);
template<typename Stream, unsigned int N, typename T> inline void Unserialize(Stream& is, prevector<N, T>& v);


// vector
template<typename Stream, typename T, typename A> void Serialize_impl(Stream& os, const std::vector<T, A>& v, const unsigned char&);
template<typename Stream, typename T, typename A, typename V> void Serialize_impl(Stream& os, const std::vector<T, A>& v, const V&);
template<typename Stream, typename T, typename A> inline void Serialize(Stream& os, const std::vector<T, A>& v);
template<typename Stream, typename T, typename A> void Unserialize_impl(Stream& is, std::vector<T, A>& v, const unsigned char&);
template<typename Stream, typename T, typename A, typename V> void Unserialize_impl(Stream& is, std::vector<T, A>& v, const V&);
template<typename Stream, typename T, typename A> inline void Unserialize(Stream& is, std::vector<T, A>& v);

// pair
template<typename Stream, typename K, typename T> void Serialize(Stream& os, const std::pair<K, T>& item);
template<typename Stream, typename K, typename T> void Unserialize(Stream& is, std::pair<K, T>& item);


// map
template<typename Stream, typename K, typename T, typename Pred, typename A> void Serialize(Stream& os, const std::map<K, T, Pred, A>& m);
template<typename Stream, typename K, typename T, typename Pred, typename A> void Unserialize(Stream& is, std::map<K, T, Pred, A>& m);


// set
template<typename Stream, typename K, typename Pred, typename A> void Serialize(Stream& os, const std::set<K, Pred, A>& m);
template<typename Stream, typename K, typename Pred, typename A> void Unserialize(Stream& is, std::set<K, Pred, A>& m);

/**
 * shared_ptr
 */
template<typename Stream, typename T> void Serialize(Stream& os, const std::shared_ptr<const T>& p);
template<typename Stream, typename T> void Unserialize(Stream& os, std::shared_ptr<const T>& p);

/**
 * unique_ptr
 */
template<typename Stream, typename T> void Serialize(Stream& os, const std::unique_ptr<const T>& p);
template<typename Stream, typename T> void Unserialize(Stream& os, std::unique_ptr<const T>& p);

/**
 * If none of the specialized versions above matched, default to calling member function.
 */
template<typename Stream, typename T>
inline void Serialize(Stream& os, const T& a)
{
    a.Serialize(os);
}

template<typename Stream, typename T>
inline void Unserialize(Stream& is, T& a)
{
    a.Unserialize(is);
}






//
// string
//
template<typename Stream, typename C>
void Serialize(Stream& os, const std::basic_string<C>& str)
{
    WriteCompactSize(os, str.size());
    if (!str.empty())
        os.write((char*)str.data(), str.size() * sizeof(C));
}

template<typename Stream, typename C>
void Unserialize(Stream& is, std::basic_string<C>& str)
{
    unsigned int nSize = ReadCompactSize(is);
    str.resize(nSize);
    if (nSize != 0)
        is.read((char*)str.data(), nSize * sizeof(C));
}


/**
 * prevector
 */
template<typename Stream, unsigned int N, typename T>
void Serialize_impl(Stream& os, const prevector<N, T>& v, const unsigned char&)
{
    WriteCompactSize(os, v.size());
    if (!v.empty())
        os.write((char*)v.data(), v.size() * sizeof(T));
}

template<typename Stream, unsigned int N, typename T, typename V>
void Serialize_impl(Stream& os, const prevector<N, T>& v, const V&)
{
    WriteCompactSize(os, v.size());
    for (typename prevector<N, T>::const_iterator vi = v.begin(); vi != v.end(); ++vi)
        ::Serialize(os, (*vi));
}

template<typename Stream, unsigned int N, typename T>
inline void Serialize(Stream& os, const prevector<N, T>& v)
{
    Serialize_impl(os, v, T());
}


template<typename Stream, unsigned int N, typename T>
void Unserialize_impl(Stream& is, prevector<N, T>& v, const unsigned char&)
{
    // Limit size per read so bogus size value won't cause out of memory
    v.clear();
    unsigned int nSize = ReadCompactSize(is);
    unsigned int i = 0;
    while (i < nSize)
    {
        unsigned int blk = std::min(nSize - i, (unsigned int)(1 + 4999999 / sizeof(T)));
        v.resize(i + blk);
        is.read((char*)&v[i], blk * sizeof(T));
        i += blk;
    }
}

template<typename Stream, unsigned int N, typename T, typename V>
void Unserialize_impl(Stream& is, prevector<N, T>& v, const V&)
{
    v.clear();
    unsigned int nSize = ReadCompactSize(is);
    unsigned int i = 0;
    unsigned int nMid = 0;
    while (nMid < nSize)
    {
        nMid += 5000000 / sizeof(T);
        if (nMid > nSize)
            nMid = nSize;
        v.resize(nMid);
        for (; i < nMid; i++)
            Unserialize(is, v[i]);
    }
}

template<typename Stream, unsigned int N, typename T>
inline void Unserialize(Stream& is, prevector<N, T>& v)
{
    Unserialize_impl(is, v, T());
}


//
// vector
//
template<typename Stream, typename T, typename A>
void Serialize_impl(Stream& os, const std::vector<T, A>& v, const unsigned char&)
{
    WriteCompactSize(os, v.size());
    if (!v.empty())
        os.write((char*)v.data(), v.size() * sizeof(T));
}

template<typename Stream, typename T, typename A, typename V>
void Serialize_impl(Stream& os, const std::vector<T, A>& v, const V&)
{
    WriteCompactSize(os, v.size());
    for (typename std::vector<T, A>::const_iterator vi = v.begin(); vi != v.end(); ++vi)
        ::Serialize(os, (*vi));
}

template<typename Stream, typename T, typename A>
inline void Serialize(Stream& os, const std::vector<T, A>& v)
{
    Serialize_impl(os, v, T());
}


template<typename Stream, typename T, typename A>
void Unserialize_impl(Stream& is, std::vector<T, A>& v, const unsigned char&)
{
    // Limit size per read so bogus size value won't cause out of memory
    v.clear();
    unsigned int nSize = ReadCompactSize(is);
    unsigned int i = 0;
    while (i < nSize)
    {
        unsigned int blk = std::min(nSize - i, (unsigned int)(1 + 4999999 / sizeof(T)));
        v.resize(i + blk);
        is.read((char*)&v[i], blk * sizeof(T));
        i += blk;
    }
}

template<typename Stream, typename T, typename A, typename V>
void Unserialize_impl(Stream& is, std::vector<T, A>& v, const V&)
{
    v.clear();
    unsigned int nSize = ReadCompactSize(is);
    unsigned int i = 0;
    unsigned int nMid = 0;
    while (nMid < nSize)
    {
        nMid += 5000000 / sizeof(T);
        if (nMid > nSize)
            nMid = nSize;
        v.resize(nMid);
        for (; i < nMid; i++)
            Unserialize(is, v[i]);
    }
}

template<typename Stream, typename T, typename A>
inline void Unserialize(Stream& is, std::vector<T, A>& v)
{
    Unserialize_impl(is, v, T());
}


//
// pair
//
template<typename Stream, typename K, typename T>
void Serialize(Stream& os, const std::pair<K, T>& item)
{
    Serialize(os, item.first);
    Serialize(os, item.second);
}

template<typename Stream, typename K, typename T>
void Unserialize(Stream& is, std::pair<K, T>& item)
{
    Unserialize(is, item.first);
    Unserialize(is, item.second);
}

//
// map
//
template<typename Stream, typename K, typename T, typename Pred, typename A>
void Serialize(Stream& os, const std::map<K, T, Pred, A>& m)
{
    WriteCompactSize(os, m.size());
    for (typename std::map<K, T, Pred, A>::const_iterator mi = m.begin(); mi != m.end(); ++mi)
        Serialize(os, (*mi));
}

template<typename Stream, typename K, typename T, typename Pred, typename A>
void Unserialize(Stream& is, std::map<K, T, Pred, A>& m)
{
    m.clear();
    unsigned int nSize = ReadCompactSize(is);
    typename std::map<K, T, Pred, A>::iterator mi = m.begin();
    for (unsigned int i = 0; i < nSize; i++)
    {
        std::pair<K, T> item;
        Unserialize(is, item);
        mi = m.insert(mi, item);
    }
}



//
// set
//
template<typename Stream, typename K, typename Pred, typename A>
void Serialize(Stream& os, const std::set<K, Pred, A>& m)
{
    WriteCompactSize(os, m.size());
    for (typename std::set<K, Pred, A>::const_iterator it = m.begin(); it != m.end(); ++it)
        Serialize(os, (*it));
}

template<typename Stream, typename K, typename Pred, typename A>
void Unserialize(Stream& is, std::set<K, Pred, A>& m)
{
    m.clear();
    unsigned int nSize = ReadCompactSize(is);
    typename std::set<K, Pred, A>::iterator it = m.begin();
    for (unsigned int i = 0; i < nSize; i++)
    {
        K key;
        Unserialize(is, key);
        it = m.insert(it, key);
    }
}


/**
 * unique_ptr
 */
template<typename Stream, typename T> void
Serialize(Stream& os, const std::unique_ptr<const T>& p)
{
    Serialize(os, *p);
}

template<typename Stream, typename T>
void Unserialize(Stream& is, std::unique_ptr<const T>& p)
{
    p.reset(new T(deserialize, is));
}



/**
 * shared_ptr
 */
template<typename Stream, typename T> void
Serialize(Stream& os, const std::shared_ptr<const T>& p)
{
    Serialize(os, *p);
}

template<typename Stream, typename T>
void Unserialize(Stream& is, std::shared_ptr<const T>& p)
{
    p = std::make_shared<const T>(deserialize, is);
}





/**
 * Support for ADD_SERIALIZE_METHODS and READWRITE macro
 */
struct CSerActionSerialize
{
    constexpr bool ForRead() const { return false; }
};
struct CSerActionUnserialize
{
    constexpr bool ForRead() const { return true; }
};

template<typename Stream, typename T>
inline void SerReadWrite(Stream& s, const T& obj, CSerActionSerialize ser_action)
{
    ::Serialize(s, obj);
}

template<typename Stream, typename T>
inline void SerReadWrite(Stream& s, T& obj, CSerActionUnserialize ser_action)
{
    ::Unserialize(s, obj);
}


struct ser_streamplaceholder
{
    int nType;
    int nVersion;
};

template<typename Stream>
void SerializeMany(Stream& s)
{
}

template<typename Stream, typename Arg>
void SerializeMany(Stream& s, Arg&& arg)
{
    ::Serialize(s, std::forward<Arg>(arg));
}

template<typename Stream, typename Arg, typename... Args>
void SerializeMany(Stream& s, Arg&& arg, Args&&... args)
{
    ::Serialize(s, std::forward<Arg>(arg));
    ::SerializeMany(s, std::forward<Args>(args)...);
}

template<typename Stream>
inline void UnserializeMany(Stream& s)
{
}

template<typename Stream, typename Arg>
inline void UnserializeMany(Stream& s, Arg& arg)
{
    ::Unserialize(s, arg);
}

template<typename Stream, typename Arg, typename... Args>
inline void UnserializeMany(Stream& s, Arg& arg, Args&... args)
{
    ::Unserialize(s, arg);
    ::UnserializeMany(s, args...);
}

template<typename Stream, typename... Args>
inline void SerReadWriteMany(Stream& s, CSerActionSerialize ser_action, Args&&... args)
{
    ::SerializeMany(s, std::forward<Args>(args)...);
}

template<typename Stream, typename... Args>
inline void SerReadWriteMany(Stream& s, CSerActionUnserialize ser_action, Args&... args)
{
    ::UnserializeMany(s, args...);
}



/* Minimal stream for overwriting and/or appending to an existing byte vector
 *
 * The referenced vector will grow as necessary
 */
class CVectorWriter
{
 public:

/*
 * @param[in]  nTypeIn Serialization Type
 * @param[in]  nVersionIn Serialization Version (including any flags)
 * @param[in]  vchDataIn  Referenced byte vector to overwrite/append
 * @param[in]  nPosIn Starting position. Vector index where writes should start. The vector will initially
 *                    grow as necessary to  max(index, vec.size()). So to append, use vec.size().
*/
    CVectorWriter(int nTypeIn, int nVersionIn, std::vector<unsigned char>& vchDataIn, size_t nPosIn) : nType(nTypeIn), nVersion(nVersionIn), vchData(vchDataIn), nPos(nPosIn)
    {
        if(nPos > vchData.size())
            vchData.resize(nPos);
    }
/*
 * (other params same as above)
 * @param[in]  args  A list of items to serialize starting at nPos.
*/
    template <typename... Args>
    CVectorWriter(int nTypeIn, int nVersionIn, std::vector<unsigned char>& vchDataIn, size_t nPosIn, Args&&... args) : CVectorWriter(nTypeIn, nVersionIn, vchDataIn, nPosIn)
    {
        ::SerializeMany(*this, std::forward<Args>(args)...);
    }
    void write(const char* pch, size_t nSize)
    {
        assert(nPos <= vchData.size());
        size_t nOverwrite = std::min(nSize, vchData.size() - nPos);
        if (nOverwrite) {
            memcpy(vchData.data() + nPos, reinterpret_cast<const unsigned char*>(pch), nOverwrite);
        }
        if (nOverwrite < nSize) {
            vchData.insert(vchData.end(), reinterpret_cast<const unsigned char*>(pch) + nOverwrite, reinterpret_cast<const unsigned char*>(pch) + nSize);
        }
        nPos += nSize;
    }
    template<typename T>
    CVectorWriter& operator<<(const T& obj)
    {
        // Serialize to this stream
        ::Serialize(*this, obj);
        return (*this);
    }
    int GetVersion() const
    {
        return nVersion;
    }
    int GetType() const
    {
        return nType;
    }
    void seek(size_t nSize)
    {
        nPos += nSize;
        if(nPos > vchData.size())
            vchData.resize(nPos);
    }
private:
    const int nType;
    const int nVersion;
    std::vector<unsigned char>& vchData;
    size_t nPos;
};






typedef std::vector<char, zero_after_free_allocator<char> > CSerializeData;

/** Double ended buffer combining vector and stream-like interfaces.
 *
 * >> and << read and write unformatted data using the above serialization templates.
 * Fills with data in linear time; some stringstream implementations take N^2 time.
 */
class CDataStream
{
protected:
    typedef CSerializeData vector_type;
    vector_type vch;
    unsigned int nReadPos;

    int nType;
    int nVersion;
public:

    typedef vector_type::allocator_type   allocator_type;
    typedef vector_type::size_type        size_type;
    typedef vector_type::difference_type  difference_type;
    typedef vector_type::reference        reference;
    typedef vector_type::const_reference  const_reference;
    typedef vector_type::value_type       value_type;
    typedef vector_type::iterator         iterator;
    typedef vector_type::const_iterator   const_iterator;
    typedef vector_type::reverse_iterator reverse_iterator;

    explicit CDataStream(int nTypeIn, int nVersionIn)
    {
        Init(nTypeIn, nVersionIn);
    }

    CDataStream(const_iterator pbegin, const_iterator pend, int nTypeIn, int nVersionIn) : vch(pbegin, pend)
    {
        Init(nTypeIn, nVersionIn);
    }

    CDataStream(const char* pbegin, const char* pend, int nTypeIn, int nVersionIn) : vch(pbegin, pend)
    {
        Init(nTypeIn, nVersionIn);
    }

    CDataStream(const vector_type& vchIn, int nTypeIn, int nVersionIn) : vch(vchIn.begin(), vchIn.end())
    {
        Init(nTypeIn, nVersionIn);
    }

    CDataStream(const std::vector<char>& vchIn, int nTypeIn, int nVersionIn) : vch(vchIn.begin(), vchIn.end())
    {
        Init(nTypeIn, nVersionIn);
    }

    CDataStream(const std::vector<unsigned char>& vchIn, int nTypeIn, int nVersionIn) : vch(vchIn.begin(), vchIn.end())
    {
        Init(nTypeIn, nVersionIn);
    }

    template <typename... Args>
    CDataStream(int nTypeIn, int nVersionIn, Args&&... args)
    {
        Init(nTypeIn, nVersionIn);
        ::SerializeMany(*this, std::forward<Args>(args)...);
    }

    void Init(int nTypeIn, int nVersionIn)
    {
        nReadPos = 0;
        nType = nTypeIn;
        nVersion = nVersionIn;
    }

    CDataStream& operator+=(const CDataStream& b)
    {
        vch.insert(vch.end(), b.begin(), b.end());
        return *this;
    }

    friend CDataStream operator+(const CDataStream& a, const CDataStream& b)
    {
        CDataStream ret = a;
        ret += b;
        return (ret);
    }

    std::string str() const
    {
        return (std::string(begin(), end()));
    }


    //
    // Vector subset
    //
    const_iterator begin() const                     { return vch.begin() + nReadPos; }
    iterator begin()                                 { return vch.begin() + nReadPos; }
    const_iterator end() const                       { return vch.end(); }
    iterator end()                                   { return vch.end(); }
    size_type size() const                           { return vch.size() - nReadPos; }
    bool empty() const                               { return vch.size() == nReadPos; }
    void resize(size_type n, value_type c=0)         { vch.resize(n + nReadPos, c); }
    void reserve(size_type n)                        { vch.reserve(n + nReadPos); }
    const_reference operator[](size_type pos) const  { return vch[pos + nReadPos]; }
    reference operator[](size_type pos)              { return vch[pos + nReadPos]; }
    void clear()                                     { vch.clear(); nReadPos = 0; }
    iterator insert(iterator it, const char& x=char()) { return vch.insert(it, x); }
    void insert(iterator it, size_type n, const char& x) { vch.insert(it, n, x); }
    value_type* data()                               { return vch.data() + nReadPos; }
    const value_type* data() const                   { return vch.data() + nReadPos; }

    void insert(iterator it, std::vector<char>::const_iterator first, std::vector<char>::const_iterator last)
    {
        if (last == first) return;
        assert(last - first > 0);
        if (it == vch.begin() + nReadPos && (unsigned int)(last - first) <= nReadPos)
        {
            // special case for inserting at the front when there's room
            nReadPos -= (last - first);
            memcpy(&vch[nReadPos], &first[0], last - first);
        }
        else
            vch.insert(it, first, last);
    }

    void insert(iterator it, const char* first, const char* last)
    {
        if (last == first) return;
        assert(last - first > 0);
        if (it == vch.begin() + nReadPos && (unsigned int)(last - first) <= nReadPos)
        {
            // special case for inserting at the front when there's room
            nReadPos -= (last - first);
            memcpy(&vch[nReadPos], &first[0], last - first);
        }
        else
            vch.insert(it, first, last);
    }

    iterator erase(iterator it)
    {
        if (it == vch.begin() + nReadPos)
        {
            // special case for erasing from the front
            if (++nReadPos >= vch.size())
            {
                // whenever we reach the end, we take the opportunity to clear the buffer
                nReadPos = 0;
                return vch.erase(vch.begin(), vch.end());
            }
            return vch.begin() + nReadPos;
        }
        else
            return vch.erase(it);
    }

    iterator erase(iterator first, iterator last)
    {
        if (first == vch.begin() + nReadPos)
        {
            // special case for erasing from the front
            if (last == vch.end())
            {
                nReadPos = 0;
                return vch.erase(vch.begin(), vch.end());
            }
            else
            {
                nReadPos = (last - vch.begin());
                return last;
            }
        }
        else
            return vch.erase(first, last);
    }

    inline void Compact()
    {
        vch.erase(vch.begin(), vch.begin() + nReadPos);
        nReadPos = 0;
    }

    bool Rewind(size_type n)
    {
        // Rewind by n characters if the buffer hasn't been compacted yet
        if (n > nReadPos)
            return false;
        nReadPos -= n;
        return true;
    }


    //
    // Stream subset
    //
    bool eof() const             { return size() == 0; }
    CDataStream* rdbuf()         { return this; }
    int in_avail()               { return size(); }

    void SetType(int n)          { nType = n; }
    int GetType() const          { return nType; }
    void SetVersion(int n)       { nVersion = n; }
    int GetVersion() const       { return nVersion; }

    void read(char* pch, size_t nSize)
    {
        if (nSize == 0) return;

        // Read from the beginning of the buffer
        unsigned int nReadPosNext = nReadPos + nSize;
        if (nReadPosNext >= vch.size())
        {
            if (nReadPosNext > vch.size())
            {
                throw std::ios_base::failure("CDataStream::read(): end of data");
            }
            memcpy(pch, &vch[nReadPos], nSize);
            nReadPos = 0;
            vch.clear();
            return;
        }
        memcpy(pch, &vch[nReadPos], nSize);
        nReadPos = nReadPosNext;
    }

    void ignore(int nSize)
    {
        // Ignore from the beginning of the buffer
        if (nSize < 0) {
            throw std::ios_base::failure("CDataStream::ignore(): nSize negative");
        }
        unsigned int nReadPosNext = nReadPos + nSize;
        if (nReadPosNext >= vch.size())
        {
            if (nReadPosNext > vch.size())
                throw std::ios_base::failure("CDataStream::ignore(): end of data");
            nReadPos = 0;
            vch.clear();
            return;
        }
        nReadPos = nReadPosNext;
    }

    void write(const char* pch, size_t nSize)
    {
        // Write to the end of the buffer
        vch.insert(vch.end(), pch, pch + nSize);
    }

    template<typename Stream>
    void Serialize(Stream& s) const
    {
        // Special case: stream << stream concatenates like stream += stream
        if (!vch.empty())
            s.write((char*)vch.data(), vch.size() * sizeof(value_type));
    }

    template<typename T>
    CDataStream& operator<<(const T& obj)
    {
        // Serialize to this stream
        ::Serialize(*this, obj);
        return (*this);
    }

    template<typename T>
    CDataStream& operator>>(T& obj)
    {
        // Unserialize from this stream
        ::Unserialize(*this, obj);
        return (*this);
    }

    void GetAndClear(CSerializeData &d) {
        d.insert(d.end(), begin(), end());
        clear();
    }

    /**
     * XOR the contents of this stream with a certain key.
     *
     * @param[in] key    The key used to XOR the data in this stream.
     */
    void Xor(const std::vector<unsigned char>& key)
    {
        if (key.size() == 0) {
            return;
        }

        for (size_type i = 0, j = 0; i != size(); i++) {
            vch[i] ^= key[j++];

            // This potentially acts on very many bytes of data, so it's
            // important that we calculate `j`, i.e. the `key` index in this
            // way instead of doing a %, which would effectively be a division
            // for each byte Xor'd -- much slower than need be.
            if (j == key.size())
                j = 0;
        }
    }
};









/** Non-refcounted RAII wrapper for FILE*
 *
 * Will automatically close the file when it goes out of scope if not null.
 * If you're returning the file pointer, return file.release().
 * If you need to close the file early, use file.fclose() instead of fclose(file).
 */
class CAutoFile
{
private:
    // Disallow copies
    CAutoFile(const CAutoFile&);
    CAutoFile& operator=(const CAutoFile&);

    const int nType;
    const int nVersion;

    FILE* file;

public:
    CAutoFile(FILE* filenew, int nTypeIn, int nVersionIn) : nType(nTypeIn), nVersion(nVersionIn)
    {
        file = filenew;
    }

    ~CAutoFile()
    {
        fclose();
    }

    void fclose()
    {
        if (file) {
            ::fclose(file);
            file = NULL;
        }
    }

    /** Get wrapped FILE* with transfer of ownership.
     * @note This will invalidate the CAutoFile object, and makes it the responsibility of the caller
     * of this function to clean up the returned FILE*.
     */
    FILE* release()             { FILE* ret = file; file = NULL; return ret; }

    /** Get wrapped FILE* without transfer of ownership.
     * @note Ownership of the FILE* will remain with this class. Use this only if the scope of the
     * CAutoFile outlives use of the passed pointer.
     */
    FILE* Get() const           { return file; }

    /** Return true if the wrapped FILE* is NULL, false otherwise.
     */
    bool IsNull() const         { return (file == NULL); }

    //
    // Stream subset
    //
    int GetType() const          { return nType; }
    int GetVersion() const       { return nVersion; }

    void read(char* pch, size_t nSize)
    {
        if (!file)
            throw std::ios_base::failure("CAutoFile::read: file handle is NULL");
        if (fread(pch, 1, nSize, file) != nSize)
            throw std::ios_base::failure(feof(file) ? "CAutoFile::read: end of file" : "CAutoFile::read: fread failed");
    }

    void ignore(size_t nSize)
    {
        if (!file)
            throw std::ios_base::failure("CAutoFile::ignore: file handle is NULL");
        unsigned char data[4096];
        while (nSize > 0) {
            size_t nNow = std::min<size_t>(nSize, sizeof(data));
            if (fread(data, 1, nNow, file) != nNow)
                throw std::ios_base::failure(feof(file) ? "CAutoFile::ignore: end of file" : "CAutoFile::read: fread failed");
            nSize -= nNow;
        }
    }

    void write(const char* pch, size_t nSize)
    {
        if (!file)
            throw std::ios_base::failure("CAutoFile::write: file handle is NULL");
        if (fwrite(pch, 1, nSize, file) != nSize)
            throw std::ios_base::failure("CAutoFile::write: write failed");
    }

    template<typename T>
    CAutoFile& operator<<(const T& obj)
    {
        // Serialize to this stream
        if (!file)
            throw std::ios_base::failure("CAutoFile::operator<<: file handle is NULL");
        ::Serialize(*this, obj);
        return (*this);
    }

    template<typename T>
    CAutoFile& operator>>(T& obj)
    {
        // Unserialize from this stream
        if (!file)
            throw std::ios_base::failure("CAutoFile::operator>>: file handle is NULL");
        ::Unserialize(*this, obj);
        return (*this);
    }
};

#endif
