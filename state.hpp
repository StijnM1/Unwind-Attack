#ifndef SBT_STATE_HPP
#define SBT_STATE_HPP

#include <cstdint>
#include <iostream>
#include <string>

using namespace std::string_literals;

static inline std::string to_hex_string(const std::uint8_t* ptr, unsigned cnt)
{
    static const char hex[17] = "0123456789ABCDEF";
    std::string ret;
    for (unsigned i = 0; i < cnt; ++i,++ptr)
    {
        unsigned x = *ptr;
        ret.push_back(hex[x>>4]);
        ret.push_back(hex[x&0xF]);
    }
    return ret;
}
static inline std::string to_hex_string(const char* ptr, unsigned cnt)
{
    static const char hex[17] = "0123456789ABCDEF";
    std::string ret;
    for (unsigned i = 0; i < cnt; ++i,++ptr)
    {
        unsigned x = *ptr;
        ret.push_back(hex[x>>4]);
        ret.push_back(hex[x&0xF]);
    }
    return ret;
}

/* 
    Class representating a 64-bit state in SBT.
    Bits are numbered 0 to 63
    Nibbles are numbered 0 to 15
    - Nibble 1 consists of state bits (LSB) 0,1,2,3 (MSB), etc
    Bytes are numbered 0 to 7
    - Byte 1 consists of state bits (LSB) 0,1,2,3,4,5,6,7 (MSB), etc
    
    The state is stored in a 64-bit unsigned integer std::uint64_t u64, 
    with u64 LSB (resp. MSB) corresponding to LSB (resp. MSB) of state.
    
    std::cout << std::dec << s; // prints state [ bit1 ... bit64 ]
    std::cout << std::hex << s; // prints state [ hex(nibble1) .... hex(nibble16) ]
*/
class state_t
{
public:
    state_t() = default;
    state_t(std::uint64_t n): u64(n) {}
    state_t(const std::string& str)
    {
        *this = str;
    }
    
    state_t(const state_t& _s) = default;
    state_t(state_t&& _s) = default;
    state_t& operator=(const state_t& _s) = default;
    state_t& operator=(state_t&& _s) = default;

    state_t& operator=(const std::string& str)
    {
        u64 = 0;
        int i = 0;
        for (auto c : str)
        {
            // ignore anything but '0' and '1' characters
            switch (c)
            {
                default:
                    break;
                case '0':
                    ++i;
                    break;
                case '1':
                    setbit(i, 1);
                    ++i;
                    break;
            }
            // Stop processing once we've read 64 bits
            if (i >= 64)
                break;
        }
        return *this;
    }
    
    bool operator==(const state_t& r) const { return u64 == r.u64; }
    bool operator!=(const state_t& r) const { return u64 != r.u64; }
    bool operator<(const state_t& r) const { return u64 < r.u64; }
    bool operator>(const state_t& r) const { return u64 > r.u64; }
    bool operator<=(const state_t& r) const { return u64 <= r.u64; }
    bool operator>=(const state_t& r) const { return u64 >= r.u64; }
    
    // bits are numbered 0 to 63 inclusive
    unsigned getbit(unsigned i) const
    {
        if (i >= 64) throw;
        return unsigned( (u64>>i) & 1 );
    }
    void setbit(unsigned i, unsigned v)
    {
        if (i >= 64) throw;
        std::uint64_t mask = ~ ( std::uint64_t(1) << i );
        u64 &= mask;
        std::uint64_t vi = std::uint64_t(v & 1) << i;
        u64 |= vi;
    }

    // nibbles are numbered 0 to 15 inclusive
    unsigned getnibble(unsigned i) const
    {
        if (i >= 16) throw;
        return unsigned( (u64>>(i*4)) & 0xF );
    }
    void setnibble(unsigned i, unsigned v)
    {
        if (i >= 16) throw;
        std::uint64_t mask = ~( std::uint64_t(0xF) << (i*4) );
        u64 &= mask;
        std::uint64_t vi = std::uint64_t(v & 0xF) << (i*4);
        u64 |= vi;
    }
    
    // bytes are numbered 0 to 7 inclusive
    unsigned getbyte(unsigned i) const
    {
        if (i >= 8) throw;
        return unsigned( (u64>>(i*8)) & 0xFF );
    }
    void setbyte(unsigned i, unsigned v)
    {
        if (i >= 8) throw;
        std::uint64_t mask = ~( std::uint64_t(0xFF) << (i*8) );
        u64 &= mask;
        std::uint64_t vi = std::uint64_t(v & 0xFF) << (i*8);
        u64 |= vi;
    }
    
    // shift MSB out: b0 .... b63 => 0 b0 ... b62
    void shiftright()
    {
        u64 <<= 1;
    }
    // shift MSB out: b0 .... b63 => b1 ... b63 0
    void shiftleft()
    {
        u64 >>= 1;
    }
    // rotate
    void rotateright(unsigned n)
    {
        n %= 64;
        u64 = (u64 << n) | (u64 >> (64-n));
    }
    void rotateleft(unsigned n)
    {
        n %= 64;
        u64 = (u64 >> n) | (u64 << (64-n));
    }

    // reverse all bits: b1 .... b64 => b64 .... b1
    void reverse_bits_naive()
    {
        state_t tmp(0);
        for (unsigned i = 0 ; i < 64; ++i)
        {
            tmp.setbit(63-i, getbit(i));
        }
        u64 = tmp.u64;
    }
    void swap_bits()
    {
        static const std::uint64_t bit1mask  = 0x5555555555555555ULL;
        u64 = ((u64>>1) & bit1mask) | ((u64&bit1mask) << 1);
    }
    void swap_bitpairs()
    {
        static const std::uint64_t bit2mask  = 0x3333333333333333ULL;
        u64 = ((u64>>2) & bit2mask) | ((u64&bit2mask) << 2);
    }
    void swap_nibbles()
    {
        static const std::uint64_t bit4mask  = 0x0F0F0F0F0F0F0F0FULL;
        u64 = ((u64>>4) & bit4mask) | ((u64&bit4mask) << 4);
    }
    void reverse_bits()
    {
        swap_bits();
        swap_bitpairs();
        swap_nibbles();
        reverse_bytes();
    }
    void reverse_bits_nibbles()
    {
        swap_bits();
        swap_bitpairs();
    }

    void reverse_bytes_naive()
    {
        state_t tmp(0);
        for (int i = 1; i <= 8; ++i)
            tmp.setbyte(9-i, getbyte(i));
        u64 = tmp.u64;
    }
    void reverse_bytes()
    {
        static const std::uint64_t bit8mask  = 0x00FF00FF00FF00FFULL;
        static const std::uint64_t bit16mask = 0x0000FFFF0000FFFFULL;
        static const std::uint64_t bit32mask = 0x00000000FFFFFFFFULL;
        u64 = ((u64>>8) & bit8mask) | ((u64&bit8mask) << 8);
        u64 = ((u64>>16) & bit16mask) | ((u64&bit16mask) << 16);
        u64 = ((u64>>32) & bit32mask) | ((u64&bit32mask) << 32);
    }
    
    // permute the bits
    template<typename Int>
    void permute_bits(const Int perm[64])
    {
        state_t tmp(0);
        for (unsigned i = 0; i < 64; ++i)
            tmp.setbit(i, getbit(perm[i]));
        u64 = tmp.u64;
    }

    // permute the bytes
    template<typename Int>
    void permute_bytes(const Int perm[8])
    {
        state_t tmp(0);
        for (unsigned i = 0; i < 8; ++i)
            tmp.setbyte(i, getbyte(perm[i]));
        u64 = tmp.u64;
    }

    std::uint64_t u64;
};

std::ostream& operator<<(std::ostream& o, const state_t& s)
{
    o << "[ ";
    if (o.flags() & std::ios_base::hex)
    {
        for (unsigned i = 0; i < 16; ++i)
        {
            o << s.getnibble(i) << ' ';
        }
    }
    else
    {
        // 'dec'=bin mode
        for (unsigned i = 0; i < 64; ++i)
        {
            o << s.getbit(i) ? '1' : '0';
            if (7 == (i % 8))
                o << ' ';
        }
    }
    o << ']';
    return o;
}

#endif