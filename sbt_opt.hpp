#ifndef SBT_SBTOPT_HPP
#define SBT_SBTOPT_HPP

#include <cstdint>

#include "state.hpp"


/* SBT design

- three registers:
-- LFSR register, 64 bits LFSR f(x)=1+x^31+x^63, which is stepped 64 times each time
-- key, 56 bits, the input key for the 'blockcipher'
-- cryptobuffer, 64 bits, the output buffer of the 'blockcipher'.
   cryptobuffer is always filled as SBT(key, LFSR).
   OTP encryption extracts byte by byte.
   Once all bytes are used then the LFSR is stepped 64 times and a new cryptobuffer computed.

- initialization:
- user_key, nonce => LFSR, prelimkey
- key = SBT(prelimkey, LFSR)
- LFSR = fixed_mask
- cryptobuffer = SBT(key, LFSR)
- now cryptobuffer is filled and ready for streaming mode


*/


/* optimized representation of SBT */

// key state: same as original SBT implementation
// lfsr state: 64-bit state is bit reversed: b0 .. b63 => b63 .. b0
// control state: low 8 bits are reversed
inline state_t switch_representation_key(state_t key)
{
    return key;
}
inline state_t switch_representation_lfsr(state_t lfsr)
{
    lfsr.reverse_bits();
    return lfsr;
}

class SBTopt
{
public:
    // the main registers of the SBT procedure
    state_t lfsr_register;
    state_t key_register;
    state_t cryptobuffer_register;
    state_t test_register;
    int used_cryptobuffer;

    void initialize(const std::string& daily_crvar, const std::string& nonce, bool verbose = false)
    {
        if (verbose)
        {
            std::cout << "Userkey: " << to_hex_string(&daily_crvar[0], 15) << " '" << daily_crvar << "'" << std::endl;
            std::cout << "Nonce : " << to_hex_string(&nonce[0], 3) << " '" << nonce << "'" << std::endl;
        }
        // 1) preliminary fill of lfsr & key register from daily+aux cryptovariable
        auto key_state = key_state_initialization(daily_crvar, nonce);
        key_register = key_state.first;
        lfsr_register = key_state.second;
        // 2) call SBT
        lfsr64(lfsr_register);
        cryptobuffer_register = SBT_cipher(key_register, lfsr_register);
        used_cryptobuffer = 0;
        // 3) set key_register using cryptobuffer_register
        key_register.u64 = cryptobuffer_register.u64 & ((1ULL<<56)-1);
        key_register.swap_bits();
        key_register.swap_bitpairs();
        key_register.swap_nibbles();
        // 4) set lfsr_register to initial_fill value
        lfsr_register = initial_fill();
        // 5) call SBT
        lfsr64(lfsr_register);
        cryptobuffer_register = SBT_cipher(key_register, lfsr_register);
        // 6) replace 3 bytes with nonce
        lfsr_register.u64 &= ((1ULL<<40)-1);
        for (int i = 0; i < 3; ++i)
            lfsr_register.u64 |= std::uint64_t(char_to_byte(nonce[2-i])) << ((7-i)*8);

        if (!verbose || nonce[0] != 0 || nonce[1] != 0 || nonce[2] != 0)
            return;
        // print KEY checksum
        std::cout << "Key Checksum: ";
        for (int i = 6; i >= 0; i -= 2)
        {
            unsigned B0 = (cryptobuffer_register.u64>>(i*8+0)) ^ (cryptobuffer_register.u64>>(i*8+12));
            B0 &= 0xF;
            B0 += unsigned('A');
            std::cout << char(B0);
        }
        std::cout << std::endl;
    }
    
    unsigned get_keystreambyte()
    {
        // if cryptobuffer fully used then step lfsr & run cipher to obtain next cryptobuffer
        if (used_cryptobuffer >= 8)
        {
            lfsr64(lfsr_register);
            cryptobuffer_register = SBT_cipher(key_register, lfsr_register);
            used_cryptobuffer = 0;
        }
        // 0 <= ucb <= 7
        unsigned ksb = (cryptobuffer_register.u64 >> (used_cryptobuffer*8)) & 0xFF;
        ++used_cryptobuffer;
        return ksb;
    }


    /* static functions that can be called without an SBT object */

    // compute cryptobuffer output from lfsr state and key
    // the lfsr state always needs to be stepped before every call!
    static inline state_t SBT_cipher(const state_t key_register, const state_t lfsr_register);

    // convert input character to byte encoding
    static inline unsigned char_to_byte(char c);

    // prepare the key & lfsr registers for the initialization procedure
    // given the user input daily cryptovariable and aux cryptovariable character strings
    static inline std::pair<state_t, state_t> key_state_initialization
        (const std::string& daily_crvar, const std::string& nonce);



    // returns the fixed initial fill lfsr state
    static inline state_t initial_fill();

    // step LFSR 64 times, optimized implementation
    static inline void lfsr64(state_t& S);
    // step LFSR once: b1 .... b64 => (b31^b63) b1 .... b63
    static inline void steplfsr(state_t& S);

    // apply bitpermutation between LFSR and Box permutation input
    static inline void bitpermutation(state_t& S);



    // perform a key right rotation per 28-bit half
    static inline state_t key_rotateright(const state_t key, unsigned n);

    // compute the control bits (Nr is bits 0-7, Gr is bits 8-39) per round
    static inline state_t control_Nr_Gr(unsigned round, const state_t key, const state_t lfsr);



    // roundfunction subprocedures
    static inline void grid_permutation(state_t& s, const state_t control);

    static inline bool partial_grid_permutation(state_t& s, const int n, const state_t BPmask, const int extra_crumb, const state_t control);

    static inline void bytepermutation(state_t& S);

    static inline void nibbleswitch(state_t& S, const state_t control);

    static inline void sbox(state_t& S);

    // roundfunction subprocedures
    static inline void grid_permutation_inv(state_t& s, const state_t control);

    static inline bool partial_grid_permutation_inv(state_t& s, const int n, const state_t BPmask, const int extra_crumb, const state_t control);

    static inline void bytepermutation_inv(state_t& S);

    static inline void nibbleswitch_inv(state_t& S, const state_t control) { nibbleswitch(S,control); }

    static inline void sbox_inv(state_t& S);

    // check for used key bits
    static inline bool grid_permutation_keycheck(const state_t control, const state_t BPmask);

    static inline bool nibbleswitch_keycheck(const state_t control, const state_t BPmask);

    static inline bool SBT_cipher_keycheck(const state_t key, state_t BPmask);

    static inline state_t determine_keymask(const state_t BPmask);
};


/* class SBT member function implementations */

    inline state_t SBTopt::SBT_cipher(const state_t key_register, const state_t lfsr_register)
    {
        state_t round_state = lfsr_register;
        bitpermutation(round_state);
        for (int r = 0; r < 8; ++r)
        {
            // compute control bits for this round
            // low 8 bits are Nr, next 32 bits are Br
            state_t round_control = control_Nr_Gr(r, key_register, lfsr_register);

//#define CHECK_INV_FUNCTIONS
#ifdef CHECK_INV_FUNCTIONS
            auto tmp = round_state;
#endif

            grid_permutation(round_state, round_control);
            bytepermutation(round_state);
            nibbleswitch(round_state, round_control);
            sbox(round_state);

#ifdef CHECK_INV_FUNCTIONS
            auto tmp2 = round_state;

            sbox_inv(tmp2);
            nibbleswitch_inv(tmp2, round_control);
            bytepermutation_inv(tmp2);
            grid_permutation_inv(tmp2, round_control);
            if (tmp2 != tmp) throw;
#endif
        }
        return round_state;
    }

    // convert input character to byte encoding
    inline unsigned SBTopt::char_to_byte(char c)
    {
        // ASCII code truncated to 6 bits
        unsigned r = unsigned(c) & 0x3F;
        return r;
    }

    // prepare the key & lfsr registers for the initialization procedure
    // given the user key and nonce character strings
    inline std::pair<state_t, state_t> SBTopt::key_state_initialization
        (const std::string& daily_crvar,
         const std::string& nonce)
    {
        state_t state(0);
        for (int i = 0; i < 8; ++i)
        {
            state.u64 |= std::uint64_t(char_to_byte(daily_crvar[i]))<<(i*8);
            if (i < 3)
                state.u64 ^= std::uint64_t(char_to_byte(nonce[i]))<<(i*8);
        }
        state_t key(0);
        for (int i = 0; i < 7; ++i)
            key.u64 |= std::uint64_t(char_to_byte(daily_crvar[i+8]))<<(i*8);
        key.swap_bits();
        key.swap_bitpairs();
        key.swap_nibbles();
        return std::pair<state_t,state_t>(key, state);
    }






    // returns the fixed initial fill lfsr state
    inline state_t SBTopt::initial_fill()
    {
        //static const std::string fill_constant_str = "10101111 00000011 01011110 00001000 01010001 11110101 11101000 11110011";
        static const std::uint64_t fill_constant = 0xcf17af8a107ac0f5ULL;
        return state_t(fill_constant);
    }

    // step LFSR: b1 .... b64 => (b31^b63) b1 .... b63
    inline void SBTopt::steplfsr(state_t& S)
    {
        std::uint64_t newbit = ((S.u64>>33)&1) ^ ((S.u64>>1)&1);
        S.shiftleft();
        S.u64 |= newbit<<63;
    }

    // step LFSR 64 times, optimized implementation
    inline void SBTopt::lfsr64(state_t& S)
    {
        // mask for high 31 bits
        const std::uint64_t mask = ((std::uint64_t(1)<<31) - 1) << 33;
        std::uint64_t new31 = (S.u64 ^ (S.u64<<32)) & mask;
        S.u64 = (S.u64 >> 31) | new31;
        new31 = (S.u64 ^ (S.u64<<32)) & mask;
        S.u64 = (S.u64 >> 31) | new31;
        new31 = ((S.u64<<29) ^ (S.u64<<61)) & (3ULL << 62);
        S.u64 = (S.u64 >> 2) | new31;
    }

    // apply bitpermutation between LFSR and Box permutation input
    inline void SBTopt::bitpermutation(state_t& S)
    {
        static const unsigned perm[64] =
            { 19, 47, 48,  5, 62, 25, 13, 36,
              16, 44, 37, 51,  8, 57,  7, 26,
              33, 50, 20,  3, 41, 11, 27, 61,
              59, 18, 55, 14, 35,  1, 24, 45,
              10, 29, 63, 46,  6, 39, 52, 21,
               2, 60, 22, 15, 42, 30, 34, 53,
              17,  0, 49, 38, 28, 12, 58, 40,
              43, 32, 23, 31, 56,  9,  4, 54 };
        std::uint64_t R = 0;
        for (unsigned i = 0; i < 64; ++i)
            R |= ((S.u64>>(perm[i]))&1)<<(i);
        S.u64 = R;
    }








    // perform a key right rotation per 28-bit half
    inline state_t SBTopt::key_rotateright(state_t key, unsigned n)
    {
        const std::uint64_t mask28 = (1ULL<<28) - 1;
        std::uint64_t x = key.u64 & mask28, y = (key.u64>>28) & mask28;
        n %= 28;
        x = ((x << n) | (x >> (28-n))) & mask28;
        y = ((y << n) | (y >> (28-n))) & mask28;
        return state_t(x | (y<<28));
    }

    // compute the control bits (Nr is bits 0-7, Br is bits 8-39) per round
    inline state_t SBTopt::control_Nr_Gr(unsigned round, const state_t key, const state_t lfsr)
    {
        if (round >= 8)
            throw;
        state_t Nr_Br = 0;

        static const unsigned rshift[8] = { 5, 7, 9, 14, 19, 24, 26, 28 };
        state_t xryr = key_rotateright( key, rshift[round] );

        static const unsigned Nr_bits[8] =
            { 35,  7, 32,  4, 29,  1, 54, 26 };
        for (int i = 0; i < 8; ++i)
            Nr_Br.u64 ^= ((xryr.u64>>Nr_bits[i])&1) << i;

        static const unsigned Sr_bits[8] = { 32, 40, 48, 56, 0, 8, 16, 24 };
        state_t Sr = lfsr;
        Sr.rotateright( Sr_bits[round] );

        static const unsigned Kr_bits[32] =
            { 10, 38, 13, 41, 16, 44, 19, 47,
              22, 50, 25, 53,  0, 28,  3, 31,
               6, 34,  9, 37, 12, 40, 15, 43,
              18, 46, 21, 49, 24, 52, 27, 55 };
        for (int i = 0; i < 32; ++i)
        {
            std::uint64_t bit = xryr.u64>>Kr_bits[i];
            bit ^= Sr.u64>>(63-i);
            bit &= 1;
            Nr_Br.u64 |= bit<<(8+i);
        }

        return Nr_Br;
    }



    inline void SBTopt::grid_permutation(state_t& s, const state_t control)
    {
        for (int n = 0; n < 16; ++n)
        {
            int pos = n^1;
            unsigned nibble = (s.u64>>(pos*4)) &0xF;
            unsigned row = nibble >> 2;
            unsigned col = nibble & 3;
            unsigned nibcon = (control.u64 >> (8+2*n)) & 3;
            /* nibcon has 2 bits with LSB left */
            switch (nibcon)
            {
                case 0: // nibcon == 00: up
                    if (row == 0)
                    {
                        unsigned neighbour = (s.u64 >> 4*(pos^(8>>nibcon)));
                        neighbour += neighbour >> 2;
                        col += neighbour;
                        col &= 3;
                    }
                    --row; row &= 3;
                    break;
                case 1: // nibcon == 10: down
                    if (row == 3)
                    {
                        unsigned neighbour = (s.u64 >> 4*(pos^(8>>nibcon)));
                        neighbour += neighbour >> 2;
                        col += neighbour;
                        col &= 3;
                    }
                    ++row; row &= 3;
                    break;
                case 2: // nibcon == 01: left
                    if (col == 0)
                    {
                        unsigned neighbour = (s.u64 >> 4*(pos^(8>>nibcon)));
                        neighbour += neighbour >> 2;
                        row += neighbour;
                        row &= 3;
                    }
                    --col; col &= 3;
                    break;
                case 3: // nibcon == 11: right
                    if (col == 3)
                    {
                        unsigned neighbour = (s.u64 >> 4*(pos^(8>>nibcon)));
                        neighbour += neighbour >> 2;
                        row += neighbour;
                        row &= 3;
                    }
                    ++col; col &= 3;
                    break;
            }
            s.u64 &= ~(0xFULL<<(pos*4));
            s.u64 |= std::uint64_t((row<<2)|col) << (pos*4);
        }
    }


inline bool SBTopt::partial_grid_permutation(state_t& s, const int n, const state_t BPmask, const int extra_crumb, const state_t control)
    {
        int pos = n^1;
        unsigned nibble = (s.u64>>(pos*4)) &0xF;
        unsigned row = nibble >> 2;
        unsigned col = nibble & 3;
        unsigned nibcon = (control.u64 >> (8+2*n)) & 3;
        bool extcrumbused = false;
        /* nibcon has 2 bits with LSB left */
        switch (nibcon)
        {
            case 0: // nibcon == 00: up
                if (row == 0)
                {
                    int nbpos = ((pos^(8>>nibcon)));
                    if (BPmask.getnibble(nbpos) != 0){ // the nb is in the bpmask
                    unsigned neighbour = (s.u64 >> 4*(pos^(8>>nibcon)));
                    neighbour += neighbour >> 2;
                    col += neighbour;
                    col &= 3;
                }
                else{
                    col += extra_crumb;
                    col &= 3;
                    extcrumbused = true;
                }
            }
            --row; row &= 3;
            break;

            case 1: // nibcon == 10: down
                if (row == 3)
                {
                    int nbpos = ((pos^(8>>nibcon)));
                    if (BPmask.getnibble(nbpos) != 0){ // the nb is in the bpmask
                    unsigned neighbour = (s.u64 >> 4*(pos^(8>>nibcon)));
                    neighbour += neighbour >> 2;
                    col += neighbour;
                    col &= 3;
                    }
                else{
                    col += extra_crumb;
                    col &= 3;
                    extcrumbused = true;
                    }
                }
                ++row; row &= 3;
                break;

            case 2: // nibcon == 01: left
                if (col == 0)
                {
                    int nbpos = ((pos^(8>>nibcon)));                    
                    if (BPmask.getnibble(nbpos) != 0){ // the nb is in the bpmask

                        unsigned neighbour = (s.u64 >> 4*(pos^(8>>nibcon)));
                        neighbour += neighbour >> 2;
                        row += neighbour;
                        row &= 3;
                    }
                    else{
                        row += extra_crumb;
                        row &= 3;
                        extcrumbused = true;
                    }
                }
                --col; col &= 3;
                break;
            case 3: // nibcon == 11: right
                if (col == 3)
                {
                    int nbpos = ((pos^(8>>nibcon)));                    
                    if (BPmask.getnibble(nbpos) != 0){ // the nb is in the bpmask
                        unsigned neighbour = (s.u64 >> 4*(pos^(8>>nibcon)));
                        neighbour += neighbour >> 2;
                        row += neighbour;
                        row &= 3;
                    }
                    else{
                        row += extra_crumb;
                        row &= 3;
                        extcrumbused = true;
                    }
                }
            ++col; col &= 3;
            break;
        }

        s.u64 &= ~(0xFULL<<(pos*4));
        s.u64 |= std::uint64_t((row<<2)|col) << (pos*4);
        return extcrumbused;
    }


    inline void SBTopt::bytepermutation(state_t& S)
    {
        state_t D(0);
        static const int perm[8] = { 3, 5, 1, 4, 6, 0, 7, 2 };
        for (int i = 0; i < 8; ++i)
            D.u64 |= ((S.u64>>(perm[i]*8)) & 0xFF) << (i*8);
        S = D;
    }

    inline void SBTopt::nibbleswitch(state_t& S, const state_t control)
    {
        for (int i = 0; i < 8; ++i)
        {
            if (!((control.u64>>i)&1))
                continue;
            std::uint64_t nibblexor = ((S.u64>>4)^S.u64) & (0xFULL<<(i*8));
            S.u64 ^= nibblexor ^ (nibblexor<<4);
        }
    }
    
    inline void SBTopt::sbox(state_t& S)
    {
        static const unsigned SBOX[16][16] = {
            {4,15,10,1,11,2,8,0,13,5,6,12,7,3,9,14},
            {15,10,8,13,3,0,14,2,12,6,9,1,4,11,7,5},
            {8,11,3,14,13,10,4,15,9,0,12,6,5,7,1,2},
            {1,8,14,10,7,4,9,13,6,3,11,5,15,0,2,12},
            {13,2,12,9,14,7,3,1,4,8,0,15,6,10,5,11},
            {11,7,9,5,10,1,15,6,2,12,4,13,14,8,3,0},
            {7,13,6,8,1,3,0,4,5,15,2,14,10,12,11,9},
            {2,4,5,12,9,11,7,8,15,14,13,10,3,1,0,6},
            {7,15,0,12,10,8,1,11,9,13,5,3,14,2,6,4},
            {4,9,8,5,0,6,10,14,11,2,7,15,1,3,13,12},
            {3,14,13,9,1,4,8,6,10,0,11,5,2,15,12,7},
            {11,10,14,0,9,13,3,2,6,12,15,7,8,5,4,1},
            {9,7,6,13,11,15,4,12,0,8,2,14,10,1,3,5},
            {5,2,1,4,13,14,0,9,15,11,6,12,3,10,7,8},
            {8,13,7,14,5,0,11,10,2,3,12,1,15,4,9,6},
            {1,5,4,6,12,10,9,15,3,14,8,0,13,7,2,11}
        };
        state_t S2(0);
        for (int i = 0; i < 16; ++i)
        {
            std::uint64_t nibble = (S.u64>>(i*4)) & 0xF;
            nibble = SBOX[i][nibble];
            S2.u64 |= nibble << (i*4);
        }
        S = S2;
    }














    inline void SBTopt::grid_permutation_inv(state_t& s, const state_t control)
    {
        for (int n = 15; n >= 0; --n)
        {
            int pos = n^1;
            unsigned nibble = (s.u64>>(pos*4)) &0xF;
            unsigned row = nibble >> 2;
            unsigned col = nibble & 3;
            unsigned nibcon = (control.u64 >> (8+2*n)) & 3;
            /* nibcon has 2 bits with LSB left */
            switch (nibcon)
            {
                case 0: // nibcon == 00: up
                    if (row == 3)
                    {
                        unsigned neighbour = (s.u64 >> 4*(pos^(8>>nibcon)));
                        neighbour += neighbour >> 2;
                        col -= neighbour;
                        col &= 3;
                    }
                    ++row; row &= 3;
                    break;
                case 1: // nibcon == 10: down
                    if (row == 0)
                    {
                        unsigned neighbour = (s.u64 >> 4*(pos^(8>>nibcon)));
                        neighbour += neighbour >> 2;
                        col -= neighbour;
                        col &= 3;
                    }
                    --row; row &= 3;
                    break;
                case 2: // nibcon == 01: left
                    if (col == 3)
                    {
                        unsigned neighbour = (s.u64 >> 4*(pos^(8>>nibcon)));
                        neighbour += neighbour >> 2;
                        row -= neighbour;
                        row &= 3;
                    }
                    ++col; col &= 3;
                    break;
                case 3: // nibcon == 11: right
                    if (col == 0)
                    {
                        unsigned neighbour = (s.u64 >> 4*(pos^(8>>nibcon)));
                        neighbour += neighbour >> 2;
                        row -= neighbour;
                        row &= 3;
                    }
                    --col; col &= 3;
                    break;
            }
            s.u64 &= ~(0xFULL<<(pos*4));
            s.u64 |= std::uint64_t((row<<2)|col) << (pos*4);
        }
    }

    inline bool SBTopt::partial_grid_permutation_inv(state_t& s, const int n, const state_t BPmask, const int extra_crumb, const state_t control)
    {
        int pos = n^1;
        unsigned nibble = (s.u64>>(pos*4)) &0xF;
        unsigned row = nibble >> 2;
        unsigned col = nibble & 3;
        unsigned nibcon = (control.u64 >> (8+2*n)) & 3;
        bool extcrumbused = false;
        /* nibcon has 2 bits with LSB left */
        switch (nibcon)
        {
            case 0: // nibcon == 00: up
                if (row == 3)
                {
                    int nbpos = ((pos^(8>>nibcon)));
                    if (BPmask.getnibble(nbpos) != 0){
                        unsigned neighbour = (s.u64 >> 4*(pos^(8>>nibcon)));
                        neighbour += neighbour >> 2;
                        col -= neighbour;
                        col &= 3;
                    }
                    else{
                        col -= extra_crumb;
                        col &= 3;
                        extcrumbused = true;
                    }
                }
                ++row; row &= 3;
                break;
            case 1: // nibcon == 10: down
                if (row == 0)
                {
                    int nbpos = ((pos^(8>>nibcon)));
                    if(BPmask.getnibble(nbpos) != 0){
                        unsigned neighbour = (s.u64 >> 4*(pos^(8>>nibcon)));
                        neighbour += neighbour >> 2;
                        col -= neighbour;
                        col &= 3;
                    }
                    else{
                        col -= extra_crumb;
                        col &= 3;
                        extcrumbused = true;
                    }
                }
                --row; row &= 3;
                break;
            case 2: // nibcon == 01: left
                if (col == 3)
                {
                    int nbpos = ((pos^(8>>nibcon)));
                    if (BPmask.getnibble(nbpos) != 0){
                        unsigned neighbour = (s.u64 >> 4*(pos^(8>>nibcon)));
                        neighbour += neighbour >> 2;
                        row -= neighbour;
                        row &= 3;
                    }
                    else{
                        row -= extra_crumb;
                        row &= 3;
                        extcrumbused = true;
                    }
                }
                ++col; col &= 3;
                break;
            case 3: // nibcon == 11: right
                if (col == 0)
                {
                    int nbpos =  ((pos^(8>>nibcon)));
                    if (BPmask.getnibble(nbpos) != 0){
                        unsigned neighbour = (s.u64 >> 4*(pos^(8>>nibcon)));
                        neighbour += neighbour >> 2;
                        row -= neighbour;
                        row &= 3;
                    }
                    else{
                        row -= extra_crumb;
                        row &= 3;
                        extcrumbused = true;
                    }
                }
                --col; col &= 3;
                break;
        }
        s.u64 &= ~(0xFULL<<(pos*4));
        s.u64 |= std::uint64_t((row<<2)|col) << (pos*4);
        return extcrumbused;
    }



    inline void SBTopt::bytepermutation_inv(state_t& S)
    {
        state_t D(0);
        static int perm_inv[8] = { 5, 2, 7, 0, 3, 1, 4, 6 };
        for (int i = 0; i < 8; ++i)
            D.u64 |= ((S.u64>>(perm_inv[i]*8))&0xFF) << (i*8);
        S = D;
    }

    inline void SBTopt::sbox_inv(state_t& S)
    {
        static const unsigned SBOXinv[16][16] = {
            {7,3,5,13,0,9,10,12,6,14,2,4,11,8,15,1},
            {5,11,7,4,12,15,9,14,2,10,1,13,8,3,6,0},
            {9,14,15,2,6,12,11,13,0,8,5,1,10,4,3,7},
            {13,0,14,9,5,11,8,4,1,6,3,10,15,7,2,12},
            {10,7,1,6,8,14,12,5,9,3,13,15,2,0,4,11},
            {15,5,8,14,10,3,7,1,13,2,4,0,9,11,12,6},
            {6,4,10,5,7,8,2,0,3,15,12,14,13,1,11,9},
            {14,13,0,12,1,2,15,6,7,4,11,5,3,10,9,8},
            {2,6,13,11,15,10,14,0,5,8,4,7,3,9,12,1},
            {4,12,9,13,0,3,5,10,2,1,6,8,15,14,7,11},
            {9,4,12,0,5,11,7,15,6,3,8,10,14,2,1,13},
            {3,15,7,6,14,13,8,11,12,4,1,0,9,5,2,10},
            {8,13,10,14,6,15,2,1,9,0,12,4,7,3,11,5},
            {6,2,1,12,3,0,10,14,15,7,13,9,11,4,5,8},
            {5,11,8,9,13,4,15,2,0,14,7,6,10,1,3,12},
            {11,0,14,8,2,1,3,13,10,6,5,15,4,12,9,7},
        };
        state_t S2(0);
        for (int i = 0; i < 16; ++i)
        {
            std::uint64_t nibble = (S.u64>>(i*4)) & 0xF;
            nibble = SBOXinv[i][nibble];
            S2.u64 |= nibble << (i*4);
        }
        S = S2;
    }

    inline bool SBTopt::grid_permutation_keycheck(const state_t control, const state_t BPmask)
    {
        for (int n = 0; n < 16; ++n)
        {
            int pos = n^1;
            if (BPmask.getnibble(pos) == 0) continue;
            unsigned nibcon = (control.u64 >> (8+2*n)) & 3;
            if (nibcon != 0)
                return true;
        }
        return false;
    }

    inline bool SBTopt::nibbleswitch_keycheck(const state_t control, const state_t BPmask)
    {
        for (int i = 0; i < 8; ++i)
        {
            if (BPmask.getbyte(i) == 0) continue;
            if ((control.u64>>i)&1)
                return true;
        }
        return false;
    }

    inline bool SBTopt::SBT_cipher_keycheck(const state_t key, state_t BPmask)
    {
        for (int r = 0; r < 8; ++r)
        {
            state_t round_control = control_Nr_Gr(r, key, 0);
            if (grid_permutation_keycheck(round_control, BPmask))
                return true;
            bytepermutation(BPmask);
            if (nibbleswitch_keycheck(round_control, BPmask))
                return true;
        }
        return false;
    }

    inline state_t SBTopt::determine_keymask(const state_t BPmask)
    {
        state_t keymask = 0;
        for (unsigned i = 0; i < 56; ++i)
        {
            state_t keybit = 1ULL<<i;
            if (SBT_cipher_keycheck(keybit, BPmask))
                keymask.u64 |= keybit.u64;
        }
        return keymask;
    }

#endif