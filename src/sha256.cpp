/** sha256.cpp - Bendik Hillestad - Public Domain
 * This is free and unencumbered software released into the public domain.
 *
 * Anyone is free to copy, modify, publish, use, compile, sell, or
 * distribute this software, either in source code form or as a compiled
 * binary, for any purpose, commercial or non-commercial, and by any
 * means.
 *
 * In jurisdictions that recognize copyright laws, the author or authors
 * of this software dedicate any and all copyright interest in the
 * software to the public domain. We make this dedication for the benefit
 * of the public at large and to the detriment of our heirs and
 * successors. We intend this dedication to be an overt act of
 * relinquishment in perpetuity of all present and future rights to this
 * software under copyright law.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */

#include "sha256.h"

#if !defined(BKH_SHA256_NO_CASSERT) && (defined(DEBUG) || defined(_DEBUG) || defined(DBG))
#    include <cassert>
#else
#    define assert(x) static_cast<void>(!!(x))
#endif

#if defined(__has_attribute)
#    if __has_attribute(const)
#        define BKH_PURE __attribute__((const))
#    endif
#endif

#if !defined(BKH_PURE)
#    define BKH_PURE
#endif

#define BKH_RESTRICT __restrict

#if defined(__has_include)
#    if __has_include(<endian.h>)
#        include <endian.h>
#    elif __has_include(<machine/endian.h>)
#        include <machine/endian.h>
#    endif
#endif

#if !defined(LITTLE_ENDIAN)
#    define LITTLE_ENDIAN 1234
#endif

#if !defined(BIG_ENDIAN)
#    define BIG_ENDIAN 4321
#endif

#if defined(WIN32) || defined(_WIN32) || defined(__WIN32)
#    if !defined(BYTE_ORDER)
#        define BYTE_ORDER LITTLE_ENDIAN
#    endif
#endif

#if !defined(BYTE_ORDER)
#    pragma message("Warning: Byte order is not defined! Assuming little-endian")
#    define BYTE_ORDER LITTLE_ENDIAN
#endif

/* Types defined for SHA-256 */

using byte = bkh::sha256::byte;
using word = bkh::sha256::word;

/* Operations defined for SHA-256 */

/**
 * Discards the right-most n bits of the word and pads the result
 * with n zero bits on the left.
 */
BKH_PURE static constexpr word right_shift(word x, byte n) noexcept
{
    constexpr byte const w = sizeof(word) * 8;

    assert(n < w);

    return static_cast<word>(x >> n);
}

/**
 * Discards the left-most n bits of the word and pads the result
 * with n zero bits on the right.
 */
BKH_PURE static constexpr word left_shift(word x, byte n) noexcept
{
    constexpr byte const w = sizeof(word) * 8;

    assert(n < w);

    return static_cast<word>(x << n);
}

/**
 * Performs the bitwise-and operation, where each bit in the result
 * is 1 if both words have a 1 in the same location, otherwise it
 * is 0.
 */
BKH_PURE static constexpr word bitwise_and(word lhs, word rhs) noexcept
{
    return lhs & rhs;
}

/**
 * Performs the bitwise-or ("inclusive-or") operation, where each
 * bit in the result is 1 if either word has a 1 in the same
 * location, otherwise it is 0.
 */
BKH_PURE static constexpr word bitwise_or(word lhs, word rhs) noexcept
{
    return lhs | rhs;
}

/**
 * Performs the bitwise-xor ("exclusive-or") operation, where each
 * bit in the result is 1 if only one word has a 1 in the same
 * location, otherwise it is 0.
 */
BKH_PURE static constexpr word bitwise_xor(word lhs, word rhs) noexcept
{
    return lhs ^ rhs;
}

/**
 * Performs the bitwise-complement operation, where each bit in
 * the result is the opposite of what is in the input.
 */
BKH_PURE static constexpr word bitwise_complement(word x) noexcept
{
    return ~x;
}

/**
 * Performs the rotate right (circular right shift) operation,
 * which is defined as: right_rotate(x, n) := 
 *     bitwise_or(right_shift(x, n), left_shift(x, w - n))
 * where w is the number of bits in a word.
 * The operation is thus equivalent to a circular shift
 * of x by n positions to the right.
 */
BKH_PURE static constexpr word right_rotate(word x, byte n) noexcept
{
    constexpr byte const w = sizeof(word) * 8;

    word const rs = right_shift(x, n);
    word const ls = left_shift (x, w - n);

    return bitwise_or(rs, ls);
}

/* Functions defined for SHA-256 */

/**
 * The first of six logical functions defined for SHA-256.
 * Referred to as "Ch" in the specification.
 */
BKH_PURE static constexpr word F0(word x, word y, word z) noexcept
{
    word const l = bitwise_and(x, y);
    word const r = bitwise_and(bitwise_complement(x), z);

    return bitwise_xor(l, r);
}

/**
 * The second of six logical functions defined for SHA-256.
 * Referred to as "Maj" in the specification.
 */
BKH_PURE static constexpr word F1(word x, word y, word z) noexcept
{
    word const t0 = bitwise_and(x, y);
    word const t1 = bitwise_and(x, z);
    word const t2 = bitwise_and(y, z);

    return bitwise_xor
    (
        bitwise_xor(t0, t1),
        t2
    );
}

/**
 * The third of six logical functions defined for SHA-256.
 * Referred to as "Sigma0" in the specification.
 */
BKH_PURE static constexpr word F2(word x) noexcept
{
    word const t0 = right_rotate(x,  2);
    word const t1 = right_rotate(x, 13);
    word const t2 = right_rotate(x, 22);

    return bitwise_xor
    (
        bitwise_xor(t0, t1),
        t2
    );
}

/**
 * The fourth of six logical functions defined for SHA-256.
 * Referred to as "Sigma1" in the specification.
 */
BKH_PURE static constexpr word F3(word x) noexcept
{
    word const t0 = right_rotate(x,  6);
    word const t1 = right_rotate(x, 11);
    word const t2 = right_rotate(x, 25);

    return bitwise_xor
    (
        bitwise_xor(t0, t1),
        t2
    );
}

/**
 * The fifth of six logical functions defined for SHA-256.
 * Referred to as "sigma0" in the specification.
 */
BKH_PURE static constexpr word F4(word x) noexcept
{
    word const t0 = right_rotate(x,  7);
    word const t1 = right_rotate(x, 18);
    word const t2 = right_shift (x,  3);

    return bitwise_xor
    (
        bitwise_xor(t0, t1),
        t2
    );
}

/**
 * The last of six logical functions defined for SHA-256.
 * Referred to as "sigma1" in the specification.
 */
BKH_PURE static constexpr word F5(word x) noexcept
{
    word const t0 = right_rotate(x, 17);
    word const t1 = right_rotate(x, 19);
    word const t2 = right_shift (x, 10);

    return bitwise_xor
    (
        bitwise_xor(t0, t1),
        t2
    );
}

/* Constants defined for SHA-256 */

/**
 * These 64 constant words are used in the transform
 * and represent the first 32 bits of the fractional
 * parts of the cube roots of the first 64 prime
 * numbers.
 */
static constexpr word const sha256_hash_constants[64]
{
    0x428A2F98u, 0x71374491u, 0xB5C0FBCFu, 0xE9B5DBA5u,
    0x3956C25Bu, 0x59F111F1u, 0x923F82A4u, 0xAB1C5ED5u,
    0xD807AA98u, 0x12835B01u, 0x243185BEu, 0x550C7DC3u,
    0x72BE5D74u, 0x80DEB1FEu, 0x9BDC06A7u, 0xC19BF174u,
    0xE49B69C1u, 0xEFBE4786u, 0x0FC19DC6u, 0x240CA1CCu,
    0x2DE92C6Fu, 0x4A7484AAu, 0x5CB0A9DCu, 0x76F988DAu,
    0x983E5152u, 0xA831C66Du, 0xB00327C8u, 0xBF597FC7u,
    0xC6E00BF3u, 0xD5A79147u, 0x06CA6351u, 0x14292967u,
    0x27B70A85u, 0x2E1B2138u, 0x4D2C6DFCu, 0x53380D13u,
    0x650A7354u, 0x766A0ABBu, 0x81C2C92Eu, 0x92722C85u,
    0xA2BFE8A1u, 0xA81A664Bu, 0xC24B8B70u, 0xC76C51A3u,
    0xD192E819u, 0xD6990624u, 0xF40E3585u, 0x106AA070u,
    0x19A4C116u, 0x1E376C08u, 0x2748774Cu, 0x34B0BCB5u,
    0x391C0CB3u, 0x4ED8AA4Au, 0x5B9CCA4Fu, 0x682E6FF3u,
    0x748F82EEu, 0x78A5636Fu, 0x84C87814u, 0x8CC70208u,
    0x90BEFFFAu, 0xA4506CEBu, 0xBEF9A3F7u, 0xC67178F2u
};

/**
 * These 8 constant words are the initial hash value
 * used in SHA-256 and were obtained by taking the
 * first 32 bits of the fractional parts of the
 * square roots of the first eight prime numbers.
 */
static constexpr word const sha256_initial_hash_value[8]
{
    0x6A09E667u, 0xBB67AE85u, 0x3C6EF372u, 0xA54FF53Au,
    0x510E527Fu, 0x9B05688Cu, 0x1F83D9ABu, 0x5BE0CD19u
};

/* Helpers */

using bkh::u64;

/**
 * Performs an unchecked copy of data from one buffer
 * to another. Buffers may not overlap.
 */
static void unsafe_copy(byte* BKH_RESTRICT dst, byte const* BKH_RESTRICT src, u64 count) noexcept
{
    for (u64 i = 0; i < count; i++)
    {
        dst[i] = src[i];
    }
}

/**
 * Writes an unsigned 64-bit value into an array as a
 * sequence of bytes in big-endian byte order.
 */
static void write_be_u64(byte* ptr, u64 value) noexcept
{
#if (BYTE_ORDER == LITTLE_ENDIAN)
    *reinterpret_cast<u64*>(ptr) = 
        ((value & 0x00000000000000FFull) << 56u) |
        ((value & 0x000000000000FF00ull) << 40u) |
        ((value & 0x0000000000FF0000ull) << 24u) |
        ((value & 0x00000000FF000000ull) <<  8u) |
        ((value & 0x000000FF00000000ull) >>  8u) |
        ((value & 0x0000FF0000000000ull) >> 24u) |
        ((value & 0x00FF000000000000ull) >> 40u) |
        ((value & 0xFF00000000000000ull) >> 56u);
#else
    *reinterpret_cast<u64*>(ptr) = value;
#endif
}

/* Implementation */

void bkh::sha256::sha256_context::init() noexcept
{
    //Sanity check
    static_assert(sizeof(this->state) == sizeof(sha256_initial_hash_value));

    //Get the number of words in the state
    constexpr int const count = sizeof(this->state) / sizeof(word);

    //Copy the words into our state
    for (int i = 0; i < count; i++)
    {
        this->state[i] = sha256_initial_hash_value[i];
    }
}

void bkh::sha256::sha256_context::transform_block(byte const* data) noexcept
{
    //Initialize our eight working variables with previous state
    word a = this->state[0],
         b = this->state[1],
         c = this->state[2],
         d = this->state[3],
         e = this->state[4],
         f = this->state[5],
         g = this->state[6],
         h = this->state[7];

    //Treat the input as words
    word const* M = reinterpret_cast<word const*>(data);

    //Prepare the message schedule W
    word W[64];
    for (int t = 0; t < 16; t++)
    {
#if (BYTE_ORDER == LITTLE_ENDIAN)
        W[t] = ((M[t] & 0x000000FFu) << 24u) |
               ((M[t] & 0x0000FF00u) <<  8u) |
               ((M[t] & 0x00FF0000u) >>  8u) |
               ((M[t] & 0xFF000000u) >> 24u);
#else
        W[t] = M[t];
#endif
    }
    for (int t = 16; t < 64; t++)
    {
        W[t] = F5(W[t - 2]) + W[t - 7] + F4(W[t - 15]) + W[t - 16];
    }

    //Perform the main transformation
    for (int t = 0; t < 64; t++)
    {
        word T1 = h + F3(e) + F0(e, f, g) + sha256_hash_constants[t] + W[t];
        word T2 = F2(a) + F1(a, b, c);

        h = g;
        g = f;
        f = e;
        e = d + T1;
        d = c;
        c = b;
        b = a;
        a = T1 + T2;
    }

    //Calculate the intermediate hash value
    this->state[0] += a;
    this->state[1] += b;
    this->state[2] += c;
    this->state[3] += d;
    this->state[4] += e;
    this->state[5] += f;
    this->state[6] += g;
    this->state[7] += h;
}

bool bkh::sha256::sha256_context::pad_block(byte const* data, u64 data_length, u64 message_length, byte* result_buffer) noexcept
{
    //Check that it's not too big
    assert(message_length < sha256::max_message_length);

    //Check for the case where data is null, which means just fill with zeroes and message_length
    if (data == nullptr)
    {
        //A small sanity check
        assert(data_length == 0);

        //Calculate number of zeroes to write
        constexpr auto const zeroes = sha256::block_length - sizeof(u64);

        //Write the zeroes
        byte* p   = result_buffer;
        byte* end = result_buffer + zeroes;
        while (p != end) *(p++) = 0;

        //Write the length
        u64 const bit_count = message_length * 8;
        write_be_u64(p, bit_count);

        //We're done
        return true;
    }

    //The user should pass full blocks to update_transform
    assert(data_length < sha256::block_length);

    //Check if we can skip the copying
    if (data != result_buffer) 
        unsafe_copy(result_buffer, data, data_length);

    //Write the 0x80 byte
    byte* p = result_buffer + data_length;
    *(p++)  = 0x80;

    //Check if there's enough space to add everything
    constexpr auto const min_bytes = 1 + sizeof(u64); //The byte 0x80 + length of message
    if (data_length <= sha256::block_length - min_bytes)
    {
        //Calculate the number of zeroes to write
        auto const zeroes = (sha256::block_length - min_bytes) - data_length;

        //Write the zeroes
        byte* end = p + zeroes;
        while (p != end) *(p++) = 0;

        //Write the length
        u64 const bit_count = message_length * 8;
        write_be_u64(p, bit_count);

        //We're done
        return true;
    }

    //Calculate the number of zeroes we can add
    auto const zeroes = (sha256::block_length - 1) - data_length;

    //Write the zeroes
    byte* end = p + zeroes;
    while (p != end) *(p++) = 0;

    //User needs to call us again
    return false;
}

void bkh::sha256::sha256_context::get_digest(byte* result_buffer) noexcept
{
    //Get the number of words in the state
    constexpr int const count = sizeof(this->state) / sizeof(word);

    //Iterate over the words
    for (int i = 0; i < count; i++)
    {
        //Read the word
        word const &w = this->state[i];

        //Insert the bytes in big-endian order
        result_buffer[i * 4 + 0] = static_cast<byte>((w & 0xFF000000u) >> 24u);
        result_buffer[i * 4 + 1] = static_cast<byte>((w & 0x00FF0000u) >> 16u);
        result_buffer[i * 4 + 2] = static_cast<byte>((w & 0x0000FF00u) >>  8u);
        result_buffer[i * 4 + 3] = static_cast<byte>((w & 0x000000FFu) >>  0u);
    }
}

void bkh::sha256::sha256_context::clear_state() noexcept
{
    /**
     * Prepare a volatile pointer which will not have its writes
     * optimized away by the compiler.
     */
    auto* vptr = reinterpret_cast<char volatile*>(this->state);
    for (int i = sizeof(this->state); --i;)
    {
        *(vptr++) = 0;
    }
}

void bkh::sha256::compute_hash(byte const* data, u64 data_length, byte* result) noexcept
{
    constexpr u64 const mask = ~static_cast<u64>(block_length - 1);

    //Mask away the stuff we have to handle separately
    auto const masked_length = data_length & mask;

    //Prepare our pointers
    byte const*       p   = data;
    byte const* const end = data + masked_length;

    //Setup the context
    context ctx;
    ctx.init();

    //Iterate over the blocks
    while (p != end)
    {
        //Perform the transform and advance
        ctx.transform_block(p);
        p += block_length;
    }

    //Calculate the remaining data
    auto const remaining = data_length - masked_length;

    //Perform the padding
    byte buf[block_length];
    bool done = context::pad_block(p, remaining, data_length, buf);

    //Handle the final block(s)
    ctx.transform_block(buf);
    if (!done)
    {
        context::pad_block(nullptr, 0, data_length, buf);
        ctx.transform_block(buf);
    }

    //Retrieve the message digest
    ctx.get_digest(result);
    ctx.clear_state();
}
