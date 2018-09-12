#ifndef BKH_SHA256_H
#define BKH_SHA256_h
#pragma once

/** sha256.h - Bendik Hillestad - Public Domain
 * Implements SHA-256 as described in FIPS PUB 180-4 (August 2015).
 *
 * This implementation exposes both a high-level and a low-level
 * API for computing the SHA-256 digest of a message.
 * The API is designed with two main goals in mind:
 *   1) Being highly predictable and deterministic.
 *   2) Not imposing any requirements on the user.
 * As such it does not perform any runtime allocations nor does
 * it use any exceptions or rtti. Additionally, the interface
 * does not demand the use of STL containers or smart pointers.
 * As a final point, this implementation can trivially be made
 * to not rely on the C++ Standard Library nor the C runtime.
 *
 * Performance was not a goal when writing this code, however
 * it should not be slower than most implementations.
 *
 * Using the API:
 * For convenience, a high-level API is provided for computing
 * the message digest in a single function call.
 * Example:
 
    using byte = unsigned char;
  
    //Some data
    std::vector<byte> vec{ ... };
  
    //Compute the digest
    byte result[sha256::digest_length];
    sha256::compute_hash(vec.data(), vec.size(), result);
  
 * For more advanced cases, such as when computing the digest
 * of an unknown-length stream of data, a lower level API is
 * provided. Note that this API does not track the length of
 * the message for you, any bookkeeping is left to the user.
 * Example:

    using byte = unsigned char;
 
    //Track the total length
    std::uint64_t total_length = 0;
  
    //Prepare the context
    sha256::context ctx;
    ctx.init();
  
    //Begin some trivial example reading loop
    bool reading_data = true;
    while (reading_data)
    {
        //Read some data
        byte buf[sha256::block_length];
        int read = read_some_data(buf, sizeof(buf));
        total_length += read;
  
        //Check if we read a full block
        if (read == sha256::block_length)
        {
            //Perform the transform
            ctx.transform_block(buf);
        }
        else
        {
            //This SHOULD be the final block
            reading_data = false;
  
            //Perform padding, reusing `buf`
            bool done = ctx.pad_block(
                buf, read, total_length, buf
            );
  
            //Perform the transform
            ctx.transform_block(buf);
            if (!done)
            {
                //We couldn't fully pad, so we
                //give a null block to finish.
                ctx.pad_block(
                    nullptr, 0, total_length, buf
                );
                ctx.transform_block(buf);
            }
        }
        
        //Retrieve the message digest
        byte digest[sha256::digest_length];
        ctx.get_digest(digest);
        ctx.clear_state();
    }
	
 *
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

#if !defined(BKH_SHA256_NO_CSTDINT)

#include <cstdint>

namespace bkh
{
    using u8  = std::uint8_t;
    using u32 = std::uint32_t;
    using u64 = std::uint64_t;
};

#else
	
namespace bkh
{
    using u8  = unsigned char;
    using u32 = unsigned int;
    using u64 = unsigned long long;
};

#endif

//Sanity check
static_assert(sizeof(bkh::u8)  == 1);
static_assert(sizeof(bkh::u32) == 4);
static_assert(sizeof(bkh::u64) == 8);

namespace bkh
{
    struct sha256
    {
        static constexpr int const block_length       = 512 / 8;
        static constexpr int const digest_length      = 256 / 8;
        static constexpr u64 const max_message_length = 0x2000000000000000ull;

        using byte = u8;
        using word = u32;

        /**
         * Computes the SHA-256 hash of an octet string. The result
         * is written to the provided `result` pointer, which is
         * expected to point to a buffer with a capacity equal to
         * or greater than the sha256::digest_length.
         */
        static void compute_hash(
            byte const* data,
            u64         data_length,
            byte*       result
        ) noexcept;

        /**
         * A low-level hashing primitive.
         */
        using context = struct sha256_context
        {
        public:
            /**
             * Prepares or resets the context. Must be called
             * before computing the hash of a new message.
             */
            void init() noexcept;

            /**
             * Feeds a single block to the SHA-256 transform,
             * updating the intermediate hash value of the
             * message. Must be called for each block length
             * sized chunk of the message.
             */
            void transform_block(byte const* data) noexcept;

            /**
             * Pads the block according to the SHA-256
             * specification and stores the result in the
             * provided buffer.
             * A return value of true means the block was
             * fully padded and the result can be passed
             * to transform_block.
             * A return value of false means the block
             * couldn't be fully padded, and this
             * function needs to be called again with a
             * null data pointer after passing the
             * previous result to transform_block.
             */
            static bool pad_block
            (
                byte const* data,
                u64         data_length,
                u64         message_length,
                byte*       result_buffer
            ) noexcept;

            /**
             * Retrieves the message digest. The provided
             * pointer is expected to point to a buffer
             * with capacity equal to or greater than the
             * sha256::digest_length.
             */
            void get_digest(byte* result_buffer) noexcept;

            /**
             * Clears the internal state.
             */
            void clear_state() noexcept;

        private:
            word state[sha256::digest_length / sizeof(word)];
        };

        sha256() = delete;
    };

    //Sanity check
    static_assert(sizeof(sha256::context) == sha256::digest_length);
};

#endif
