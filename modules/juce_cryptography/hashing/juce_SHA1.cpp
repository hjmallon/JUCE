/*
  ==============================================================================

   This file is part of the JUCE library.
   Copyright (c) 2015 - ROLI Ltd.

   Permission is granted to use this software under the terms of either:
   a) the GPL v2 (or any later version)
   b) the Affero GPL v3

   Details of these licenses can be found at: www.gnu.org/licenses

   JUCE is distributed in the hope that it will be useful, but WITHOUT ANY
   WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
   A PARTICULAR PURPOSE.  See the GNU General Public License for more details.

   ------------------------------------------------------------------------------

   To release a closed-source product which uses JUCE, commercial licenses are
   available: visit www.juce.com for more information.

  ==============================================================================
*/

class SHA1Processor
{
public:
    SHA1Processor() noexcept
    : length (0)
    {
        init(state);
    }

    // expects 64 bytes of data
    void processFullBlock (const void* const data) noexcept
    {
        uint32 s[5];
        memcpy (s, state, sizeof (s));

        uint32 block[80];

        for (int i = 0; i < 16; ++i)
            block[i] = ByteOrder::bigEndianInt (addBytesToPointer (data, i * 4));

        for (int i = 16; i < 80; ++i)
            block[i] = lrotate(block[i-3] ^ block[i-8] ^ block[i-14] ^ block[i-16], 1);

        for (int i = 0; i < 80; ++i)
        {
            uint32 k, f, temp;

            if (i < 20)
            {
                f = (s[1] & s[2]) | (~s[1] & s[3]);
                k = 0x5a827999u;
            }
            else if (i < 40)
            {
                f = s[1] ^ s[2] ^ s[3];
                k = 0x6ed9eba1u;
            }
            else if (i < 60)
            {
                f = (s[1] & s[2]) | (s[1] & s[3]) | (s[2] & s[3]);
                k = 0x8f1bbcdcu;
            }
            else // i < 80
            {
                f = s[1] ^ s[2] ^ s[3];
                k = 0xca62c1d6u;
            }

            temp = lrotate(s[0], 5) + f + s[4] + k + block[i];
            s[4] = s[3];
            s[3] = s[2];
            s[2] = lrotate(s[1], 30);
            s[1] = s[0];
            s[0] = temp;
        }

        for (int i = 0; i < 6; ++i)
            state[i] += s[i];

        length += 64;
    }

    void processFinalBlock (const void* const data, unsigned int numBytes) noexcept
    {
        jassert (numBytes < 64);

        length += numBytes;
        length *= 8; // (the length is stored as a count of bits, not bytes)

        uint8 finalBlocks[128];

        memcpy (finalBlocks, data, numBytes);
        finalBlocks [numBytes++] = 128; // append a '1' bit

        while (numBytes != 56 && numBytes < 64 + 56)
            finalBlocks [numBytes++] = 0; // pad with zeros..

        for (int i = 8; --i >= 0;)
            finalBlocks [numBytes++] = (uint8) (length >> (i * 8)); // append the length.

        jassert (numBytes == 64 || numBytes == 128);

        processFullBlock (finalBlocks);

        if (numBytes > 64)
            processFullBlock (finalBlocks + 64);
    }

    void copyResult (uint8* result) const noexcept
    {
        for (int i = 0; i < 5; ++i)
        {
            const uint32 val (ByteOrder::swapIfLittleEndian(state[i]));
            memcpy(result + (4 * i), &val, 4);
        }
    }

    void processStream (InputStream& input, int64 numBytesToRead, uint8* const result)
    {
        if (numBytesToRead < 0)
            numBytesToRead = std::numeric_limits<int64>::max();

        for (;;)
        {
            uint8 buffer [64];
            const int bytesRead = input.read (buffer, (int) jmin (numBytesToRead, (int64) sizeof (buffer)));

            if (bytesRead < (int) sizeof (buffer))
            {
                processFinalBlock (buffer, (unsigned int) bytesRead);
                break;
            }

            numBytesToRead -= sizeof (buffer);
            processFullBlock (buffer);
        }

        copyResult (result);
    }

private:
    uint32 state[5];
    uint64 length;

    static inline uint32 lrotate (const uint32 x, const uint32 y) noexcept                { return (x << y) ^ (x >> (32 - y)); }
    static inline void init (uint32* s)
    {
        s[0] = 0x67452301u;
        s[1] = 0xefcdab89u;
        s[2] = 0x98badcfeu;
        s[3] = 0x10325476u;
        s[4] = 0xc3d2e1f0u;
    }

    JUCE_DECLARE_NON_COPYABLE (SHA1Processor)
};

//==============================================================================
SHA1::SHA1() noexcept
{
    zerostruct (result);
}

SHA1::~SHA1() noexcept {}

SHA1::SHA1 (const SHA1& other) noexcept
{
    memcpy (result, other.result, sizeof (result));
}

SHA1& SHA1::operator= (const SHA1& other) noexcept
{
    memcpy (result, other.result, sizeof (result));
    return *this;
}

SHA1::SHA1 (const MemoryBlock& data)
{
    process (data.getData(), data.getSize());
}

SHA1::SHA1 (const void* const data, const size_t numBytes)
{
    process (data, numBytes);
}

SHA1::SHA1 (InputStream& input, const int64 numBytesToRead)
{
    SHA1Processor processor;
    processor.processStream (input, numBytesToRead, result);
}

SHA1::SHA1 (const File& file)
{
    FileInputStream fin (file);

    if (fin.getStatus().wasOk())
    {
        SHA1Processor processor;
        processor.processStream (fin, -1, result);
    }
    else
    {
        zerostruct (result);
    }
}

SHA1::SHA1 (CharPointer_UTF8 utf8) noexcept
{
    jassert (utf8.getAddress() != nullptr);
    process (utf8.getAddress(), utf8.sizeInBytes() - 1);
}

void SHA1::process (const void* const data, size_t numBytes)
{
    MemoryInputStream m (data, numBytes, false);
    SHA1Processor processor;
    processor.processStream (m, -1, result);
}

MemoryBlock SHA1::getRawData() const
{
    return MemoryBlock (result, sizeof (result));
}

String SHA1::toHexString() const
{
    return String::toHexString (result, sizeof (result), 0);
}

bool SHA1::operator== (const SHA1& other) const noexcept  { return memcmp (result, other.result, sizeof (result)) == 0; }
bool SHA1::operator!= (const SHA1& other) const noexcept  { return ! operator== (other); }


//==============================================================================
#if JUCE_UNIT_TESTS

class SHA1Tests  : public UnitTest
{
public:
    SHA1Tests() : UnitTest ("SHA-1") {}

    void test (const char* input, const char* expected)
    {
        {
            SHA1 hash (input, strlen (input));
            expectEquals (hash.toHexString(), String (expected));
        }

        {
            CharPointer_UTF8 utf8 (input);
            SHA1 hash (utf8);
            expectEquals (hash.toHexString(), String (expected));
        }

        {
            MemoryInputStream m (input, strlen (input), false);
            SHA1 hash (m);
            expectEquals (hash.toHexString(), String (expected));
        }
    }

    void runTest() override
    {
        beginTest ("SHA1");

        test ("", "da39a3ee5e6b4b0d3255bfef95601890afd80709");
        test ("The quick brown fox jumps over the lazy dog",  "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12");
        test ("The quick brown fox jumps over the lazy dog.", "408d94384216f890ff7a0c3528e8bed1e0b01621");
    }
};

static SHA1Tests SHA1UnitTests;

#endif
