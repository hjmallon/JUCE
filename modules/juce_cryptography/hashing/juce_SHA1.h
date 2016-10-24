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

#ifndef JUCE_SHA1_H_INCLUDED
#define JUCE_SHA1_H_INCLUDED


//==============================================================================
/**
    SHA-1 UNSECURE hash generator. Do not use this class for cryptographic uses.

    Create one of these objects from a block of source data or a stream, and it
    calculates the SHA-1 hash of that data.

    You can retrieve the hash as a raw 32-byte block, or as a 64-digit hex string.
    @see MD5, SHA256
*/
class JUCE_API  SHA1
{
public:
    //==============================================================================
    /** Creates an empty SHA1 object.
        The default constructor just creates a hash filled with zeros. (This is not
        equal to the hash of an empty block of data).
    */
    SHA1() noexcept;

    /** Destructor. */
    ~SHA1() noexcept;

    /** Creates a copy of another SHA1. */
    SHA1 (const SHA1& other) noexcept;

    /** Copies another SHA1. */
    SHA1& operator= (const SHA1& other) noexcept;

    //==============================================================================
    /** Creates a hash from a block of raw data. */
    explicit SHA1 (const MemoryBlock& data);

    /** Creates a hash from a block of raw data. */
    SHA1 (const void* data, size_t numBytes);

    /** Creates a hash from the contents of a stream.

        This will read from the stream until the stream is exhausted, or until
        maxBytesToRead bytes have been read. If maxBytesToRead is negative, the entire
        stream will be read.
    */
    SHA1 (InputStream& input, int64 maxBytesToRead = -1);

    /** Reads a file and generates the hash of its contents.
        If the file can't be opened, the hash will be left uninitialised (i.e. full
        of zeros).
    */
    explicit SHA1 (const File& file);

    /** Creates a checksum from a UTF-8 buffer.
        E.g.
        @code SHA1 checksum (myString.toUTF8());
        @endcode
    */
    explicit SHA1 (CharPointer_UTF8 utf8Text) noexcept;

    //==============================================================================
    /** Returns the hash as a 32-byte block of data. */
    MemoryBlock getRawData() const;

    /** Returns the checksum as a 64-digit hex string. */
    String toHexString() const;

    //==============================================================================
    bool operator== (const SHA1&) const noexcept;
    bool operator!= (const SHA1&) const noexcept;


private:
    //==============================================================================
    uint8 result [20];
    void process (const void*, size_t);

    JUCE_LEAK_DETECTOR (SHA1)
};


#endif   // JUCE_SHA1_H_INCLUDED
