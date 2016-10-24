/*
  ==============================================================================

   This file is part of the juce_core module of the JUCE library.
   Copyright (c) 2015 - ROLI Ltd.

   Permission to use, copy, modify, and/or distribute this software for any purpose with
   or without fee is hereby granted, provided that the above copyright notice and this
   permission notice appear in all copies.

   THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH REGARD
   TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN
   NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
   DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER
   IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
   CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

   ------------------------------------------------------------------------------

   NOTE! This permissive ISC license applies ONLY to files within the juce_core module!
   All other JUCE modules are covered by a dual GPL/commercial license, so if you are
   using any other modules, be sure to check that you also comply with their license.

   For more details, visit www.juce.com

  ==============================================================================
*/

#ifndef JUCE_UUID_H_INCLUDED
#define JUCE_UUID_H_INCLUDED


//==============================================================================
/**
    A universally unique 128-bit identifier.

    This class generates very random unique numbers. It's vanishingly unlikely
    that two identical UUIDs would ever be created by chance. The values are
    formatted to meet the RFC 4122 version 4 standard.

    The class includes methods for saving the ID as a string or as raw binary data.
*/
class JUCE_API  Uuid
{
public:
    //==============================================================================
    /** Creates a new unique ID, compliant with RFC 4122 version 4. */
    Uuid();

    /** Destructor. */
    ~Uuid() noexcept;

    /** Creates a copy of another UUID. */
    Uuid (const Uuid&) noexcept;

    /** Copies another UUID. */
    Uuid& operator= (const Uuid&) noexcept;

    //==============================================================================
    /** Returns true if the ID is zero. */
    bool isNull() const noexcept;

    /** Returns a null Uuid object. */
    static Uuid null() noexcept;

    bool operator== (const Uuid&) const noexcept;
    bool operator!= (const Uuid&) const noexcept;

    //==============================================================================
    /** Returns a stringified version of this UUID.

        A Uuid object can later be reconstructed from this string using operator= or
        the constructor that takes a string parameter.

        @returns a 32 character hex string.
    */
    String toString() const;

    /** Returns a stringified version of this UUID, separating it into sections with dashes.
        @returns a string in the format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
    */
    String toDashedString() const;

    /** Creates an ID from an encoded string version.
        @see toString
    */
    Uuid (const String& uuidString);

    /** Copies from a stringified UUID.
        The string passed in should be one that was created with the toString() method.
    */
    Uuid& operator= (const String& uuidString);


    //==============================================================================
    /** Returns a pointer to the internal binary representation of the ID.

        This is an array of 16 bytes. To reconstruct a Uuid from its data, use
        the constructor or operator= method that takes an array of uint8s.
    */
    const uint8* getRawData() const noexcept                { return uuid; }

    /** Returns the Raw Data Size, which is always 16.
     */
    static const size_t getRawDataSize() noexcept           { return 16; }

    /** Creates a UUID from a 16-byte array.
        @see getRawData
    */
    Uuid (const uint8* rawData) noexcept;

    /** Sets this UUID from 16-bytes of raw data. */
    Uuid& operator= (const uint8* rawData) noexcept;

    //==============================================================================
    /** Creates a deterministic unique ID based on a SHA-1 hash. You can use
        this function to make a RFC 4122 version 5 compliant Uuid if you
        concatenate a Uuid defining a 'namespace' wih the 'name' (the data
        you are using) as follows.

        @code
        String test("www.example.org");

        MemoryBlock block;
        block.append(Uuid::namespaceDns.getRawData(),
                     Uuid::getRawDataSize());
        block.append(test.toRawUTF8(), test.getNumBytesAsUTF8());

        SHA1 hash (block);
        Uuid uuid = Uuid::fromSHA1(hash.getRawData());
        @endcode
     */
    static Uuid fromSHA1 (const MemoryBlock hash);

    /** Creates a deterministic unique ID based on the string representation of
        a SHA-1 hash. You can use this function to make a RFC 4122 version 5
        compliant Uuid.
        @see fromSHA1
     */
    static Uuid fromHexStringSHA1 (const String& hash);

    /** Creates a deterministic unique ID based on an MD5 hash. You can use this
        function to make a RFC 4122 version 3 compliant Uuid. SHA-1 based
        (version 5) are preferred.
        @see fromSHA1
     */
    static Uuid fromMD5 (const MemoryBlock hash);

    /** Creates a deterministic unique ID based on the string representation of
        an MD5 hash. You can use this function to make a RFC 4122 version 3
        compliant Uuid. SHA-1 based (version 5) are preferred.
        @see fromSHA1
     */
    static Uuid fromHexStringMD5 (const String& hash);

    /** Returns a name space ID for when the 'name string is a fully-qualified
        domain name' as defined in RFC 4122 Appendix C.
        @see fromSHA1
     */
    static const Uuid namespaceDns;

    /** Returns a name space ID for when the 'name string is a URL' as defined
        in RFC 4122 Appendix C.
        @see fromSHA1
     */
    static const Uuid namespaceUrl;

    /** Returns a name space ID for when the 'name string is an ISO OID' as
        defined in RFC 4122 Appendix C.
        @see fromSHA1
     */
    static const Uuid namespaceIsoOid;

    /** Returns a name space ID for when the 'name string is an X.500 DN
        (in DER or a text output format)' as defined in RFC 4122 Appendix C.
        @see fromSHA1
     */
    static const Uuid namespaceX500Dn;

private:
    //==============================================================================
    uint8 uuid[16];
    String getHexRegion (int, int) const;

    JUCE_LEAK_DETECTOR (Uuid)
};


#endif   // JUCE_UUID_H_INCLUDED
