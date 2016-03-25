/* $Id: PaddingMD.java,v 1.8 2001/06/25 15:39:55 gelderen Exp $
 *
 * Copyright (C) 1995-2000 The Cryptix Foundation Limited.
 * All rights reserved.
 *
 * Use, modification, copying and distribution of this software is subject to
 * the terms and conditions of the Cryptix General Licence. You should have
 * received a copy of the Cryptix General Licence along with this library;
 * if not, you can download a copy from http://www.cryptix.org/ .
 */

package cryptix.jce.provider.md;


import java.security.DigestException;
import java.security.MessageDigestSpi;


/**
 * This abstract class implements the MD4-like block/padding structure as it is
 * used by most hashes (MD4, MD5, SHA-0, SHA-1, RIPEMD-128, RIPEMD-160, Tiger).
 *
 * This class handles the message buffering, bit counting and padding.
 * Subclasses need implement only the three abstract functions to create a
 * working hash.
 *
 * This class has three padding modes: MD5-like, SHA-like and Tiger-like.
 * This applies to the padding and encoding of the 64-bit length counter.
 *
 * @version $Revision: 1.8 $
 * @author  Jeroen C. van Gelderen (gelderen@cryptix.org)
 */
abstract class PaddingMD
extends MessageDigestSpi
{

// Constants
//...........................................................................

    private static final int DEFAULT_BLOCKSIZE = 64;


// Instance variables
//...........................................................................

    /** Size (in bytes) of the blocks. */
    private final int blockSize;


    /** Size (in bytes) of the digest */
    private final int hashSize;


    /** 64 byte buffer */
    private final byte[] buf;


    /** Buffer offset */
    private int bufOff;


    /** Number of bytes hashed 'till now. */
    private long byteCount;


    /** Mode */
    private final int mode;


    /*package*/ static final int
        MODE_MD    = 0,
        MODE_SHA   = 1,
        MODE_TIGER = 2;


// Constructors
//...........................................................................


    /**
     * Construct a 64-byte PaddingMD in MD-like, SHA-like or Tiger-like
     * padding mode.
     *
     * The subclass must call this constructor, giving the length of it's hash
     * in bytes.
     *
     * @param hashSize  Length of the hash in bytes.
     */
    protected PaddingMD(int hashSize, int mode) {
        this(DEFAULT_BLOCKSIZE, hashSize, mode);
    }


    /**
     * Construct a 64 or 128-byte PaddingMD in MD-like, SHA-like or Tiger-like
     * padding mode.
     *
     * @param hashSize  Length of the hash in bytes.
     */
    protected PaddingMD(int blockSize, int hashSize, int mode) {
        if( blockSize != 64 && blockSize != 128 )
            throw new RuntimeException("blockSize must be 64 or 128!");

        this.blockSize = blockSize;
        this.hashSize  = hashSize;
        this.buf       = new byte[blockSize];
        this.bufOff    = 0;
        this.byteCount = 0;
        this.mode      = mode;
    }


    protected PaddingMD(PaddingMD src) {
        this.blockSize = src.blockSize;
        this.hashSize  = src.hashSize;
        this.buf       = (byte[])src.buf.clone();
        this.bufOff    = src.bufOff;
        this.byteCount = src.byteCount;
        this.mode      = src.mode;
    }


    public Object clone() throws CloneNotSupportedException {
        throw new CloneNotSupportedException("You have just found a bug!");
    }


// Implementation
//...........................................................................

    protected int engineGetDigestLength() {
        return this.hashSize;
    }


    protected void engineUpdate(byte input) {
        //#ASSERT(this.bufOff < blockSize);

        byteCount += 1;
        buf[bufOff++] = input;
        if( bufOff==blockSize ) {
            coreUpdate(buf, 0);
            bufOff = 0;
        }

        //#ASSERT(this.bufOff < blockSize);
    }


    protected void engineUpdate(byte[] input, int offset, int length) {
        byteCount += length;

        //#ASSERT(this.bufOff < blockSize);

        int todo;
        while( length >= (todo = blockSize - this.bufOff) ) {
            System.arraycopy(input, offset, this.buf, this.bufOff, todo);
            coreUpdate(this.buf, 0);
            length -= todo;
            offset += todo;
            this.bufOff = 0;
        }

        //#ASSERT(this.bufOff < blockSize);

        System.arraycopy(input, offset, this.buf, this.bufOff, length);
        bufOff += length;
    }


    protected byte[] engineDigest() {
        byte[] tmp = new byte[hashSize];
        privateDigest(tmp, 0, hashSize);
        return tmp;
    }


    protected int engineDigest(byte[] buf, int offset, int len)
    throws DigestException
    {
        if(len<hashSize)
            throw new DigestException();

        return privateDigest(buf, offset, len);
    }


    /**
     * Same as protected int engineDigest(byte[] buf, int offset, int len)
     * except that we don't validate arguments.
     */
    private int privateDigest(byte[] buf, int offset, int len)
    {
        //#ASSERT(this.bufOff < blockSize);

        this.buf[this.bufOff++] = (mode==MODE_TIGER) ? (byte)0x01 : (byte)0x80;

        int lenOfBitLen = (blockSize==128) ? 16 : 8;
        int C = blockSize - lenOfBitLen;
        if(this.bufOff > C) {
            while(this.bufOff < blockSize)
                this.buf[this.bufOff++] = (byte)0x00;

            coreUpdate(this.buf, 0);
            this.bufOff = 0;
        }

        while(this.bufOff < C)
            this.buf[this.bufOff++] = (byte)0x00;

        long bitCount = byteCount * 8;
        if(blockSize==128)
            for(int i=0; i<8; i++)
                this.buf[this.bufOff++] = 0x00;

        if(mode==MODE_SHA) {
            // 64-bit length is appended in big endian order
            for(int i=56; i>=0; i-=8)
                this.buf[this.bufOff++] = (byte)(bitCount >>> (i) );
        } else {
            // 64-bit length is appended in little endian order
            for(int i=0; i<64; i+=8)
                this.buf[this.bufOff++] = (byte)(bitCount >>> (i) );
        }

        coreUpdate(this.buf, 0);
        coreDigest(buf, offset);

        engineReset();
        return hashSize;
    }


    protected void engineReset() {
        this.bufOff    = 0;
        this.byteCount = 0;
        coreReset();
    }


// Delegated methods
//...........................................................................

    /**
     * Return the hash bytes in <code>buf</code>, starting at offset
     * <code>off</code>.
     *
     * The subclass is expected to write exactly <code>hashSize</code> bytes
     * in the given buffer. The buffer is guaranteed to be large enough.
     */
    protected abstract void coreDigest(byte[] buf, int off);


    /**
     * Reset the hash internal structures to initial state.
     */
    protected abstract void coreReset();


    /**
     * Update the internal state with a single block.
     *
     * <code>buf</code> contains a single block (64 bytes, 512 bits) of data,
     * starting at offset <code>off</code>.
     */
    protected abstract void coreUpdate(byte[] buf, int off);
}