/* $Id: SHA512.java,v 1.2 2001/06/25 15:39:55 gelderen Exp $
 *
 * Copyright (C) 2001 The Cryptix Foundation Limited. All rights reserved.
 *
 * Use, modification, copying and distribution of this software is subject to
 * the terms and conditions of the Cryptix General Licence. You should have
 * received a copy of the Cryptix General Licence along with this library;
 * if not, you can download a copy from http://www.cryptix.org/ .
 */

package cryptix.jce.provider.md;


/**
 * SHA-512
 *
 * @version $Revision: 1.2 $
 * @author  Jeroen C. van Gelderen (gelderen@cryptix.org)
 */
public final class SHA512 extends SHA512Base implements Cloneable {

    /** Size (in bytes) of this hash */
    private static final int HASH_SIZE = 64;

// Ctors
//...........................................................................

    public SHA512() { super(HASH_SIZE); }


    private SHA512(SHA512 src) {
        super(src);
    }


    public Object clone() {
        return new SHA512(this);
    }


// Implementation
//...........................................................................

    protected void loadInitialValues(long[] context) {
        // initial values
        context[0] = 0x6a09e667f3bcc908L;
        context[1] = 0xbb67ae8584caa73bL;
        context[2] = 0x3c6ef372fe94f82bL;
        context[3] = 0xa54ff53a5f1d36f1L;
        context[4] = 0x510e527fade682d1L;
        context[5] = 0x9b05688c2b3e6c1fL;
        context[6] = 0x1f83d9abfb41bd6bL;
        context[7] = 0x5be0cd19137e2179L;
    }


    protected void generateDigest(long[] context, byte[] buf, int off) {
        for( int i=0; i<context.length; i++ )
            for( int j=0; j<8 ; j++ )
                buf[off+(i * 8 + (7-j))] = (byte)(context[i] >>> (8 * j));
    }
}
