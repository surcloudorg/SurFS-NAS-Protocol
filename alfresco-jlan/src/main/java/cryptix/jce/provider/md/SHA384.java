/* $Id: SHA384.java,v 1.2 2001/06/25 15:39:55 gelderen Exp $
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
 * SHA-384
 *
 * @version $Revision: 1.2 $
 * @author  Jeroen C. van Gelderen (gelderen@cryptix.org)
 */
public final class SHA384 extends SHA512Base implements Cloneable {

    /** Size (in bytes) of this hash */
    private static final int HASH_SIZE = 48;

// Ctors
//...........................................................................

    public SHA384() { super(HASH_SIZE); }


    private SHA384(SHA384 src) {
        super(src);
    }


    public Object clone() {
        return new SHA384(this);
    }


// Implementation
//...........................................................................

    protected void loadInitialValues(long[] context) {
        context[0] = 0xcbbb9d5dc1059ed8L;
        context[1] = 0x629a292a367cd507L;
        context[2] = 0x9159015a3070dd17L;
        context[3] = 0x152fecd8f70e5939L;
        context[4] = 0x67332667ffc00b31L;
        context[5] = 0x8eb44a8768581511L;
        context[6] = 0xdb0c2e0d64f98fa7L;
        context[7] = 0x47b5481dbefa4fa4L;
    }


    protected void generateDigest(long[] context, byte[] buf, int off) {
        for( int i=0; i<context.length-2; i++ )
            for( int j=0; j<8 ; j++ )
                buf[off+(i * 8 + (7-j))] = (byte)(context[i] >>> (8 * j));
    }
}
