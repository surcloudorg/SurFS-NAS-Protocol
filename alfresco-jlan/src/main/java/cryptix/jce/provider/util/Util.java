/* $Id: Util.java,v 1.3 2003/02/07 15:06:24 gelderen Exp $
 *
 * Copyright (C) 2000 The Cryptix Foundation Limited.
 * All rights reserved.
 * 
 * Use, modification, copying and distribution of this software is subject 
 * the terms and conditions of the Cryptix General Licence. You should have 
 * received a copy of the Cryptix General Licence along with this library; 
 * if not, you can download a copy from http://www.cryptix.org/ .
 */
package cryptix.jce.provider.util;


import java.math.BigInteger;


/**
 * Misc utility methods.
 *
 * @version $Revision: 1.3 $
 * @author  Jeroen C. van Gelderen (gelderen@cryptix.org)
 */
public final class Util
{
    public static final BigInteger BI_ZERO = BigInteger.valueOf(0L);


    public static final BigInteger BI_ONE = BigInteger.valueOf(1L);


    private Util() {}
    

    /**
     * Fit (stretch or shrink) the given positive BigInteger into a 
     * byte[] of resultByteLen bytes without losing precision.
     *
     * @trhows IllegalArgumentException
     *         If x negative, or won't fit in requested number of bytes.
     */
    public static byte[] toFixedLenByteArray(BigInteger x, int resultByteLen) {

        if (x.signum() != 1)
            throw new IllegalArgumentException("BigInteger not positive.");

        byte[] x_bytes = x.toByteArray();
        int x_len = x_bytes.length;

        if (x_len <= 0)
            throw new IllegalArgumentException("BigInteger too small.");

        /*
         * The BigInteger contract specifies that we now have at most one
         * superfluous leading zero byte:
         */
        int x_off = (x_bytes[0] == 0) ? 1 : 0;
        x_len -= x_off;

        /*
         * Check whether the BigInteger will fit in the requested byte length.
         */
        if ( x_len > resultByteLen)
            throw new IllegalArgumentException("BigInteger too large.");

        /*
         * Now stretch or shrink the encoding to fit in resByteLen bytes.
         */
        byte[] res_bytes = new byte[resultByteLen];
        int res_off = resultByteLen-x_len;
        System.arraycopy(x_bytes, x_off, res_bytes, res_off, x_len);
        return res_bytes;
    }


    /**
     * Compare two byte[] for equality. byte[]s are considered equal if they
     * have the same length and the same contents (same elems, same order).
     * Additionally, two null arguments compare equal too.
     */
    public static boolean equals(byte[] a, byte[] b) {

        if( a==null && b==null ) return true;

        if( a==null ^ b==null ) return false;

        int aLen = a.length;
        int bLen = b.length;
        if( aLen != bLen ) return false;

        for(int i=0; i<aLen; i++)
            if( a[i] != b[i] ) return false;

        return true;
    }
}
