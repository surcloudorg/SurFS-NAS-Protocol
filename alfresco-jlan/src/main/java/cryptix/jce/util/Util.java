/* $Id: Util.java,v 1.5 2001/05/19 01:09:45 gelderen Exp $
 *
 * Copyright (C) 2000 The Cryptix Foundation Limited.
 * All rights reserved.
 * 
 * Use, modification, copying and distribution of this software is subject 
 * the terms and conditions of the Cryptix General Licence. You should have 
 * received a copy of the Cryptix General Licence along with this library; 
 * if not, you can download a copy from http://www.cryptix.org/ .
 */
package cryptix.jce.util;


import java.math.BigInteger;


/**
 * Misc utility methods.
 *
 * @version $Revision: 1.5 $
 * @author  Jeroen C. van Gelderen (gelderen@cryptix.org)
 */
public final class Util
{
    private Util() {}
    

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


    /**
     * Convert the given byte[] to a String with it's hexadecimal
     * representation. This function doesn't like a null argument.
     */
    public static String toString(byte[] ba) {
        int length = ba.length;
        char[] buf = new char[length * 2];
        for (int i = 0, j = 0, k; i < length; )
        {
            k = ba[i++];
            buf[j++] = HEX_DIGITS[(k >>> 4) & 0x0F];
            buf[j++] = HEX_DIGITS[ k        & 0x0F];
        }
        return new String(buf);
    }


    private static final char[] HEX_DIGITS = {
        '0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F'
    };
}
