/* $Id: RC4KeyGenerator.java,v 1.6 2000/02/19 02:57:54 gelderen Exp $
 *
 * Copyright (C) 1995-1999 The Cryptix Foundation Limited.
 * All rights reserved.
 *
 * Use, modification, copying and distribution of this software is subject
 * the terms and conditions of the Cryptix General Licence. You should have
 * received a copy of the Cryptix General Licence along with this library;
 * if not, you can download a copy from http://www.cryptix.org/ .
 */
package cryptix.jce.provider.key;



/**
 * A key generator for RC4.
 * <p>
 * Key length between 40 and 1024 bits inclusive (increments of 8). Default
 * length is 128 bits.
 * <p>
 * References:
 * <ul>
 * <li>Andrew Roos &lt;andrewr@vironix.co.za&gt; (Vironix Software Laboratories),
 *     <cite>A Class of Weak Keys in the RC4 Stream Cipher</cite>,
 *     Preliminary draft posted to sci.crypt, 4th November 1997.
 * </ul>
 *
 * @version $Revision: 1.6 $
 * @author  David Hopwood
 * @author  Jeroen C. van Gelderen (gelderen@cryptix.org)
 */
public class RC4KeyGenerator extends RawKeyGenerator
{
    public RC4KeyGenerator()
    {
        super("RC4", 128);
    }


    /**
     * Returns true iff <i>key</i> is a weak RC4 key, as described in Andrew
     * Roos' paper.
     */
    protected boolean isWeak(byte[] key)
    {
        return key.length < 2 || (key[0] + key[1]) % 256 == 0;
    }


    /** 40 <= size <= 1024 */
    protected boolean isValidSize( int size )
    {
        if( size<40 )
            return false;
        else if( size>1024 )
            return false;
        else if( size%8 != 0 )
            return false;
        else
            return true;
    }
}
