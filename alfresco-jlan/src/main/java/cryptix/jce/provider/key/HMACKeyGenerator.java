/* $Id: HMACKeyGenerator.java,v 1.4 2000/02/19 02:57:54 gelderen Exp $
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
 * A key generator for HMACs.
 *
 * @version $Revision: 1.4 $
 * @author  Jeroen C. van Gelderen <gelderen@cryptix.org>
 */
public class HMACKeyGenerator extends RawKeyGenerator
{
    public HMACKeyGenerator()
    {
        // 128 bit keys by default
        super("HMAC", 128);
    }


    protected boolean isWeak( byte[] key )
    {
        // HMACs don't have weak keys
        return false;
    }


    protected boolean isValidSize( int size )
    {
        // any length is valid. we might want to limit them to be >= L
        return true;
    }
}
