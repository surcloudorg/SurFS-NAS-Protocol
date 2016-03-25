/* $Id: TwofishKeyGenerator.java,v 1.2 2000/02/19 02:57:54 gelderen Exp $
 *
 * Copyright (C) 2000 The Cryptix Foundation Limited.
 * All rights reserved.
 *
 * Use, modification, copying and distribution of this software is subject
 * the terms and conditions of the Cryptix General Licence. You should have
 * received a copy of the Cryptix General Licence along with this library;
 * if not, you can download a copy from http://www.cryptix.org/ .
 */
package cryptix.jce.provider.key;


/**
 * Key generator for Twofish.
 *
 * @version $Revision: 1.2 $
 * @author  Jeroen C. van Gelderen <gelderen@cryptix.org>
 */
public final class TwofishKeyGenerator
extends RawKeyGenerator
{
    public TwofishKeyGenerator()
    {
        super("Twofish", 256); // conservative: use 256-bit keys by default
    }


    /**
     * Tests the given key for weaknesses
     */
    protected boolean isWeak( byte[] key )
    {
        return false; // Twofish doesn't have weak keys
    }


    /**
     * @param size  Keysize in bits (128, 192 and 256 accepted)
     */
    protected boolean isValidSize( int size )
    {
        return (size==128 || size==192 || size==256) ? true : false;
    }
}
