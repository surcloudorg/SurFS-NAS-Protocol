/* $Id: BlowfishKeyGenerator.java,v 1.7 2000/02/19 02:57:54 gelderen Exp $
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
 * A key generator for Blowfish.
 * See {@link cryptix.jce.provider.cipher.Blowfish Blowfish} for details.
 * <p>
 * Blowfish key length is between 40 and 448 bits inclusive, (8-bit increments).
 *
 * @version $Revision: 1.7 $
 * @author  Jeroen C. van Gelderen <gelderen@cryptix.org>
 */
public class BlowfishKeyGenerator extends RawKeyGenerator
{
    public BlowfishKeyGenerator()
    {
        // 128 bit keys by default
        super("Blowfish", 128);
    }


    protected boolean isWeak( byte[] key )
    {
        // Blowfish does not really have weak keys
        return false;
    }


    protected boolean isValidSize( int size )
    {
        // 40 bits to 448 bits in 8-bit increments
        return ((size&0x7)==0) && (size>=40) && (size<=448) ? true : false;

    }
}
