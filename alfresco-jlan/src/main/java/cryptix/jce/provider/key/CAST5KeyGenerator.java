/* $Id: CAST5KeyGenerator.java,v 1.7 2000/02/19 02:57:54 gelderen Exp $
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
 * A key generator for CAST5.
 * <p>
 * The CAST5 encryption algorithm has been designed to allow a key size
 * that can vary from 40 bits to 128 bits, in 8-bit increments (that is,
 * the allowable key sizes are 40, 48, 56, 64, ..., 112, 120, and 128
 * bits.
 *
 * @version $Revision: 1.7 $
 * @author  Jeroen C. van Gelderen <gelderen@cryptix.org>
 */
public class CAST5KeyGenerator extends RawKeyGenerator
{
    public CAST5KeyGenerator()
    {
        super("CAST5", 128);
    }


    protected boolean isWeak( byte[] key )
    {
        return false;
    }


    protected boolean isValidSize( int size )
    {
        // 40 bits to 128 bits in 8-bit increments
        return ((size&0x7)==0) && (size>=40) && (size<=128) ? true : false;
    }
}
