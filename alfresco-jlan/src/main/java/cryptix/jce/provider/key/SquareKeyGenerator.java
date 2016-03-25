/* $Id: SquareKeyGenerator.java,v 1.6 2000/02/19 02:57:54 gelderen Exp $
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
 * <p>
 * IDEA keys are between 40 and 448 bits in length (8-bit increments).
 * <p>
 *
 * @version $Revision: 1.6 $
 * @author  Jeroen C. van Gelderen <gelderen@cryptix.org>
 */
public class SquareKeyGenerator extends RawKeyGenerator
{
    public SquareKeyGenerator()
    {
        super("Square", 128);
    }


    protected boolean isWeak( byte[] key )
    {
        return false;
    }


    protected boolean isValidSize( int size )
    {
        return (size==128) ? true : false;
    }
}
