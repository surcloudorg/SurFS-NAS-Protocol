/* $Id: RC2KeyGenerator.java,v 1.6 2000/02/19 02:57:54 gelderen Exp $
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
 * A key generator for RC2.
 * <p>
 * FIXME: We only support 128-bit keys for now.
 * <p>
 *
 * @version $Revision: 1.6 $
 * @author  Jeroen C. van Gelderen (gelderen@cryptix.org)
 */
public class RC2KeyGenerator extends RawKeyGenerator
{
    public RC2KeyGenerator()
    {
        super("RC2", 128);
    }


    /** RC2 doesn't have weak keys. */
    protected boolean isWeak( byte[] key )
    {
        return false;
    }


    /** FIXME: 128-bit keys only. */
    protected boolean isValidSize( int size )
    {
        return size==128 ? true : false;
    }
}
