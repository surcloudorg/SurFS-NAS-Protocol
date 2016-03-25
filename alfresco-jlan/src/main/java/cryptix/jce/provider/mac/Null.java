/* $Id: Null.java,v 1.5 2000/02/09 20:32:33 gelderen Exp $
 *
 * Copyright (C) 1995-2000 The Cryptix Foundation Limited.
 * All rights reserved.
 *
 * Use, modification, copying and distribution of this software is subject
 * the terms and conditions of the Cryptix General Licence. You should have
 * received a copy of the Cryptix General Licence along with this library;
 * if not, you can download a copy from http://www.cryptix.org/ .
 */
package cryptix.jce.provider.mac;


import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.MacSpi;


/**
 * Null MAC, a MAC with length 0.
 *
 * @author Jeroen C. van Gelderen (gelderen@cryptix.org)
 * @version $Revision: 1.5 $
 */
public final class Null extends MacSpi
{
    public Null() {}


    /**
     * Return the length of this Mac: 0
     */
    protected final int engineGetMacLength()
    {
        // we are a normal MAC, just have length 0
        return 0;
    }


    protected final void engineInit(Key key, AlgorithmParameterSpec params)
    throws InvalidKeyException, InvalidAlgorithmParameterException
    {
    }


    protected final void engineUpdate(byte input)
    {
    }


    protected final void engineUpdate(byte[] input, int offset, int len)
    {
    }


    protected final byte[] engineDoFinal()
    {
        // we can't return null for this would require
        // special casing in client code
        return new byte[0];
    }


    protected final void engineReset()
    {
    }


    /**
     * Clone this MAC object.
     */
    public Object clone()
    throws CloneNotSupportedException
    {
        // we don't hold state so just give 'em a new one
        return new Null();
    }
}