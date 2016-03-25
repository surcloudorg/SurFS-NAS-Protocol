/* $Id: DSAPrivateKeyImpl.java,v 1.5 2000/02/19 03:01:35 gelderen Exp $
 *
 * Copyright (C) 1995-1999 The Cryptix Foundation Limited.
 * All rights reserved.
 *
 * Use, modification, copying and distribution of this software is subject
 * the terms and conditions of the Cryptix General Licence. You should have
 * received a copy of the Cryptix General Licence along with this library;
 * if not, you can download a copy from http://www.cryptix.org/ .
 */
package cryptix.jce.provider.dsa;


import java.math.BigInteger;
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPrivateKey;


/**
 * Private key for DSA. No parameter checking is done.
 *
 * @author Jeroen C. van Gelderen (gelderen@cryptix.org)
 */
final class DSAPrivateKeyImpl
implements DSAPrivateKey
{

// Class variables
//...........................................................................

    public static final long serialVersionUID = 0L; //XXX


// Instance varibles
//...........................................................................

    /** Private value y */
    private final BigInteger x;

    /** DSA parameters (g, q, p) */
    private final DSAParams params;


// Constructor
//...........................................................................

    /**
     * Construct a public key from the given values.
     * No parameter checking is done.
     */
    /*package*/ DSAPrivateKeyImpl(BigInteger x, DSAParams params)
    {
        this.x = x;
        this.params = params;
    }



// Methods from DSAPrivateKey
//...........................................................................

    /**
     * Returns private value X.
     */
    public BigInteger getX()
    {
        return x;
    }


// Methods from DSAKey
//...........................................................................

    /**
     * Return DSA parameters (g,q, p).
     */
    public DSAParams getParams()
    {
        return params;
    }


// Methods from Key
//...........................................................................

    public String getAlgorithm()
    {
        throw new RuntimeException(); //XXX
    }


    public String getFormat()
    {
        throw new RuntimeException(); //XXX
    }


    public byte[] getEncoded()
    {
        throw new RuntimeException(); //XXX
    }
}