/* $Id: DSAPrivateKeyCryptix.java,v 1.3 2000/02/19 03:01:35 gelderen Exp $
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


import cryptix.jce.util.MPIOutputStream;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPrivateKey;


/**
 * Private key for DSA. No parameter checking is done.
 * Encodes itself in an OpenPGP-like Cryptix format.
 *
 * @author Jeroen C. van Gelderen (gelderen@cryptix.org)
 */
final class DSAPrivateKeyCryptix
implements DSAPrivateKey
{

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
    /*package*/ DSAPrivateKeyCryptix(BigInteger x, DSAParams params)
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
        return "DSA";
    }


    public String getFormat()
    {
        return "Cryptix";
    }


    public byte[] getEncoded()
    {
        try
        {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            MPIOutputStream       mos  = new MPIOutputStream(baos);
            mos.write(this.params.getP());
            mos.write(this.params.getQ());
            mos.write(this.params.getG());
            mos.write(this.x);
            mos.flush();
            mos.close();
            return baos.toByteArray();
        }
        catch(IOException e)
        {
            throw new RuntimeException("PANIC");
        }
    }
}