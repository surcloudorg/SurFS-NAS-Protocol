/* $Id: DSAPublicKeyCryptix.java,v 1.3 2000/01/20 14:59:27 gelderen Exp $
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
import java.security.interfaces.DSAPublicKey;


/**
 * Public key for DSA. No parameter checking is done.
 * This keys can encode itself in OpenPGP-like Cryptix format.
 *
 * @author Jeroen C. van Gelderen (gelderen@cryptix.org)
 */
final class DSAPublicKeyOpenPGP
implements DSAPublicKey
{

// Instance varibles
//...........................................................................

    /** Public value y */
    private final BigInteger y;

    /** DSA parameters (g, q, p) */
    private final DSAParams params;


// Constructor
//...........................................................................

    /**
     * Construct a public key from the given values.
     * No parameter checking is done.
     */
    /*package*/ DSAPublicKeyOpenPGP(BigInteger y, DSAParams params)
    {
        this.y = y;
        this.params = params;
    }



// Methods from DSAPublicKey
//...........................................................................

    /**
     * Returns public value Y.
     */
    public BigInteger getY()
    {
        return y;
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


    /**
     * From RFC 2440bis:
     *
     * Algorithm Specific Fields for DSA public keys:
     *   - MPI of DSA prime p;
     *   - MPI of DSA group order q (q is a prime divisor of p-1);
     *   - MPI of DSA group generator g;
     *   - MPI of DSA public key value y (= g**x where x is secret).
     */
    public byte[] getEncoded()
    {
        try
        {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            MPIOutputStream       mos  = new MPIOutputStream(baos);
            mos.write(this.params.getP());
            mos.write(this.params.getQ());
            mos.write(this.params.getG());
            mos.write(this.y);
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