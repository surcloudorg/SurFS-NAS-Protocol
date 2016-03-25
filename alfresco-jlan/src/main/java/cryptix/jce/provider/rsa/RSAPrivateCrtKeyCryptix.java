/* $Id: RSAPrivateCrtKeyCryptix.java,v 1.2 2000/08/25 01:23:06 gelderen Exp $
 *
 * Copyright (C) 2000 The Cryptix Foundation Limited.
 * All rights reserved.
 *
 * Use, modification, copying and distribution of this software is subject
 * the terms and conditions of the Cryptix General Licence. You should have
 * received a copy of the Cryptix General Licence along with this library;
 * if not, you can download a copy from http://www.cryptix.org/ .
 */
package cryptix.jce.provider.rsa;


import cryptix.jce.util.MPIOutputStream;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.interfaces.RSAPrivateCrtKey;


/**
 * Instances are immutable.
 *
 * @version $Revision: 1.2 $
 * @author  Jeroen C. van Gelderen (gelderen@cryptix.org)
 */
public final class RSAPrivateCrtKeyCryptix
implements RSAPrivateCrtKey
{

// Instance variables
// ..........................................................................

    private final BigInteger 
        modulus,          // n
        publicExponent,   // e
        privateExponent,  // d
        primeP,           // p
        primeQ,           // q
        primeExponentP,   // d mod (p-1)
        primeExponentQ,   // q mod (q-1)
        crtCoefficient;   // q^(-1) mod p


// Constructor
// ..........................................................................
    
    public RSAPrivateCrtKeyCryptix(BigInteger modulus, 
                                   BigInteger publicExponent,
                                   BigInteger privateExponent, 
                                   BigInteger primeP, 
                                   BigInteger primeQ,
                                   BigInteger primeExponentP, 
                                   BigInteger primeExponentQ,
                                   BigInteger crtCoefficient)
    {
        this.modulus         = modulus;
        this.publicExponent  = publicExponent;
        this.privateExponent = privateExponent;
        this.primeP          = primeP;
        this.primeQ          = primeQ;
        this.primeExponentP  = primeExponentP;
        this.primeExponentQ  = primeExponentQ;
        this.crtCoefficient  = crtCoefficient;
    }
    

// Interface RSAPrivateCrtKey
// ..........................................................................

    public BigInteger getPublicExponent()
    {
        return this.publicExponent;
    }
    
    
    public BigInteger getPrimeP()
    {
        return this.primeP;
    }
    
    
    public BigInteger getPrimeQ()
    {
        return this.primeQ;
    }
    
    
    public BigInteger getPrimeExponentP()
    {
        return this.primeExponentP;
    }
    
    
    public BigInteger getPrimeExponentQ()
    {
        return this.primeExponentQ;
    }
    
    
    public BigInteger getCrtCoefficient()
    {
        return this.crtCoefficient;
    }
    

// Interface RSAPrivateKey
// ..........................................................................
    
    public BigInteger getModulus()
    {
        return this.modulus;
    }
    
    
    public BigInteger getPrivateExponent()
    {
        return this.privateExponent;
    }
    

// Interface Key
// ..........................................................................
    
    public String getAlgorithm()
    {
        return "RSA";
    }
    
    
    public String getFormat()
    {
        return "Cryptix";
    }
    
    
    public byte[] getEncoded()
    {
        throw new RuntimeException("NYI");
    }
}
