/* $Id: ElGamalKeyPairGenerator.java,v 1.3 2001/02/26 16:26:48 gelderen Exp $
 *
 * Copyright (C) 2000 The Cryptix Foundation Limited.
 * All rights reserved.
 *
 * Use, modification, copying and distribution of this software is subject
 * the terms and conditions of the Cryptix General Licence. You should have
 * received a copy of the Cryptix General Licence along with this library;
 * if not, you can download a copy from http://www.cryptix.org/ .
 */
package cryptix.jce.provider.elgamal;


import cryptix.jce.ElGamalParams;

import java.math.BigInteger;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGeneratorSpi;
import java.security.SecureRandom;

import java.security.spec.AlgorithmParameterSpec;


/**
 * @version $Revision: 1.3 $
 * @author  Jeroen C. van Gelderen (gelderen@cryptix.org)
 */
public final class ElGamalKeyPairGenerator 
extends KeyPairGeneratorSpi
{

// Constants    
//...........................................................................

    private static final int 
        KEYSIZE_MIN     =   384,
        KEYSIZE_MAX     = 16384,
        KEYSIZE_DEFAULT = 1536;
        
    private static final BigInteger
        TWO = BigInteger.valueOf(2);


// Instance variables
//...........................................................................

    private SecureRandom random;
    
    
    private int keysize;
    
    
    /** Initialized already? */
    private boolean initialized = false;


// Constructor
//...........................................................................

    public ElGamalKeyPairGenerator()
    {
        super();
    }
    

// KeyPairGeneratorSpi methods
//...........................................................................
    
    public void initialize(int keysize, SecureRandom random)
    {
        //ASSERT(random != null);
        
        if( (keysize < KEYSIZE_MIN) || (keysize > KEYSIZE_MAX) )
            throw new IllegalArgumentException(
                "keysize: invalid size (" + keysize + ")" );
        
        this.keysize = keysize;
        this.random  = random;
        
        this.initialized = true;
    }
    
    
    public void initialize(AlgorithmParameterSpec params, SecureRandom random)
    throws InvalidAlgorithmParameterException
    {
        throw new RuntimeException("NYI");
        // don't forget:
        //this.initialized = true;
    }
    
    
    public KeyPair generateKeyPair()
    {
        if( !this.initialized )
            initialize();
        
        // try and obtain precomputed parameters
        ElGamalParams params = PrecomputedParams.get(this.keysize);
        if(params == null)
        {
            // generate 'em
            // FIXME: throw for now
            throw new RuntimeException("NYI");
        }
        
        BigInteger p    = params.getP();
        BigInteger g    = params.getG();
        BigInteger xMin = TWO;
        BigInteger xMax = p.subtract(TWO);
        int        xLen = p.bitLength();

        BigInteger x, y;
        do
        {
            x = new BigInteger(xLen, this.random);
        }
        while( (x.compareTo(xMin) == -1) || (x.compareTo(xMax) == 1) );
        
        y = g.modPow(x, p);
        
        ElGamalPublicKeyCryptix pub   = new ElGamalPublicKeyCryptix(y, params);
        ElGamalPrivateKeyCryptix priv = new ElGamalPrivateKeyCryptix(x, params);
        return new KeyPair(pub, priv);
    }
    
    
    private void initialize()
    {
        initialize( KEYSIZE_DEFAULT, new SecureRandom() );
    }
}
