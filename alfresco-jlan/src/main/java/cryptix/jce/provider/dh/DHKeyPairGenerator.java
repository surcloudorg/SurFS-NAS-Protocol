/* $Id: DHKeyPairGenerator.java,v 1.4 2003/02/15 13:44:26 gelderen Exp $
 *
 * Copyright (C) 2000 The Cryptix Foundation Limited.
 * All rights reserved.
 *
 * Use, modification, copying and distribution of this software is subject
 * the terms and conditions of the Cryptix General Licence. You should have
 * received a copy of the Cryptix General Licence along with this library;
 * if not, you can download a copy from http://www.cryptix.org/ .
 */
package cryptix.jce.provider.dh;


import cryptix.jce.provider.util.Group;
import cryptix.jce.provider.util.Precomputed;

import java.math.BigInteger;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGeneratorSpi;
import java.security.SecureRandom;

import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.spec.DHParameterSpec;


public final class DHKeyPairGenerator
extends KeyPairGeneratorSpi
{
    private static final BigInteger
        ZERO = BigInteger.valueOf(0),
        ONE  = BigInteger.valueOf(1);

    private static final int
        KEYSIZE_MIN     =   384,
        KEYSIZE_MAX     = 16384,
        KEYSIZE_DEFAULT = 16384;

    private static final int CERTAINTY = 80;


// Instance variables
//...........................................................................

    private SecureRandom random;


    private BigInteger p, g;


    /** Bit length of the generated value x. Must be valid. */
    private int xLen;


    /** Initialized already? */
    private boolean initialized = false;


// Concreteness
//...........................................................................

    public void initialize(int keysize, SecureRandom random)
    {
        //ASSERT(random != null);

        if( (keysize < KEYSIZE_MIN) || (keysize > KEYSIZE_MAX) )
            throw new IllegalArgumentException(
                "keysize: invalid size (" + keysize + ")" );

        // try and obtain precomputed parameters
        Group group = Precomputed.getStrongGroup( keysize );
        if( group == null )
            throw new RuntimeException(
                "keysize: sorry, no parameters available"); // FIXME

        // ASSERT( p!=null && g!=null );

        this.p      = group.getP();
        this.g      = group.getG();
        this.xLen   = p.bitLength() - 1;
        this.random = random;

        // ASSERT( xLen >= KEYSIZE_MIN-1 );

        this.initialized = true;
    }


    public void initialize(AlgorithmParameterSpec params, SecureRandom random)
    throws InvalidAlgorithmParameterException
    {
        // ASSERT(random != null);

        if( !(params instanceof DHParameterSpec) )
            throw new InvalidAlgorithmParameterException();

        DHParameterSpec dhps = (DHParameterSpec)params;
        BigInteger p = dhps.getP();
        BigInteger g = dhps.getG();
        int        l = dhps.getL();

        // FIXME: do sanity checks on P, G, L before messing with the state

        this.p      = p;
        this.g      = g;
        this.xLen   = (l==0) ? p.bitLength()-1 : l;
        this.random = random;

        this.initialized = true;
    }


    public KeyPair generateKeyPair()
    {
        if( !this.initialized )
            initialize(); // defaults are evil but Sun wants 'em...

        // ASSERT( xLen > 0 );

        BigInteger x, y;
        do
        {
            x = new BigInteger(this.xLen, this.random);
        }
        while( (x.compareTo(ZERO) != 1)
            || (x.compareTo(p.subtract(ONE)) != -1) );

        y = g.modPow(x, p);

        DHParameterSpec params = new DHParameterSpec( p, g );
        DHPrivateKeyCryptix priv = new DHPrivateKeyCryptix( x, params );
        DHPublicKeyCryptix  pub  = new DHPublicKeyCryptix ( y, params );

        return new KeyPair(pub, priv);
    }


// Private parts
//...........................................................................

    /** Initialize with default values */
    private void initialize()
    {
        this.initialize( KEYSIZE_DEFAULT, new SecureRandom() );
    }
}
