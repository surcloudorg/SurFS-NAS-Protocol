/* $Id: DHKeyAgreement.java,v 1.1 2000/02/09 20:35:10 gelderen Exp $
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


import java.math.BigInteger;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.KeyAgreementSpi;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;

import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;


/**
 * Diffie-Hellman key agreement, PKCS#3 style.
 *
 * @author Jeroen C. van Gelderen (gelderen@cryptix.org)
 */
public final class DHKeyAgreement extends KeyAgreementSpi
{

// Constants and instance variables
// ..........................................................................

    /** Private key components. */
    private BigInteger
        privG,
        privP,
        privX;


    /**
     * Our master secret.
     * Under construction during STATE_NEED_PUB_KEY, final if STATE_COMPLETE.
     */
    private BigInteger masterSecret;


    private int masterSecretLen;


    /** Constants for state machine. */
    private static final int
        STATE_UNINITIALIZED = 0, // we need keys
        STATE_NEED_PUB_KEY  = 1, // we need a
        STATE_COMPLETE      = 2; // we can generate a secret

    /** Current state. */
    private int state = STATE_UNINITIALIZED;


    /** BigInteger constants. */
    private static final BigInteger
        ZERO = BigInteger.valueOf(0);


// Constructor
// ..........................................................................

    /**
     * Constructor for use by javax.crypto.KeyAgreement only.
     */
    public DHKeyAgreement()
    {
        super();
    }


// KeyAgreementSpi abstract methods
// ..........................................................................

    /**
     * Initialize the KeyAgreement with private value x (wrapped in a
     * DHPrivateKey.
     *
     * @param  key
     *         A DHPrivateKey containing the secret value X and the group
     *         parameters P and G.
     *
     * @throws InvalidKeyException
     *         If key is not a DHPrivateKey or the key's parameters are
     *         invalid according to PKCS#3. If this exception is thrown
     *         the objects state is unaltered.
     */
    protected void engineInit(Key key, SecureRandom unused)
    throws InvalidKeyException
    {
        if( !(key instanceof DHPrivateKey) )
            throw new InvalidKeyException("key: not a DHPrivateKey");

        DHPrivateKey priv  = (DHPrivateKey)key; // cast always succeeds
        BigInteger   privX = priv.getX();
        BigInteger   privG = priv.getParams().getG();
        BigInteger   privP = priv.getParams().getP();

        // check that P is odd
        if( !privP.testBit(0) )
            throw new InvalidKeyException("key: P is not odd");

        // check 0 < G < P
        if( (privG.compareTo(ZERO) != 1) || (privG.compareTo(privP) != -1) )
            throw new InvalidKeyException("key: G is invalid");

        // FIXME: do the rest of the PKCS3 checks

        // now update state
        this.privX = privX;
        this.privG = privG;
        this.privP = privP;

        this.masterSecretLen = (privP.bitLength() + 7) / 8;


        System.out.println("privP.bitLen: " + this.privP.bitLength());
        System.out.println("masterSecretLen: " + this.masterSecretLen);

        this.state = STATE_NEED_PUB_KEY;
    }


    /**
     * Not yet implemented.
     */
    protected void engineInit(Key key, AlgorithmParameterSpec params,
                              SecureRandom random)
    throws InvalidKeyException, InvalidAlgorithmParameterException
    {
        throw new RuntimeException("NYI");
    }


    /**
     * This
     */
    protected Key engineDoPhase(Key key, boolean lastPhase)
    throws InvalidKeyException, IllegalStateException
    {
        if( this.state != STATE_NEED_PUB_KEY )
            throw new IllegalStateException();

        // only two-party agreement for now
        if( !lastPhase )
            throw new IllegalArgumentException("lastPhase: not 'true'");

        if( !(key instanceof DHPublicKey) )
            throw new IllegalArgumentException("key: not a DHPublicKey");

        DHPublicKey pub  = (DHPublicKey)key; // cast succeeds
        BigInteger  pubY = pub.getY();
        BigInteger  pubG = pub.getParams().getG();
        BigInteger  pubP = pub.getParams().getP();

        if( !pubG.equals(this.privG) || !pubP.equals(this.privP) )
            throw new InvalidKeyException(
                "key: incompatible group");

        // set secret
        this.masterSecret = pubY.modPow(this.privX, this.privP);

        if( lastPhase )
            this.state = STATE_COMPLETE;

        return null;
    }


    protected byte[] engineGenerateSecret()
    throws IllegalStateException
    {
        if( this.state != STATE_COMPLETE )
            throw new IllegalStateException();

        byte[] returnBuf  = new byte[this.masterSecretLen];
        byte[] integerBuf = this.masterSecret.toByteArray();
        
        // byte length without sign bit!
        int toCopy = (this.masterSecret.bitLength() + 7) /8;


        System.out.println("this.masterSecret.bitLength(): " + 
                                        this.masterSecret.bitLength() );
        System.out.println("toCopy            : " + toCopy );
        System.out.println("returnBuf.length  : " + returnBuf.length);
        System.out.println("integerBuf.length : " + integerBuf.length);
        System.arraycopy(integerBuf,
                         0,
                         returnBuf,
                         (returnBuf.length - toCopy),
                         toCopy);

        return returnBuf;
    }


    protected int engineGenerateSecret(byte[] sharedSecret, int offset)
    throws IllegalStateException, ShortBufferException
    {
        byte[] masterBytes = engineGenerateSecret(); // ensures correct state

        int masterBytesLen = masterBytes.length;
        if( masterBytesLen > (sharedSecret.length + offset) )
            throw new ShortBufferException();

        System.arraycopy(masterBytes, 0, sharedSecret, offset, masterBytesLen);
        return masterBytesLen;
    }


    protected SecretKey engineGenerateSecret(String algorithm)
    throws IllegalStateException, NoSuchAlgorithmException, InvalidKeyException
    {
        throw new RuntimeException("NYI");
    }
}