/* $Id: RSAKeyFactory.java,v 1.2 2000/08/25 01:21:10 gelderen Exp $
 *
 * Copyright (C) 1995-1999 The Cryptix Foundation Limited.
 * All rights reserved.
 *
 * Use, modification, copying and distribution of this software is subject
 * the terms and conditions of the Cryptix General Licence. You should have
 * received a copy of the Cryptix General Licence along with this library;
 * if not, you can download a copy from http://www.cryptix.org/ .
 */
package cryptix.jce.provider.rsa;


import java.io.IOException; // for ASN library
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactorySpi;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;

import cryptix.jce.provider.asn.*; // whole library


/**
 * @version $Revision: 1.2 $
 * @author Jeroen C. van Gelderen (gelderen@cryptix.org)
 */
public final class RSAKeyFactory extends KeyFactorySpi {

//...........................................................................

    public RSAKeyFactory() {
        super();
    }


// Spi implementation
//...........................................................................

    protected PrivateKey engineGeneratePrivate(KeySpec keySpec)
    throws InvalidKeySpecException
    {
        if (keySpec instanceof RSAPrivateKeySpec) {
            RSAPrivateKeySpec s = (RSAPrivateKeySpec)keySpec;
            return new RSAPrivateKeyCryptix(
                s.getModulus(), 
                s.getPrivateExponent() );

        } else if (keySpec instanceof RSAPrivateCrtKeySpec) {
            RSAPrivateCrtKeySpec s = (RSAPrivateCrtKeySpec)keySpec;
            return new RSAPrivateCrtKeyCryptix(
                s.getModulus(),
                s.getPublicExponent(),
                s.getPrivateExponent(),
                s.getPrimeP(),
                s.getPrimeQ(),
                s.getPrimeExponentP(),
                s.getPrimeExponentQ(),
                s.getCrtCoefficient() );

        } else if (keySpec instanceof X509EncodedKeySpec) {
            return decodePrivateKey((X509EncodedKeySpec)keySpec);

        } else {
            throw new InvalidKeySpecException(
                this.getClass().getName() + ".engineGeneratePrivate: " +
                "KeySpec of type " + keySpec.getClass() + " not supported.");
        }
    }


    protected PublicKey engineGeneratePublic(KeySpec keySpec)
    throws InvalidKeySpecException
    {
        if( keySpec instanceof RSAPublicKeySpec ) {
            RSAPublicKeySpec s = (RSAPublicKeySpec)keySpec;
            return new RSAPublicKeyCryptix(
                s.getModulus(),
                s.getPublicExponent() );

        } else if (keySpec instanceof X509EncodedKeySpec) {
            // XXX: remove this when stable
            PublicKey tmp = decodePublicKey((X509EncodedKeySpec)keySpec);
            X509EncodedKeySpec ks = new X509EncodedKeySpec(tmp.getEncoded());
            return decodePublicKey(ks);

        } else {
            throw new InvalidKeySpecException(
                this.getClass().getName() + ".engineGeneratePublic: " +
                "KeySpec type " + keySpec.getClass() + " not supported.");
        }
    }


    protected KeySpec engineGetKeySpec(Key key, Class keySpec)
    throws InvalidKeySpecException
    {
        throw new RuntimeException("NYI");
    }


    protected Key engineTranslateKey(Key key) throws InvalidKeyException {
        throw new RuntimeException("NYI");
    }


//
//...........................................................................

    private PrivateKey decodePrivateKey(X509EncodedKeySpec keySpec)
    throws InvalidKeySpecException
    {
        throw new RuntimeException("NYI");
    }



    /**
     * <pre>
     * byte[] containing the DER of:
     * SEQUENCE
     *   AlgorithmId
     *   BIT STRING
     *
     * where BIT STRING is the DER encoding of:
     *   SEQUENCE
     *     INTEGER modulus
     *     INTEGER publicExponent
     * </pre>
     */
    private PublicKey decodePublicKey(X509EncodedKeySpec keySpec)
    throws InvalidKeySpecException
    {
        try {
            AsnInputStream ais = new AsnInputStream( keySpec.getEncoded() );
            AsnSequence seq = (AsnSequence)ais.read();
            if (seq.size() != 2)
                throw new InvalidKeySpecException(
                    "First SEQUENCE has " + seq.size() + " elements.");

            // XXX: check for valid AlgOID

            AsnObject uh = seq.get(0);
            System.out.println(uh);

            AsnBitString bs = (AsnBitString)seq.get(1);
            ais = new AsnInputStream( bs.toByteArray() );

            seq = (AsnSequence)ais.read();
            if (seq.size() != 2)
                throw new InvalidKeySpecException(
                    "Second SEQUENCE has " + seq.size() + " elements.");

            AsnInteger n = (AsnInteger)seq.get(0);
            AsnInteger e = (AsnInteger)seq.get(1);

            return new RSAPublicKeyImpl(n.toBigInteger(), e.toBigInteger());

        } catch(ClassCastException e) {
            throw new InvalidKeySpecException(
                "Unexpected ASN.1 type detected: " + e.getMessage() );
            
        } catch(IOException e) {
            throw new InvalidKeySpecException("Could not parse key.");
        }
    }
}
