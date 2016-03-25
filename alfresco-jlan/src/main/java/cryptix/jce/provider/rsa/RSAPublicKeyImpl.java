/* $Id: RSAPublicKeyImpl.java,v 1.2 2000/08/31 00:24:05 gelderen Exp $
 *
 * Copyright (C) 2000 The Cryptix Foundation Limited. All rights reserved.
 *
 * Use, modification, copying and distribution of this software is subject
 * the terms and conditions of the Cryptix General Licence. You should have
 * received a copy of the Cryptix General Licence along with this library;
 * if not, you can download a copy from http://www.cryptix.org/ .
 */
package cryptix.jce.provider.rsa;


import java.io.IOException;
import java.math.BigInteger;
import java.security.interfaces.RSAPublicKey;

import cryptix.jce.provider.asn.*; // import whole library


/**
 * RSAPublicKey implementation that encodes itself in X.509 format.
 *
 * <pre>
 * X.509 encoding is DER-encoded ASN.1:
 *
 * SEQUENCE
 *   AlgorithId  id
 *   BIT_STRING  key
 *
 * where key is the DER-encoding of:
 *
 * SEQUENCE
 *   INTEGER  modulus
 *   INTEGER  exponent
 * </pre>
 *
 * @version $Revision: 1.2 $
 * @author  Jeroen C. van Gelderen (gelderen@cryptix.org)
 */

// XXX: should be package protected
public final class RSAPublicKeyImpl implements RSAPublicKey {

// Instance variables
//...........................................................................

    /**
     * Modulus and public exponent.
     */
    private final BigInteger n, e;


// Ctor
//...........................................................................

    public RSAPublicKeyImpl(BigInteger n, BigInteger e) {
        this.n = n;
        this.e = e;
    }


// RSAPublicKey methods
//...........................................................................

    public BigInteger getModulus() {
        return this.n;
    }


    public BigInteger getPublicExponent() {
        return this.e;
    }


// Implementation of Key interface
//...........................................................................

    public String getAlgorithm() {
        return "RSA";
    }


    /**
     * The string "X.509".
     */
    public String getFormat() {
        return "X.509";
    }


    /**
     * Returns a byte[] containing the X.509 encoded RSAPublicKey.
     */
    public byte[] getEncoded() {

        try {
            // construct the BIT_STRING
            AsnOutputStream aos = new AsnOutputStream();
            aos.write( new AsnSequence( 
                           new AsnInteger(this.n),
                           new AsnInteger(this.e) ) );
            byte[] bitStringBytes = aos.toByteArray();

            // construct and return outer SEQUENCE
            aos = new AsnOutputStream();
            aos.write( new AsnSequence( 
                           new AsnAlgorithmId(AsnObjectId.OID_rsaEncryption),
                           new AsnBitString(bitStringBytes) ) );

            return aos.toByteArray();

        } catch(IOException e) {
            e.printStackTrace();
            throw new InternalError(
                "PANIC: Unexpected exception during ASN encoding...");
        }
    }
}
