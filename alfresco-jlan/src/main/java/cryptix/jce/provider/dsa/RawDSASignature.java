/* $Id: RawDSASignature.java,v 1.7 2000/02/19 03:01:35 gelderen Exp $
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
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.SignatureSpi;
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.security.spec.AlgorithmParameterSpec;


/**
 * @author Jeroen C. van Gelderen (gelderen@cryptix.org)
 */
public final class RawDSASignature
extends SignatureSpi
{

// Constants and variables
//...........................................................................

    /** Puke, we need this because JDK 1.1.x doesn't have BigInteger.ZERO :-( */
    private BigInteger ZERO = BigInteger.valueOf(0L);

    private BigInteger x, y, g, p, q;

    private final byte[] buf;
    private int          bufPtr;

    private SecureRandom random; // FIXME: or use appRandom?


// Constructor
//...........................................................................

    public RawDSASignature()
    {
        super();
        buf = new byte[20];

        burn();
    }


// Signature abstract methods implementation
//...........................................................................

    protected void engineInitVerify(PublicKey key)
    throws InvalidKeyException
    {
        // clear out all data except random
        burn();

        if( !(key instanceof DSAPublicKey) )
            throw new InvalidKeyException("Not a DSA public key");

        DSAPublicKey dsa = (DSAPublicKey) key;
        y = dsa.getY();
        DSAParams params = dsa.getParams();
        g = params.getG();
        p = params.getP();
        q = params.getQ();

        if( !validate() )
        {
            burn();
            throw new InvalidKeyException("Invalid key values");
        }
    }


    protected void engineInitSign(PrivateKey key)
    throws InvalidKeyException
    {
        if( this.random==null )
            this.random = new SecureRandom();

        engineInitSign(key, this.random);
    }


    protected void engineInitSign(PrivateKey key, SecureRandom random)
    throws InvalidKeyException
    {
        burn();

        if( !(key instanceof DSAPrivateKey) )
            throw new InvalidKeyException("Not a DSA private key");

        DSAPrivateKey dsa = (DSAPrivateKey) key;
        x = dsa.getX();
        DSAParams params = dsa.getParams();
        g = params.getG();
        p = params.getP();
        q = params.getQ();

        this.random = random;

        if( !validate() )
        {
            burn();
            throw new InvalidKeyException("Invalid key values");
        }
    }


    protected void engineUpdate( byte b )
    throws SignatureException
    {
        if( bufPtr >= 20 )
            throw new SignatureException("Signature data length exceeded");

        buf[bufPtr++] = b;
    }


    protected void engineUpdate(byte[] in, int offset, int length)
    throws SignatureException
    {
        if( bufPtr+length > 20 )
            throw new SignatureException("Signature data length exceeded");

        System.arraycopy(in, offset, buf, bufPtr, length);
        bufPtr += length;
    }


    /**
     * Returns a signature over the accumulated data.
     *
     * @return signature over the accumulated data.
     * @throws SignatureException
     *         if length of accumulated data < 20 (160 bits).
     */
    protected byte[] engineSign()
    throws SignatureException
    {
        if( bufPtr != 20 )
            throw new SignatureException("Insufficient data for signature");

        // construct a positive BigInteger out of the accumulated data
        BigInteger data = new BigInteger(1, buf);

        // find us a signature with r!=0 && s!=0
        BigInteger k, r, s;
        do
        {
            // find a random k < q
            int qBitLen = q.bitLength();
            do
            {
                k = new BigInteger(qBitLen, random);
            }
            while( k.compareTo(q) != -1 ); // while( k < q )

            r = g.modPow(k, p).mod(q);
            s = k.modInverse(q).multiply(data.add(x.multiply(r))).mod(q);
        }
        while( r.equals(ZERO) || s.equals(ZERO) );

        return new SignatureData(r, s).getData();
    }


    protected boolean engineVerify(byte[] signature)
    throws SignatureException
    {
        // buffer must contain exactly 20 bytes
        if( bufPtr != 20 )
            throw new SignatureException("Insufficient data for signature");

        // extract r and s from signature blob
        SignatureData sigData = new SignatureData(signature);
        BigInteger r = sigData.getR();
        BigInteger s = sigData.getS();

        // verify constraints: 0<r<q && 0<s<q
        if( r.compareTo(ZERO)!=1
         || s.compareTo(ZERO)!=1
         || r.compareTo(q)!=-1
         || s.compareTo(q)!=-1 )
            throw new SignatureException("Invalid signature data");

        // construct a positive BigInt from the data
        BigInteger data = new BigInteger(1, buf);

if( data.bitLength() > 160 ) throw new InternalError("PANIC");

        // The actual DSA verify operation
        BigInteger w   = s.modInverse(q);
        BigInteger u1  = data.multiply(w).mod(q);
        BigInteger u2  = r.multiply(w).mod(q);
        BigInteger gu1 = g.modPow(u1, p);
        BigInteger yu2 = y.modPow(u2, p);
        BigInteger v   = gu1.multiply(yu2).mod(p).mod(q);

if( w.compareTo(q)!=-1 ) throw new InternalError("PANIC");
if( v.compareTo(q)!=-1 ) throw new InternalError("PANIC");
if( u1.compareTo(q)!=-1 ) throw new InternalError("PANIC");
if( u2.compareTo(q)!=-1 ) throw new InternalError("PANIC");
if( gu1.compareTo(p)!=-1 ) throw new InternalError("PANIC");
if( yu2.compareTo(p)!=-1 ) throw new InternalError("PANIC");

        // true if valid signature
        return v.equals(r);
    }


    /** deprecated */
    protected void engineSetParameter(String param, Object value)
    throws InvalidParameterException
    {
        throw new InvalidParameterException(
            "This algorithm does not accept parameters.");
    }


    protected void engineSetParameter(AlgorithmParameterSpec params)
    throws InvalidAlgorithmParameterException
    {
        throw new InvalidAlgorithmParameterException(
            "This algorithm does not accept AlgorithmParameterSpec.");
    }


    /** deprecated */
    protected Object engineGetParameter(String param)
    throws InvalidParameterException
    {
        throw new InvalidParameterException(
            "This algorithm does not have parameters.");
    }



// Private helper methods
//...........................................................................

    /**
     * Try and zero all potentially sensitive data. This is not secure because
     * we cannot control memory allocation, garbage collection and swapping.
     * It's the best we can do though, apart from changing the JVM.
     */
    private void burn()
    {
        x = y = g = p = q = null;
        bufPtr = 0;
        for( int i=0; i<buf.length; i++ )
            buf[i] = 0;
    }


    /**
     * Check our invariants.
     *
     * @return true if ok, false otherwise
     */
    private boolean validate()
    {
        int pLen = p.bitLength();
        if( pLen>1024 || pLen<512 || (pLen%64)!=0 )
            return false;
        if( q.bitLength()!=160 || g.compareTo(p)!=-1 )
            return false;
        if( y!=null && y.compareTo(p)!=-1 )
            return false;
        if( x!=null && x.compareTo(p)!=-1 )
            return false;

if( x!=null && y!=null ) throw new InternalError("PANIC");
if( x==null && y==null ) throw new InternalError("PANIC");

        return true;
    }
}