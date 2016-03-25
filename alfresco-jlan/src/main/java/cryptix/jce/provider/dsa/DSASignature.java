/* $Id: DSASignature.java,v 1.4 2001/11/18 00:44:36 gelderen Exp $
 *
 * Copyright (C) 2001 The Cryptix Foundation Limited. All rights reserved.
 *
 * Use, modification, copying and distribution of this software is subject
 * the terms and conditions of the Cryptix General Licence. You should have
 * received a copy of the Cryptix General Licence along with this library;
 * if not, you can download a copy from http://www.cryptix.org/ .
 */
package cryptix.jce.provider.dsa;


import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.*;
import java.security.spec.AlgorithmParameterSpec;

import cryptix.jce.provider.util.Util;


/**
 * Implementation of the Digital Signature Algorithm (DSA) conformant with 
 * FIPS 186-2, Digital Signature Standard (DSS), February 2000. Tested and
 * interoperable with the DSA implementation in the Sun JDKs.
 *
 * @version $Revision: 1.4 $
 * @aurhor  Jeroen C. van Gelderen (gelderen@cryptix.org)
 */
public final class DSASignature
    extends SignatureSpi
    implements Cloneable
{
    /** RNG used when none is specified by our callers. */
    private static final SecureRandom _fallbackRng;


    static {
        _fallbackRng = new SecureRandom();
    }


// Instance variables
//...........................................................................

    private final MessageDigest _md;


    private BigInteger _g, _p, _q;


    /** Either public or private exponent, depending on our mode. */
    private BigInteger _exp;


// Ctors + java.lang.Object methods
//...........................................................................

    public DSASignature() {
        try {
            _md = MessageDigest.getInstance("SHA");
        } catch(NoSuchAlgorithmException nsae) {
            // Every JDK should provide a SHA implementation. On top of that 
            // we provide our own Cryptix one. Crashing thus is acceptable.
            throw new RuntimeException("PANIC: Algorithm SHA not found!");
        }
    }


    /**
     * Copy constructor.
     *
     * @throws CloneNotSupportedException
     *         if srcSig._md does not support cloning.
     */
    private DSASignature(DSASignature srcSig)
        throws CloneNotSupportedException
    {
        _md  = (MessageDigest)(srcSig._md.clone());
        _g   = srcSig._g;
        _p   = srcSig._p;
        _q   = srcSig._q;
        _exp = srcSig._exp;
    }


    public Object clone()
        throws CloneNotSupportedException
    {
        return new DSASignature(this); // may throw CloneNotSupportedException
    }
    
    
    public boolean equals(Object o) {
        return super.equals(o);
    }
    
    
    public int hashCode() {
        return super.hashCode();
    }


// Methods
//...........................................................................

    protected Object engineGetParameter(String param)
        throws InvalidParameterException
    {
        throw new InvalidParameterException("No params supported.");
    }


    /**
     * Init for signing with private key and a default RNG.
     */
    protected void engineInitSign(PrivateKey privateKey)
        throws InvalidKeyException
    {
        this.engineInitSign(privateKey, _fallbackRng);
    }


    /**
     * Init for signing with private key and RNG.
     */
    protected void engineInitSign(PrivateKey privKey, SecureRandom random)
        throws InvalidKeyException
    {
        if( !(privKey instanceof DSAPrivateKey) )
            throw new InvalidKeyException("Not a DSA private key");

        DSAPrivateKey dsaPrivKey = (DSAPrivateKey)privKey;
        _exp = dsaPrivKey.getX();

        DSAParams params = dsaPrivKey.getParams();
        _g = params.getG();
        _p = params.getP();
        _q = params.getQ();

        this.appRandom = random;

        _md.reset();

        if( !_isValid(MODE_SIGN) ) {
            _clear();
            throw new InvalidKeyException("Corrupt key?");
        }
    }


    /**
     * Calculate the signature over the accumulated data and reset (keeping
     * the key information, resetting the hash).
     */
    protected byte[] engineSign()
        throws SignatureException
    {
        // construct a positive BigInteger out of the accumulated data
        BigInteger data = new BigInteger(1, _md.digest());

        // find us a signature with r!=0 && s!=0
        BigInteger k, r, s;
        do {
            // find a random k < q
            int qBitLen = _q.bitLength();

            do {
                k = new BigInteger(qBitLen, this.appRandom);
            } while( k.compareTo(_q) != -1 ); // while( k < q )

            r = _g.modPow(k, _p).mod(_q);
            s = k.modInverse(_q).multiply(data.add(_exp.multiply(r))).mod(_q);

        } while( r.equals(Util.BI_ZERO) || s.equals(Util.BI_ZERO) );

        return new SignatureData(r, s).getData();
    }


    /**
     * Calculate the signature over the accumulated data and reset (keeping
     * the key information, resetting the hash).
     *
     * @throws SignatureException
     *         if the passed-in buffer is too small to hold the signature.
     */
    protected int engineSign(byte[] outbuf, int offset, int len)
        throws SignatureException
    {
        byte[] sigBytes = this.engineSign();
        if( sigBytes.length > len )
            throw new SignatureException("Buffer too small.");

        System.arraycopy(sigBytes, 0, outbuf, offset, sigBytes.length);
        return sigBytes.length;
    }


    protected void engineUpdate(byte b)
        throws SignatureException
    {
        _md.update(b);
    }


    protected void engineUpdate(byte[] b, int off, int len)
        throws SignatureException
    {
        _md.update(b, off, len);
    }


    /**
     * Init for verification with a public key.
     *
     * @throws InvalidKeyException
     *         if the key is not java.security.interfaces.DSAPublicKey or if
     *         the key data is corrupt/incorrect.
     */
    protected void engineInitVerify(PublicKey pubKey)
        throws InvalidKeyException
    {
        if( !(pubKey instanceof DSAPublicKey) )
            throw new InvalidKeyException("Not a DSA public key");

        DSAPublicKey dsaPubKey = (DSAPublicKey) pubKey;
        _exp = dsaPubKey.getY();

        DSAParams dsaParams = dsaPubKey.getParams();
        _g = dsaParams.getG();
        _p = dsaParams.getP();
        _q = dsaParams.getQ();

        this.appRandom = null;

        _md.reset();

        if( !_isValid(MODE_VERIFY) ) {
            _clear();
            throw new InvalidKeyException("Corrupt key?");
        }
    }


    /**
     * Calculate signature over the accumulated data and compare the result
     * to the passed in signature.
     *
     * @throws SignatureException
     *         if the passed-in signature appears corrupt.
     */
    protected boolean engineVerify(byte[] sigBytes)
        throws SignatureException
    {
        SignatureData sigData = new SignatureData(sigBytes);
        BigInteger r = sigData.getR();
        BigInteger s = sigData.getS();

        // verify signature constraints: 0<r<q && 0<s<q
        if( r.compareTo(Util.BI_ZERO)!=1 || r.compareTo(_q)!=-1
         || s.compareTo(Util.BI_ZERO)!=1 || s.compareTo(_q)!=-1 )
            throw new SignatureException("Invalid signature data");

        // construct a positive BigInt from the data
        BigInteger data = new BigInteger(1, _md.digest());

        if( data.bitLength() > 160 ) throw new InternalError("PANIC");

        // The actual DSA verify operation
        BigInteger w   = s.modInverse(_q);
        BigInteger u1  = data.multiply(w).mod(_q);
        BigInteger u2  = r.multiply(w).mod(_q);
        BigInteger gu1 = _g.modPow(u1, _p);
        BigInteger yu2 = _exp.modPow(u2, _p);
        BigInteger v   = gu1.multiply(yu2).mod(_p).mod(_q);

        if( w.compareTo(_q)!=-1 ) throw new InternalError("PANIC");
        if( v.compareTo(_q)!=-1 ) throw new InternalError("PANIC");
        if( u1.compareTo(_q)!=-1 ) throw new InternalError("PANIC");
        if( u2.compareTo(_q)!=-1 ) throw new InternalError("PANIC");
        if( gu1.compareTo(_p)!=-1 ) throw new InternalError("PANIC");
        if( yu2.compareTo(_p)!=-1 ) throw new InternalError("PANIC");

        return v.equals(r); // true if valid signature
    }


    protected void engineSetParameter(AlgorithmParameterSpec params)
        throws InvalidAlgorithmParameterException
    {
        throw new InvalidAlgorithmParameterException("No params supported.");
    }


    protected void engineSetParameter(String param, Object value)
        throws InvalidParameterException
    {
        throw new InvalidParameterException("No params supported.");
    }


// Helpers
//...........................................................................

    private static final boolean 
        MODE_SIGN = false, 
        MODE_VERIFY = true;


    /** Clear all sensitive state. */
    private void _clear() {
        this.appRandom = null;
        _g = _p = _q = _exp = null;
        _md.reset();
    }


    /** Invariants hold? */
    private boolean _isValid(boolean mode) {
        int pLen = _p.bitLength();
        if( pLen>1024 || pLen<512 || (pLen%64)!=0 )
            return false;
        if( _q.bitLength()!=160 )
            return false;
        if( _g.compareTo(_p)!=-1 )
            return false;
        if( _exp==null || _exp.compareTo(_p)!=-1 )
            return false;
        if( (this.appRandom == null) != mode )
            return false;
            
        return true;
    }
}

