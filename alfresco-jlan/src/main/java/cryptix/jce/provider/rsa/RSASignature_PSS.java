/* $Id: RSASignature_PSS.java,v 1.3 2001/11/18 02:30:02 gelderen Exp $
 *
 * Copyright (C) 2001 The Cryptix Foundation Limited.
 * All rights reserved.
 *
 * Use, modification, copying and distribution of this software is subject
 * the terms and conditions of the Cryptix General Licence. You should have
 * received a copy of the Cryptix General Licence along with this library;
 * if not, you can download a copy from http://www.cryptix.org/ .
 */
package cryptix.jce.provider.rsa;


import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.RSAPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.AlgorithmParameterSpec;
import cryptix.jce.provider.util.Util;


/**
 * Implementation of the RSASSA-PSS signature scheme as described in
 * RSA Labs' PKCS#1v2.
 *
 * @author Jeroen C. van Gelderen (gelderen@cryptix.org)
 * @version $Revision: 1.3 $
 */
public abstract class RSASignature_PSS extends SignatureSpi {

    /** Bitmasks of least significant bits indexed by bitcount. */
    private static final byte[] MASK = {
        (byte)0xFF, 0x7F, 0x3F, 0x1F, 0x0F, 0x07, 0x03, 0x01
    };

// Instance variables
//...........................................................................

    /** Hash instance for this signature instance. */
    private final MessageDigest md;

    /** Length of hash (in bytes). */
    private final int hLen;

    /** Length of salt (in bytes). */
    private final int sLen;

    /**
     * XXX  If !null, this will be used as salt in lieu of randomness.
     *      This allows the signature to behave deterministically
     *      for testing purposes.
     */
    private byte[] presetSalt;

// Key dependent variables
//...........................................................................

    /** Byte length of encoded message: emLen = ceil(emBits/8). */
    private int emLen;

    /** Exact bit-length of encoded message (modulus len - 1). */
    private int emBits;

    /** Various components of our RSA[Private|Public]Key. */
    private BigInteger exp, n, p, q, u;

    /** RNG */
    private SecureRandom rng;

//...........................................................................

    public RSASignature_PSS(String hashName) {
        try {
            this.md = MessageDigest.getInstance(hashName);
            this.hLen = this.sLen = this.md.getDigestLength();
        } catch(NoSuchAlgorithmException ex) {
            // we should have the given hash in our provider so this should
            // be unreachable
            throw new InternalError(
                "MessageDigest not found! (" + hashName + "): " +
                ex.toString());
        }
    }

    protected Object engineGetParameter(String a) {
        throw new RuntimeException("NYI");
    }


    protected void engineInitSign(PrivateKey key, SecureRandom random)
    throws InvalidKeyException {
        if( !(key instanceof RSAPrivateKey) )
            throw new InvalidKeyException("Not an RSA private key");

        RSAPrivateKey rsa = (RSAPrivateKey)key;
        this.n   = rsa.getModulus();
        this.exp = rsa.getPrivateExponent();

        if(key instanceof RSAPrivateCrtKey) {
            RSAPrivateCrtKey crt = (RSAPrivateCrtKey)key;
            this.p = crt.getPrimeP();
            this.q = crt.getPrimeQ();
            this.u = crt.getCrtCoefficient();
        } else {
            this.p = this.q = this.u = null;
        }

        this.rng = random;
        initCommon();
    }


    protected void engineInitSign(PrivateKey privateKey)
    throws InvalidKeyException {
        this.engineInitSign(privateKey, new SecureRandom());
    }


    protected void engineInitVerify(PublicKey key) throws InvalidKeyException {
       if( !(key instanceof RSAPublicKey) )
            throw new InvalidKeyException("Not an RSA public key");

        RSAPublicKey rsa = (RSAPublicKey) key;
        this.n   = rsa.getModulus();
        this.exp = rsa.getPublicExponent();
        this.p = this.q = this.u = null;

        this.rng = null;
        initCommon();
    }


    private void initCommon() throws InvalidKeyException {
        this.emBits = getModulusBitLen() - 1;
        this.emLen = (this.emBits + 7) / 8;

        if( this.emBits < 8*this.hLen + 8*this.sLen + 9 )
            throw new InvalidKeyException("Signer's key modulus too short.");

        md.reset();
    }


    protected void engineSetParameter(String name, Object param) {
        if( name.equalsIgnoreCase("CryptixDebugFixedSalt") ) {
            if( param instanceof byte[] )
                this.presetSalt = (byte[])param;
        }
    }


    protected byte[] engineSign() {

        byte[] padding1 = new byte[8]; // 8 zeroes
        byte[] mHash = this.md.digest();
        byte[] salt;

        /*
         * Magic to allow for preset salt so we can force this signature to
         * behave deterministically. This is neccessary in order to be able
         * to test against test vectors. We make sure the preset salt is only
         * used once (you have to set it after each call to initSign()).
         */
        if( this.presetSalt == null ) {
            // 4. Generate a random octet string salt of length sLen;
            salt = new byte[this.sLen];
            this.rng.nextBytes(salt);
        } else if( this.sLen != this.presetSalt.length ) {
            // user should know what he is doing fo we just fail hard
            throw new Error("Invalid presetSalt, size mismatch!");
        } else {
            salt = this.presetSalt;
            this.presetSalt = null; // enforce one-shot behaviour
            System.err.println("Using preset salt: " +
                               cryptix.jce.util.Util.toString(salt) + "!");
        }

        // 5, 6. Let M = 00 00 00 00 00 00 00 00 || mHash || salt;
        //       M is an octet string of length 8 + hLen + sLen with eight
        //       initial zero octets. Let H = Hash(M).
        this.md.update(padding1);
        this.md.update(mHash);
        byte[] H = this.md.digest(salt);

        // 9. Let dbMask = MGF(H, emLen  hLen  1).
        byte[] dbMask = mgf1(H, this.emLen - this.hLen - 1);

        // 7,8. Generate an octet string PS consisting of emLen-sLen-hLen-2
        //      zero octets. The length of PS may be 0. Let DB = PS||01||salt.
        byte[] PS = new byte[this.emLen - this.sLen - this.hLen - 2];
        byte[] one = new byte[] { 0x01 };
        byte[] DB = concat(PS, one, salt);

        // 10. Let maskedDB = DB dbMask.
        byte[] maskedDB = xor(DB, dbMask);

        // 11. Set the leftmost 8emLen - emBits bits of the leftmost octet in
        //     maskedDB to zero.
        int maskBits = 8*this.emLen - this.emBits;
        maskedDB[0] &= MASK[maskBits];

        // 12. Let EM = maskedDB || H || bc, where bc is the single octet
        //     with hexadecimal value bc.
        byte[] EM = concat( maskedDB, H, new byte[]{ (byte)0xbc } );

        // 2. Convert the encoded message EM to an integer message
        //    representative m:
        BigInteger m = new BigInteger(1, EM);
        if( m.compareTo(this.n) != -1 )
            throw new InternalError("message > modulus!");

        // 3. Apply the RSASP1 signature primitive to the private key K and
        //    the message representative m to produce an integer signature
        //    representative s:
        BigInteger s = RSAAlgorithm.rsa(m, n, exp, p, q, u);

        // 4. Convert the signature representative s to a signature S of
        //    length k octets:
        return Util.toFixedLenByteArray(s, this.getModulusLen());
    }


    private int getModulusLen() {
        return (this.n.bitLength() + 7) / 8;
    }


    private int getModulusBitLen() {
        return this.n.bitLength();
    }


    private static byte[] xor(byte[] a, byte[] b) {
        if( a.length != b.length )
            throw new InternalError("a.len != b.len");

        byte[] res = new byte[a.length];
        for(int i=0; i<res.length; i++)
            res[i] = (byte)(a[i] ^ b[i]);
        return res;
    }


    // T = T || Hash (Z || C)
    private byte[] mgf1(byte[] seed, int len) {
        int hashCount = (len + hLen - 1) / hLen; // ceil(len / hLen)
        byte[] mask = new byte[0];
        for(int i=0; i<hashCount; i++)
            mask = concat(mask, mgf1Hash(seed, (byte)i));
        byte[] res = new byte[len];
        System.arraycopy(mask, 0, res, 0, res.length);
        return res;
    }


    private byte[] mgf1Hash(byte[] seed, byte c) {
        md.update(seed);
        md.update(new byte[3]);
        md.update(c);
        return md.digest();
    }


    private byte[] concat(byte[] a, byte[] b) {
        byte[] res = new byte[a.length + b.length];
        System.arraycopy(a, 0, res, 0, a.length);
        System.arraycopy(b, 0, res, a.length, b.length);
        return res;
    }


    private byte[] concat(byte[] a, byte[] b, byte[] c) {
        return concat(a, concat(b, c));
    }


    protected void engineUpdate(byte b) {
        this.md.update(b);
    }


    protected void engineUpdate(byte[] buf, int off, int len) {
        this.md.update(buf, off, len);
    }


    protected boolean engineVerify(byte[] signature) {

        // 1. If the length of the signature S is not k octets, output
        //    invalid signature and stop.
        if( signature.length != this.getModulusLen() )
            return false;

        // 2. Convert the signature S to an integer signature representative
        BigInteger s = new BigInteger(1, signature);

        // 3. Apply the RSAVP1 verification primitive
        if( s.compareTo(Util.BI_ZERO) < 0 || s.compareTo(this.n) >= 0 )
            return false;
        BigInteger m = RSAAlgorithm.rsa(s, n, exp, p, q, u); // m >= 0

        // 4. Convert the message representative m to an encoded message EM
        //    of length emLen = ceil( (modBits-1)/8 ) octets, where modBits
        //    is the length in bits of the modulus n
        if( m.bitLength() > (emLen*8) )
            return false;

        byte[] em = Util.toFixedLenByteArray(m, this.emLen);

        // 5.
        return pssVerify(this.md.digest(), em, getModulusBitLen()-1);
    }


    private boolean pssVerify(byte[] mHash, byte[] em, int emBits) {

        // 3. If emBits < 8 * hLen + 8 * sLen + 9, output inconsistent and stop.
        if( emBits < 8*this.hLen + 8*this.sLen + 9 )
            return false;

        // 4. If the rightmost octet of EM does not have hexadecimal value
        //    bc, output inconsistent and stop.
        if( em[em.length - 1] != (byte)0xbc )
            return false;

        // 5a. Let maskedDB be the leftmost emLen  hLen  1 octets of EM,
        int maskedDbLen = emLen - hLen - 1;
        byte[] maskedDb = new byte[maskedDbLen];
        System.arraycopy(em, 0, maskedDb, 0, maskedDbLen);

        // 5b. ... and let H be the next hLen octets.
        byte[] H = new byte[this.hLen];
        System.arraycopy(em, maskedDbLen, H, 0, this.hLen);

        // 6. If the leftmost 8emLen  emBits bits of the leftmost octet
        //    in maskedDB are not all equal to zero, output inconsistent and stop.
        int lmbs = 8*emLen - emBits;
        if( (maskedDb[0] & ~MASK[lmbs]) != 0 )
            return false;

        // 7. Let dbMask = MGF(H, emLen  hLen  1).
        byte[] dbMask = mgf1(H, emLen - this.hLen - 1);

        // 8. Let DB = maskedDB dbMask.
        byte[] DB = xor(maskedDb, dbMask);

        // 9. Set the leftmost 8emLen  emBits bits of DB to zero.
        int zc = 8*emLen - emBits;
        DB[0] &= MASK[zc];

        // 10. If the emLen  hLen  sLen  2 leftmost octets of DB are not
        //     zero or if the octet at position emLen  hLen  sLen  1 is
        //     not equal to 01, output inconsistent and stop.
        int leftMost = emLen - hLen - sLen - 2;
        for(int i=0; i<leftMost; i++)
            if( DB[i] != 0 )
                return false;
        if( DB[leftMost] != 0x1 )
            return false;

        // 11. Let salt be the last sLen octets of DB.
        byte[] salt = new byte[sLen];
        System.arraycopy(DB, DB.length - sLen, salt, 0, sLen);

        // 12, 13. Let H = Hash(M), an octet string of length hLen.
        this.md.reset();
        this.md.update(new byte[8]);
        this.md.update(mHash);
        byte[] H1 = this.md.digest(salt);

        return cryptix.jce.util.Util.equals(H1, H);
    }
}
