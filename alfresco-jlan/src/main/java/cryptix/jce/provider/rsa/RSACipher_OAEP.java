/* $Id: RSACipher_OAEP.java,v 1.1 2003/02/07 15:08:32 gelderen Exp $
 *
 * Copyright (C) 2002, 2003 The Cryptix Foundation Limited.
 * All rights reserved.
 *
 * Use, modification, copying and distribution of this software is subject
 * the terms and conditions of the Cryptix General Licence. You should have
 * received a copy of the Cryptix General Licence along with this library;
 * if not, you can download a copy from http://www.cryptix.org/ .
 */
package cryptix.jce.provider.rsa;


import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.interfaces.RSAPublicKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherSpi;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKeyFactory;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.SecretKeySpec;

import cryptix.jce.provider.util.Util;


/**
 * @author Jeroen C. van Gelderen (gelderen@cryptix.org)
 * @version $Revision: 1.1 $
 */
public abstract class RSACipher_OAEP extends CipherSpi {

    private final MessageDigest _md;

    private final int _hLen;

    private final byte[] _lHash;

    private SecureRandom _rng;

    private BigInteger _n, _exp, _p, _q, _u;

    /** Byte-length of modulus (n), excluding sign bit. */
    private int _k;

    private int _mode;

    public RSACipher_OAEP(String hashName) {
        try {
            _md = MessageDigest.getInstance(hashName);
            _hLen = _md.getDigestLength();

            //  a. If the label L is not provided, let L be the empty string.
            //     Let lHash = Hash(L), an octet string of length hLen.
            _lHash = _md.digest();

        } catch(NoSuchAlgorithmException ex) {
            // we should have the given hash in our provider so this should
            // be unreachable
            throw new InternalError(
                "MessageDigest not found! (" + hashName + "): " +
                ex.toString());
        }
    }

    protected final void
    engineSetMode(String mode)
    throws NoSuchAlgorithmException {
//        if (!mode.equalsIgnoreCase("ECB"))
            throw new NoSuchAlgorithmException("Wrong mode type!");
    }


    protected final void
    engineSetPadding(String padding)
    throws NoSuchPaddingException {
    }


    protected final int
    engineGetBlockSize() {
        throw new IllegalArgumentException();
    }


    protected final int
    engineGetOutputSize(int inputLen) {
        throw new IllegalArgumentException();
    }


    protected final byte[]
    engineGetIV() { 
        return null;
    }


    protected final AlgorithmParameters
    engineGetParameters() {
        return null;
    }


    protected final void
    engineInit(int opmode, Key key, SecureRandom random)
    throws InvalidKeyException {

        if (!(key instanceof RSAPrivateKey) && !(key instanceof RSAPublicKey))
            throw new InvalidKeyException(
              "Key must be instance of either RSAPublicKey or RSAPrivateKey!");

        _mode = opmode;
        _rng = random;

        if (_mode == Cipher.DECRYPT_MODE) {
            _n = ((RSAPrivateKey)key).getModulus();
            _exp = ((RSAPrivateKey)key).getPrivateExponent();
        } else if(_mode == Cipher.ENCRYPT_MODE) {
            _n = ((RSAPublicKey)key).getModulus();
            _exp = ((RSAPublicKey)key).getPublicExponent();
        } else {
            throw new IllegalArgumentException("opmode not supported.");
        }

        if (key instanceof RSAPrivateCrtKey) {
            _p = ((RSAPrivateCrtKey)key).getPrimeP();
            _q = ((RSAPrivateCrtKey)key).getPrimeQ();
            _u = ((RSAPrivateCrtKey)key).getCrtCoefficient();
        } else {
            _p = _q = _u = null;
        }

        // round up to nearest multiple of eight bits
        _k = (_n.bitLength() + 7) / 8;

        //  c. If k < 2hLen + 2, output "decryption error" and stop.
        if(_k < 2*_hLen +2)
            throw new InvalidKeyException("Modulus too short.");
    }


    protected final void
    engineInit(int opmode, Key key, AlgorithmParameterSpec params,
               SecureRandom random)
    throws InvalidKeyException, InvalidAlgorithmParameterException
    {
        if(params != null)
            throw new InvalidAlgorithmParameterException(
                "This cipher do not support AlgorithmParameterSpecs");

        engineInit(opmode, key, random);
    }


    protected final void
    engineInit(int opmode, Key key, AlgorithmParameters params,
               SecureRandom random)
    throws InvalidKeyException, InvalidAlgorithmParameterException
    {
        if(params != null)
            throw new InvalidAlgorithmParameterException(
                "This cipher do not support AlgorithmParameters");

        engineInit(opmode, key, random);
    }


    protected final byte[]
    engineUpdate(byte[] input, int inputOffset, int inputLen) {
        throw new RuntimeException("You can't do an update when using OAEP!");
    }


    protected final int
    engineUpdate(byte[] input, int inputOffset, int inputLen,
                 byte[] output, int outputOffset)
    throws ShortBufferException {
        throw new RuntimeException("You can't do an update when using OAEP!");
    }


    protected final byte[]
    engineDoFinal(byte[] input, int inputOffset, int inputLen)
    throws IllegalBlockSizeException, BadPaddingException {
        if(_mode == Cipher.ENCRYPT_MODE) {
            byte[] M = new byte[inputLen];
            System.arraycopy(input, inputOffset, M, 0, inputLen);
            byte[] C = RSAES_OAEP_ENCRYPT(M);
            return C;
        } else {
            byte[] C = new byte[inputLen];
            System.arraycopy(input, inputOffset, C, 0, inputLen);
            byte[] M = RSAES_OAEP_DECRYPT(C);
            return M;
        }
    }


    protected final int
    engineDoFinal(byte[] input, int inputOffset, int inputLen,
                  byte[] output, int outputOffset)
    throws ShortBufferException, IllegalBlockSizeException, BadPaddingException
    {
        byte[] M = new byte[inputLen];
        System.arraycopy(input, inputOffset, M, 0, inputLen);

        byte[] C = RSAES_OAEP_ENCRYPT(M);

        int outputLen = output.length - outputOffset;
        if(C.length > outputLen)
            throw new ShortBufferException();
        System.arraycopy(C, 0, output, outputOffset, C.length);
        return C.length;
    }


    protected int engineGetKeySize(Key key) throws InvalidKeyException {

        if(key instanceof RSAPublicKey)
            return ((RSAPublicKey)key).getModulus().bitLength();
        else if(key instanceof RSAPrivateKey)
            return ((RSAPrivateKey)key).getModulus().bitLength();
        else
            throw new InvalidKeyException("Not an RSA key.");
    }


    private byte[] RSAES_OAEP_DECRYPT(byte[] C)
        throws BadPaddingException, IllegalBlockSizeException
    {
        // 1. Length checking:
        //  a. If the length of L is greater than the input limitation for
        //     the hash function, output "decryption error" and stop.
        //  -- we use the empty label

        //  b. If the length of the ciphertext C is not k octets, output
        //     "decryption error" and stop.
        if(C.length != _k)
            throw new IllegalBlockSizeException();

        //  c. If k < 2hLen + 2, output "decryption error" and stop.
        //  -- we check for this in engineInit

        // 2. RSA decryption:
        //  a. Convert the ciphertext C to an integer ciphertext
        //     representative c = OS2IP (C) .
        BigInteger c = new BigInteger(1, C);

        //  b. Apply the RSADP decryption primitive to the RSA private
        //     key K and the ciphertext representative c to produce an
        //     integer message representative m = RSADP (K, c) .
        //     If RSADP outputs "ciphertext representative out of range"
        //     (meaning that c >= n), output "decryption error" and stop.
        BigInteger m = RSAAlgorithm.rsa(c, _n, _exp, _p, _q, _u);
        // XXX: handle errors (bad key)

        //  c. Convert the message representative m to an encoded message
        //     EM of length k octets: EM = I2OSP (m, k) .
        byte[] EM = Util.toFixedLenByteArray(m, _k);
        // XXX: handle m too long (bad key)
        
        // 3. EME-OAEP decoding:
        //  a. If the label L is not provided, let L be the empty string.
        //     Let lHash = Hash(L), an octet string of length hLen.
        //  -- done in ctor

        //  b. Separate the encoded message EM into a single octet Y, an
        //     octet string maskedSeed of length hLen, and an octet string
        //     maskedDB of length k - hLen - 1 as
        //         EM = Y || maskedSeed || maskedDB .
        if(EM[0] != 0x00)
            throw new BadPaddingException();

        byte[] maskedSeed = new byte[_hLen];
        System.arraycopy(EM, 1, maskedSeed, 0, maskedSeed.length);
        
        byte[] maskedDB = new byte[_k - _hLen -1];
        System.arraycopy(EM, 1 + _hLen, maskedDB, 0, maskedDB.length);

        //  c. Let seedMask = MGF (maskedDB, hLen).
        byte[] seedMask = mgf1(maskedDB, _hLen);

        //  d. Let seed = maskedSeed ^ seedMask.
        byte[] seed = xor(maskedSeed, seedMask);

        //  e. Let dbMask = MGF (seed, k - hLen - 1).
        byte[] dbMask = mgf1(seed, _k - _hLen -1);

        //  f. Let DB = maskedDB ^ dbMask.
        byte[] DB = xor(maskedDB, dbMask);

        //  g. Separate DB into an octet string lHash' of length hLen,
        //     a (possibly empty) padding string PS consisting of octets
        //     with hexadecimal value 0x00, and a message M as
        //         DB = lHash' || PS || 0x01 || M .
        //     If there is no octet with hexadecimal value 0x01 to separate
        //     PS from M, if lHash does not equal lHash', or if Y is
        //     nonzero, output "decryption error" and stop.
        byte[] lHash1 = new byte[_hLen];
        System.arraycopy(DB, 0, lHash1, 0, lHash1.length);
        if(!Util.equals(_lHash, lHash1))
            throw new BadPaddingException();

        int i = _hLen;
        for( ; i < DB.length; i++)
            if(DB[i] != 0x00)
                break;

        if(DB[i++] != 0x01)
            throw new BadPaddingException();

        //  4. Output the message M.
        int mLen = DB.length - i;
        byte[] M = new byte[mLen];
        System.arraycopy(DB, i, M, 0, mLen);
        return M;
    }


    private byte[] RSAES_OAEP_ENCRYPT(byte[] M)
        throws IllegalBlockSizeException
    {
        int mLen = M.length;

        // 1. Length checking:
        //  a. If the length of L is greater than the input limitation for
        //     the hash function, output "label too long" and stop.
        // -- we use zero-length L so this check is not necessary

        //  b. If mLen > k-2hLen-2, output "message too long" and stop.
        if(mLen > _k - 2*_hLen - 2)
            throw new IllegalBlockSizeException();
        //
        // 2. EME-OAEP encoding
        //  a. If the label L is not provided, let L be the empty string.
        //     Let lHash = Hash(L), an octet string of length hLen.
        //  -- see constructor, value in _lHash

        //  b. Generate an octet string PS consisting of k-mLen-2hLen-2
        //     zero octets. The length of PS may be zero.
        byte[] PS = new byte[_k - mLen - 2*_hLen -2];

        //  c. Concatenate lHash, PS, a single octet with hexadecimal
        //     value 0x01, and the message M to form a data block DB of
        //     length k-hLen-1 octets as DB = lHash || PS || 0x01 || M .
        byte[] DB = concat(_lHash, PS, new byte[]{ 0x01 }, M);

        //  d. Generate a random octet string seed of length hLen.
        byte[] seed = new byte[_hLen];
        _rng.nextBytes(seed);

        //  e. Let dbMask = MGF (seed, _k - hLen - 1)
        byte[] dbMask = mgf1(seed, _k - _hLen - 1);

        //  f. Let maskedDB = DB ^ dbMask.
        byte[] maskedDB = xor(DB, dbMask);

        //  g. Let seedMask = MGF (maskedDB, hLen).
        byte[] seedMask = mgf1(maskedDB, _hLen);

        //  h. Let maskedSeed = seed ^ seedMask.
        byte[] maskedSeed = xor(seed, seedMask);

        //  i. Concatenate a single octet with hexadecimal value 0x00,
        //     maskedSeed, and maskedDB to form an encoded message EM of
        //     length k octets as EM = 0x00 || maskedSeed || maskedDB.
        byte[] EM = concat(new byte[]{ 0x00 }, maskedSeed, maskedDB);

        // 3. RSA encryption:
        //  a. Convert the encoded message EM to an integer message
        //     representative m = OS2IP (EM) .
        BigInteger m = new BigInteger(1, EM);

        //  b. Apply the RSAEP encryption primitive to the RSA public
        //     key (n, e) and the message representative m to produce an
        //     integer ciphertext representative c: c = RSAEP ((n, e), m) .
        BigInteger c = RSAAlgorithm.rsa(m, _n, _exp, _p, _q, _u);
        // XXX: handle error (bad key)

        //  c. Convert the ciphertext representative c to a ciphertext C
        //     of length k octets C = I2OSP (c, k) .
        byte[] C = Util.toFixedLenByteArray(c, _k);
        // XXX: handle error (bad key)

        // 4. Output the ciphertext C.
        return C;
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
        int hashCount = (len + _hLen - 1) / _hLen; // ceil(len / hLen)
        byte[] mask = new byte[0];
        for(int i=0; i<hashCount; i++)
            mask = concat(mask, mgf1Hash(seed, (byte)i));
        byte[] res = new byte[len];
        System.arraycopy(mask, 0, res, 0, res.length);
        return res;
    }


    private byte[] mgf1Hash(byte[] seed, byte c) {
        _md.update(seed);
        _md.update(new byte[3]);
        _md.update(c);
        return _md.digest();   
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


    private byte[] concat(byte[] a, byte[] b, byte[] c, byte[] d) {
        return concat(a, concat(b, concat(c, d)));   
    }
}
