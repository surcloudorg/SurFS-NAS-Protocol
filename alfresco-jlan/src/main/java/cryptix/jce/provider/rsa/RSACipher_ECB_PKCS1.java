/* $Id: RSACipher_ECB_PKCS1.java,v 1.12 2003/02/17 18:25:19 gelderen Exp $
 *
 * Copyright (C) 1995-2000 The Cryptix Foundation Limited.
 * All rights reserved.
 *
 * Use, modification, copying and distribution of this software is subject
 * the terms and conditions of the Cryptix General Licence. You should have
 * received a copy of the Cryptix General Licence along with this library;
 * if not, you can download a copy from http://www.cryptix.org/ .
 */
package cryptix.jce.provider.rsa;

import javax.crypto.Cipher;
import javax.crypto.CipherSpi;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKeyFactory;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.BadPaddingException;
import javax.crypto.ShortBufferException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.spec.SecretKeySpec;

import java.math.BigInteger;
import java.security.Key;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.AlgorithmParameters;
import java.security.NoSuchProviderException;
import java.security.NoSuchAlgorithmException;
import java.security.InvalidKeyException;
import java.security.InvalidAlgorithmParameterException;
import java.security.spec.InvalidKeySpecException;
import java.security.interfaces.RSAPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPrivateCrtKey;


/**
 * <B>Please read the comments in the source.</B>
 *
 * @author Paul Waserbrot (pw@cryptix.org)
 * @version $Revision: 1.12 $
 */
public final class RSACipher_ECB_PKCS1 extends CipherSpi {

    private BigInteger n, e, p, q, u;

    private boolean decrypt;

    public RSACipher_ECB_PKCS1() {
        super();
    }

    protected final void
    engineSetMode(String mode)
    throws NoSuchAlgorithmException {
        if (!mode.equalsIgnoreCase("ECB"))
            throw new NoSuchAlgorithmException("Wrong mode type!");
    }


    protected final void
    engineSetPadding(String padding)
    throws NoSuchPaddingException {
        if (!padding.equalsIgnoreCase("PKCS1")
            && !padding.equalsIgnoreCase("PKCS#1")
            && !padding.equalsIgnoreCase("PKCS1Padding"))
        {
            // Added as many cases i could think of.. (pw)
            throw new NoSuchPaddingException("Wrong padding scheme!");
        }
    }


    protected final int
    engineGetBlockSize() {
        return (n.bitLength()+7)/8;
    }


    protected final int
    engineGetOutputSize(int inputLen) {
        return (inputLen < this.engineGetBlockSize()+1) ? 
            this.engineGetBlockSize() + 1: inputLen;
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

        decrypt = ((opmode == Cipher.DECRYPT_MODE) || 
                   (opmode == Cipher.UNWRAP_MODE));

        if (decrypt) {
            n = ((RSAPrivateKey)key).getModulus();
            e = ((RSAPrivateKey)key).getPrivateExponent();
            
        } else {
            n = ((RSAPublicKey)key).getModulus();
            e = ((RSAPublicKey)key).getPublicExponent();
        }

        if (key instanceof RSAPrivateCrtKey) {
            p = ((RSAPrivateCrtKey)key).getPrimeP();
            q = ((RSAPrivateCrtKey)key).getPrimeQ();
            u = ((RSAPrivateCrtKey)key).getCrtCoefficient();
        } else {
            p = q = u = null;
        }
    }


    protected final void
    engineInit(int opmode, Key key, AlgorithmParameterSpec params,
               SecureRandom random)
    throws InvalidKeyException, InvalidAlgorithmParameterException {
        throw new InvalidAlgorithmParameterException(
            "This cipher do not support AlgorithmParameterSpecs");
    }


    protected final void
    engineInit(int opmode, Key key, AlgorithmParameters params,
               SecureRandom random)
    throws InvalidKeyException, InvalidAlgorithmParameterException {
        throw new InvalidAlgorithmParameterException(
            "This cipher do not support AlgorithmParameters");
    }


    protected final byte[]
    engineUpdate(byte[] input, int inputOffset, int inputLen) {
        throw new RuntimeException("You can't do an update when using PKCS1!");
        /* Or should we buffer everything until doFinal 
         * or maybe .update() the buffer as many blocksizes a possible and 
         * then buffer (like we do for blockciphers)?
         * IMO a bad idea! (pw)
         */
    }


    protected final int
    engineUpdate(byte[] input, int inputOffset, int inputLen,
                 byte[] output, int outputOffset)
    throws ShortBufferException {
        throw new RuntimeException("You can't do an update when using PKCS1!");
        /* Or should we buffer everything until doFinal?? 
         * or maybe .update() the buffer as many blocksizes a possible and 
         * then buffer (like we do for blockciphers)?
         * IMO a bad idea! (pw)
         */
    }


    protected final byte[]
    engineDoFinal(byte[] input, int inputOffset, int inputLen)
    throws IllegalBlockSizeException, BadPaddingException {
        byte [] o = new byte[this.engineGetOutputSize(inputLen)];
        int ret;
        try {
            ret = this.engineDoFinal(input, inputOffset, inputLen, o, 0);
            if (ret == o.length) 
                return o;
        } catch (ShortBufferException e) {
            throw new RuntimeException("PANIC: Should not happned!");
        }

        // If the buffer returned is smaller than what we allocated first.
        byte [] r = new byte[ret];
        System.arraycopy(o, 0, r, 0, ret);
        return r;
    }


    protected final int
    engineDoFinal(byte[] input, int inputOffset, int inputLen,
                  byte[] output, int outputOffset)
    throws ShortBufferException, IllegalBlockSizeException, BadPaddingException
    {
        if (output.length < this.engineGetOutputSize(inputLen))
            throw new ShortBufferException("Output buffer too small!");

        byte[] blub = new byte[inputLen];
        System.arraycopy(input, inputOffset, blub, 0, inputLen);

        byte [] b;
        BigInteger bi, res;
        if (decrypt) {
            
            bi = new BigInteger(1, blub);
            if(bi.compareTo(n)!=-1)
                throw new RuntimeException("TT");
            res = RSAAlgorithm.rsa(bi, n, e, p, q, u);
            b = res.toByteArray();
            return unpad(b, b.length, 0,
                         output, outputOffset);
        } else {

            /* FIXME: Do so we choose right block type out of the keytype?
             * (pw)
             */
            bi = new BigInteger(1, pad(blub, blub.length, 0, 0x02));
            if(bi.compareTo(n)!=-1)
                throw new RuntimeException("TT");

            res = RSAAlgorithm.rsa(bi, this.n, this.e);
            if(res.compareTo(n)!=-1)
                throw new RuntimeException("TT");

            int blockSize = engineGetBlockSize();

            b = res.toByteArray();
            if( b.length-1 > blockSize )
                throw new RuntimeException("YY");

            if( b.length > blockSize ) {
                byte[] t = new byte[blockSize];
                System.arraycopy(b, 1, t, 0, blockSize);
                b = t;
            }

            for(int i=0; i<blockSize; i++)
                output[outputOffset+i] = 0x00;

            int bOff = blockSize - b.length;

            System.arraycopy(b, 0, output, outputOffset + bOff, b.length);
            return b.length + bOff;
        }
    }


    protected byte[] 
    engineWrap(Key key)
    throws IllegalBlockSizeException, InvalidKeyException {
        // FIXME: Should we do some sanity check of the key?? (pw)
        String format = key.getFormat();
        // FIXME: Add so we take more than just keys from blockciphers (pw)
        if (format == null || !format.equalsIgnoreCase("RAW"))
            throw new InvalidKeyException("Wrong format on key!");
        byte [] buf = key.getEncoded();
        try {
            return this.engineDoFinal(buf, 0, buf.length); 
        } catch (BadPaddingException e) {
            throw new RuntimeException("PANIC: This should not happend!");
        }
    }

    protected Key 
    engineUnwrap(byte[] wrappedKey, 
                 String wrappedKeyAlgorithm, 
                 int wrappedKeyType)
    throws InvalidKeyException, NoSuchAlgorithmException {
        // FIXME: Add so we also support private and publickeys (pw)
        if (wrappedKeyType != Cipher.SECRET_KEY)
            throw new InvalidKeyException("Wrong keytype!");


        try {
            // FIXME: HACK! Do test to see if we support the algorithm
            // Do we need to do this??? (pw)
            KeyGenerator.getInstance(wrappedKeyAlgorithm, "Cryptix");

            byte [] buf = this.engineDoFinal(wrappedKey, 0, wrappedKey.length);
        
            // FIXME: Shall we check for DES keys and use DESKeySpec? (pw)
            SecretKeySpec sks = new SecretKeySpec(buf, 0, buf.length, 
                                                  wrappedKeyAlgorithm);

            SecretKeyFactory skf = 
                SecretKeyFactory.getInstance(wrappedKeyAlgorithm);
            return skf.generateSecret(sks);

        } catch (NoSuchAlgorithmException e) { // Gee i'm so polite (pw)
            throw new NoSuchAlgorithmException("Algorithm not supported!");
        } catch (NoSuchProviderException e) {
            throw new RuntimeException("PANIC: Should not happend!");
        } catch (BadPaddingException e) {
            throw new RuntimeException("PANIC: This should not happend!");
        } catch (IllegalBlockSizeException e) {
            throw new RuntimeException("PANIC: This should not happend!");
        } catch (InvalidKeySpecException e) {
            throw new RuntimeException("PANIC: This should not happend!");
        }
    }


    protected int engineGetKeySize(Key key) throws InvalidKeyException {

        if(key instanceof RSAPublicKey)       
            return ((RSAPublicKey)key).getModulus().bitLength();
        else if(key instanceof RSAPrivateKey)
            return ((RSAPrivateKey)key).getModulus().bitLength();
        else
            throw new InvalidKeyException("Not an RSA key.");
    }


    /*
     * Private methods below.
     *
     * This is PKCS1 padding as described in the PKCS1 v 1.5 
     * standard section 8 from RSALabs:
     * EB = 00 || BT || PS || 00 || D. 
     * 
     * But since BigInteger actually removes any leading zero
     * the encrypted buffer will be without the first 00.
     *
     * Both pad and unpad assumes us to have check so that the 
     * output buffer is of valid size.
     *
     * I have done so we may use both private and public keys
     * as input, ie BT may be either 0x00, 0x01 or 0x02. (pw)
     */
    private byte[] pad(byte [] input, int inputLen, int offset, int bt) 
    throws BadPaddingException
    {
        int k = (n.bitLength() + 7)/8;
        if (inputLen > k-11)
            throw new BadPaddingException("Data too long for this modulus!");

        byte [] ed = new byte[k];
        int padLen = k - 3 - inputLen;
        ed[0] = ed[2 + padLen] = 0x00;

        switch (bt) {
          case 0x00:
            for (int i = 1; i < (2 + padLen); i++)
                ed[i] = 0x00;
            break;
          case 0x01:
            ed[1] = 0x01;
            for (int i = 2; i < (2 + padLen); i++)
                ed[i] = (byte)0xFF;
            break;
          case 0x02:
            ed[1] = 0x02;
            byte [] b = new byte[1];
            SecureRandom sr = new SecureRandom();
            for (int i = 2; i < (2 + padLen); i++) {
                b[0] = 0;
                while (b[0] == 0)
                    sr.nextBytes(b);
                ed[i] = b[0];
            }
            break;
          default:
            throw new BadPaddingException("Wrong block type!");
        }

        System.arraycopy(input, offset, ed, padLen + 3, inputLen);
        return ed;
    }

    private int unpad(byte [] input, int inputLen, int inOffset,
                      byte [] output, int outOffset)
    throws BadPaddingException {
        int bt = input[inOffset];

        int padLen = 1;
        switch (bt) {
          case 0x00:
            for (;; padLen++)
                if (input[inOffset + padLen + 1] != (byte)0x00) break;
            break;
          case 0x01:
          case 0x02:
            for (;; padLen++)
                if (input[inOffset + padLen] == (byte)0x00) break;
            break;
          default:
            throw new BadPaddingException("Wrong block type!");
        }
        padLen++;

        int len = inputLen - inOffset - padLen;
        System.arraycopy(input, inOffset + padLen, output, outOffset, len);
        return len;
    }
}
