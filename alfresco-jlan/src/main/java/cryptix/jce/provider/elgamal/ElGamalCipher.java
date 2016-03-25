/* $Id: ElGamalCipher.java,v 1.10 2003/02/17 18:25:35 gelderen Exp $
 *
 * Copyright (C) 1995-2000 The Cryptix Foundation Limited.
 * All rights reserved.
 *
 * Use, modification, copying and distribution of this software is subject
 * the terms and conditions of the Cryptix General Licence. You should have
 * received a copy of the Cryptix General Licence along with this library;
 * if not, you can download a copy from http://www.cryptix.org/ .
 */
package cryptix.jce.provider.elgamal;

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

import cryptix.jce.ElGamalKey;
import cryptix.jce.ElGamalParams;
import cryptix.jce.ElGamalPrivateKey;
import cryptix.jce.ElGamalPublicKey;

import cryptix.jce.provider.util.Util;

/**
 * Expirimental ElGamal implementation.
 *
 * @author Paul Waserbrot (pw@cryptix.org)
 * @author Kevin Dana, Agorics Inc. (Agorics mod: 16273)
 * @version $Revision: 1.10 $
 */
public final class ElGamalCipher extends CipherSpi {

    private BigInteger p, g, a;


    private int messageMaxLength;


    private boolean decrypt;
    
    public ElGamalCipher() {
        super();
    }

    // FIXME: Add(?) a skipLeadingZero method, since BigInteger add a leading 
    // zero if MSB > 0x7F.. ..hm, that's why i had to add 1 byte in RSACipher
    // Found it when debugged a test progie for ElGamalAlgorithm. (pw)

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
        //we should use p.bitLength() rounded up instead of messageMaxLength
        //which is rounded down.
        return ((p.bitLength() + 7) / 8) * 2;
    }


    protected int engineGetKeySize(Key key) throws InvalidKeyException {

        if( !(key instanceof ElGamalKey) )       
            throw new InvalidKeyException("Not an ElGamalKey!");

        ElGamalParams params = ((ElGamalKey)key).getParams();
        return params.getP().bitLength();
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
        throw new RuntimeException("NYI");
    }

    /* FIXME: Add something about weak keys..
     * comment from Jeroen 
     * "and state in the doco that that is considered pretty 
     * weak and then point to www.cryptosavvy.com " (pw)
     */
    protected final void
    engineInit(int opmode, Key key, SecureRandom random)
    throws InvalidKeyException {
        decrypt = opmode == Cipher.DECRYPT_MODE;
        if(!(key instanceof ElGamalKey) )
        {
            throw new InvalidKeyException("Not an ElGamalKey");
        }
        g = ((ElGamalParams)((ElGamalKey)key).getParams() ).getG();
        p = ((ElGamalParams)((ElGamalKey)key).getParams() ).getP();
        if(decrypt)
        {
            if(!(key instanceof ElGamalPrivateKey) )
            {
                throw new InvalidKeyException("Not a private key");
            }
            a = ((ElGamalPrivateKey)key).getX();
        }
        else
        {
            if(!(key instanceof ElGamalPublicKey) )
            {
                throw new InvalidKeyException("Not a public key" );
            }
            a = ((ElGamalPublicKey)key).getY();
        }
        messageMaxLength = (p.bitLength() - 1)/8;
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
        // FIXME: isn't it a bug here? We must take length - offset! (pw)
        if (output.length < this.engineGetOutputSize(inputLen))
            throw new ShortBufferException("Output buffer too small!");

        BigInteger bi;
        BigInteger [] res;
        byte [] tmp1, tmp2, b;
        
        int blocksize = engineGetBlockSize() / 2;
        if (decrypt) {
            res = new BigInteger[2];
            tmp1 = new byte[blocksize];
            System.arraycopy(input, 0, tmp1, 0, blocksize);
            res[0] = new BigInteger(1, tmp1);
            tmp2 = new byte[blocksize];
            System.arraycopy(input, blocksize, tmp2, 0, blocksize);
            res[1] = new BigInteger(1, tmp2);
            
            BigInteger m = null;
            
            try {
                m = ElGamalAlgorithm.decrypt(res, p, a);
            } catch (ArithmeticException e) {
                // This is not really a bad padding exception, however we are
                // not allowed to throw other exceptions and this one comes the
                // closest to what is going on here (applications should handle
                // them the same way anyway).
                throw new BadPaddingException("Decryption Failed.");
            }
            
            b = Util.toFixedLenByteArray(m, blocksize);
            return unpad(b, b.length, 0, output, outputOffset);
        } else {
            /* FIXME: Do so we choose right block type out of the keytype?
             * (pw)
             */
            bi = new BigInteger(1, pad(input, inputLen, 
                                inputOffset, 0x02));
            res = ElGamalAlgorithm.encrypt(bi, p, g, a);

            tmp1 = Util.toFixedLenByteArray(res[0], blocksize);
            tmp2 = Util.toFixedLenByteArray(res[1], blocksize);

            System.arraycopy(tmp1,0,output,outputOffset, tmp1.length);
            System.arraycopy(tmp2,0,output,outputOffset + tmp1.length, 
                             tmp2.length);
            
            return tmp1.length + tmp2.length;
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

    
    /* 
     * Should we implement this one?? (pw)
    protected int 
    engineGetKeySize(Key key)
    throws InvalidKeyException {
        throw new UnsupportedOperationException(
            "Not implemented by the provider!");
    }
    */


// Private methods
//............................................................................

    /*
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
    private byte[] pad(byte[] input, int inputLen, int offset, int bt) 
    throws BadPaddingException {
        int k = (p.bitLength() + 7)/8;
        if (inputLen > k-11)
            throw new BadPaddingException("Data too long for this modulus!");

        byte[] ed = new byte[k];
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


    private int unpad(byte[] input, int inputLen, int inOffset,
                      byte[] output, int outOffset)
    throws BadPaddingException {
        int bt = input[inOffset + 1];
        int padLen = 1;
        try {
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
        } catch (ArrayIndexOutOfBoundsException ex) {
            throw new BadPaddingException(
                "Cannot unpad: padding incorrect for PKCS#1 block type "+bt);
        }

        padLen++;

        int len = inputLen - inOffset - padLen;
        System.arraycopy(input, inOffset + padLen, output, outOffset, len);
        return len;
    }
}
