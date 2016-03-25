/* $Id: Padding.java,v 1.18 2000/08/10 22:48:03 gelderen Exp $
 *
 * Copyright (C) 1995-2000 The Cryptix Foundation Limited.
 * All rights reserved.
 *
 * Use, modification, copying and distribution of this software is subject
 * the terms and conditions of the Cryptix General Licence. You should have
 * received a copy of the Cryptix General Licence along with this library;
 * if not, you can download a copy from http://www.cryptix.org/ .
 */
package cryptix.jce.provider.cipher;


import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.ShortBufferException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.BadPaddingException;
import javax.crypto.NoSuchPaddingException;


/**
 * <p>
 * A fully constructed Cipher instance looks like this:
 * <pre>
 * +------------------------------------------+
 * | CipherSpi (API methods)                  |
 * |                                          |
 * | +--------------------------------------+ |
 * | | Padding                              | |
 * | |                                      | |
 * | | +----------------------------------+ | |
 * | | | Mode                             | | |
 * | | |                                  | | |
 * | | | +------------------------------+ | | |
 * | | | | CipherSpi                    | | | |
 * | | | | (blockcipher implementation) | | | |
 * | | | |                              | | | |
 * | | | +------------------------------+ | | |
 * | | |                                  | | |
 * | | +----------------------------------+ | |
 * | |                                      | |
 * | +--------------------------------------+ |
 * |                                          |
 * +------------------------------------------+
 * </pre>
 *
 * @author  Jeroen C. van Gelderen (gelderen@cryptix.org)
 * @author  Paul Waserbrot (pw@cryptix.org)
 * @version $Revision: 1.18 $
 */
abstract class Padding
{
    /** Cipher/Mode delegate */
    private final Mode mode;


    private byte[] scratchBuf;
    private int blSize;
    private boolean isBuffered;


    protected boolean decrypt;


    Padding(Mode mode) {
        this.mode = mode;
        blSize = this.getBlockSize();
        scratchBuf = new byte[blSize];
        isBuffered = false;
    }


    /**
     * Factory method for obtaining different padding type objects.
     *
     * This method accept a padding name and a Mode instance and
     * returns a Padding instance that wraps the given Mode instance.
     * 
     * This class is package protected therefore the various padding 
     * types can be (and are) hardcoded here.
     *
     * @throws NoSuchPaddingException
     *         When the requested padding type cannot be provided.
     */
    static Padding getInstance(String padding, Mode mode)
    throws NoSuchPaddingException
    {
        // Debug.assert(padding!=null);
        // Debug.assert(mode!=null);
        
        // None
        if( padding.equalsIgnoreCase("None")
         || padding.equalsIgnoreCase("NoPadding") )
            return new PaddingNone(mode);
        
        // Generalized PKCS#5 (aka PKCS#7)
        if( padding.equalsIgnoreCase("PKCS5") 
         || padding.equalsIgnoreCase("PKCS#5")
         || padding.equalsIgnoreCase("PKCS5Padding")
         || padding.equalsIgnoreCase("PKCS7")
         || padding.equalsIgnoreCase("PKCS#7") )
            return new PaddingPKCS5(mode);
        
        // Oops, not supported
        throw new NoSuchPaddingException(
            "Padding not available [" + padding + "]");
    }


    /**
     * This method delegates to the wrapped Mode instance.
     */
    final int getBlockSize() {
        return mode.getBlockSize();
    }


    final int getOutputSize(int inputLen) {
        return mode.getOutputSize(inputLen + this.getPadSize(inputLen));
    }


    /**
     * This method delegates to the wrapped Mode instance.
     */
    final AlgorithmParameterSpec getParamSpec() {
        return mode.getParamSpec();
    }


    /**
     * This method delegates to the wrapped Mode instance.
     */
    final byte[] getIV() {
        return mode.getIV();
    }


    /**
     * This method delegates to the wrapped Mode instance.
     */
    final void init(boolean decrypt, Key key, AlgorithmParameterSpec params,
                    SecureRandom random)
    throws InvalidKeyException, InvalidAlgorithmParameterException
    {
        mode.init(this.decrypt = decrypt, key, params, random);
    }


    /**
     * This method delegates to the wrapped Mode instance.
     *
     * @throws ShortBufferException
     *         If output is too short to hold the result.
     */
    final int update(byte[] input, int inputOffset, int inputLen,
                     byte[] output, int outputOffset)
    throws ShortBufferException
    {
        if (output.length < this.getOutputSize(inputLen))
            throw new ShortBufferException("The output buffer is too short");
        
        if (decrypt) {
            int i = 0;
             if (!isBuffered) {
                i = mode.update(input, inputOffset, inputLen - blSize,
                                 output, outputOffset);
                System.arraycopy(input, inputOffset + (inputLen - blSize),
                                 scratchBuf, 0, blSize);
                isBuffered = true;
            } else {
                i = mode.update(scratchBuf, 0, blSize, output, outputOffset);
                System.arraycopy(input, inputOffset + (inputLen - blSize),
                                 scratchBuf, 0, blSize);
                i += mode.update(input, inputOffset, inputLen - blSize,
                                 output, outputOffset + blSize);
            }
            return i;
        } else
            return mode.update(input, inputOffset, inputLen, 
                               output, outputOffset);
    }

    /**
     * @throws BadPaddingException
     *         If the padding data is corrupt or not found (decrypt only).
     * @throws IllegalBlockSizeException
     *         If no padding is specified *and* the input data was not a
     *         multiple of the Cipher's blocksize.
     * @throws ShortBufferException
     *         If output is too short to hold the result.
     */
    final int doFinal(byte[] input, int inputOffset, int inputLen,
                      byte[] output, int outputOffset)
    throws ShortBufferException, IllegalBlockSizeException, BadPaddingException
    {
        if (output.length < this.getOutputSize(inputLen))
            throw new ShortBufferException("The output buffer is too short");
        byte [] t;
        if (decrypt) {
           if (input == null && !isBuffered) return 0;
           if (input != null && inputLen < this.getPadSize(inputLen))
              throw new BadPaddingException("Input data not bounded by the "+
                                            "padding size");
           int i = 0;
           if (isBuffered) {
               i = mode.update(scratchBuf, 0, blSize, 
                               output, outputOffset);
               if (input != null)
                   i += mode.update(input, inputOffset, 
                                    inputLen, output, outputOffset + blSize);
           } else {
               i = mode.update(input, inputOffset, inputLen, 
                               output, outputOffset);
           }
           isBuffered = false;
           return coreUnPad(output,i);
        }
        t = this.corePad(input, inputLen);
        return mode.update(t, inputOffset, t.length, output, outputOffset);
    }


    protected int getBufSize() {
        return mode.getBufSize();
    }

    // Abstract methods which the Padding classes must implement
    abstract byte [] corePad(byte [] input, int inputLen)
        throws IllegalBlockSizeException;

    abstract int coreUnPad(byte [] input, int inputLen);

    abstract int getPadSize(int inputLen); 
}
