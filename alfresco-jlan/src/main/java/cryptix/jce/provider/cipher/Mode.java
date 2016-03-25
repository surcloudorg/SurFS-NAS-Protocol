/* $Id: Mode.java,v 1.18 2003/02/04 18:38:31 gelderen Exp $
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
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.RC2ParameterSpec;
import javax.crypto.spec.RC5ParameterSpec;


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
 * @author Kevin Dana, Agorics Inc. (Agorics mod: 16164)
 * @version $Revision: 1.18 $
 */
/*package*/ abstract class Mode
{
    /** Underlying block cipher */
    protected final BlockCipher cipher;


    /** Block size of underlying cipher */
    protected final int CIPHER_BLOCK_SIZE;


    /** Decrypting? */
    protected boolean decrypt;


    /** How many bytes the buffer holds */
    protected int bufCount;


    /*package*/ Mode(BlockCipher cipher) {
        this.cipher       = cipher;
        CIPHER_BLOCK_SIZE = cipher.coreGetBlockSize();
    }


    /*package*/ static Mode getInstance(String mode, BlockCipher cipher)
    throws NoSuchAlgorithmException
    {
        try {
            if( mode.equalsIgnoreCase("CBC") )
                return new ModeCBC(cipher);

            else if( mode.substring(0, 3).equalsIgnoreCase("CFB") ) {
                String fbs = mode.substring(3, mode.length());
                if( fbs.length() > 0 )
                    return new ModeCFB(cipher, Integer.parseInt(fbs));
                else
                    return new ModeCFB(cipher);
            }
            else if( mode.equalsIgnoreCase("ECB") )
                return new ModeECB(cipher);
            else if( mode.equalsIgnoreCase("OFB") )
                return new ModeOFB(cipher);
            else if( mode.equalsIgnoreCase("openpgpCFB") )
                return new ModeOpenpgpCFB(cipher);
        } 
        catch(IndexOutOfBoundsException e) {
            // ignore here and fail below
        }

        throw new NoSuchAlgorithmException(
            "Mode (" + mode +") not available." );
    }


    /*package*/ void init(boolean decrypt, Key key,
                          AlgorithmParameterSpec params,
                          SecureRandom random)
    throws InvalidKeyException, InvalidAlgorithmParameterException
    {
        this.decrypt = decrypt;
        coreInit(decrypt, key, params, random);
    }


    /*package*/ final byte[] getIV() {
        return coreGetIV();
    }


    /*package*/ final AlgorithmParameterSpec getParamSpec() {
        return coreGetParamSpec();
    }


    /*package*/ final int getOutputSize(int inputLen) {
        return coreGetOutputSize(inputLen);
    }


    /*package*/ final int getBlockSize() {
        return CIPHER_BLOCK_SIZE;
    }


    /*package*/ final int update(byte[] input, int inputOffset, int inputLen,
                                 byte[] output, int outputOffset) {
        return coreUpdate(input, inputOffset, inputLen, output, outputOffset);
    }

   
    /*package*/ final int getBufSize() {
        return bufCount;
    }


    protected byte [] generateIV() {
        byte [] b = new byte[CIPHER_BLOCK_SIZE];
        SecureRandom sr = new SecureRandom();
        sr.nextBytes(b);
        return b;
    }


    protected final byte[] extractIV(AlgorithmParameterSpec params)
        throws InvalidAlgorithmParameterException
    {
        /*
         * -- AlgorithmParameterSpec is a blank interface
         *    and the Java JCE does not provide a common superinterface
         *    for AlgorithmParameterSpec subclasses that provide
         *    initialization vector (IV) byte arrays,
         *    so test for each known type that has a "getIV()" method
         *
         * -- The current API creates a combinatorial explosion. The JCE
         *    API should be amended with a composite AlgorithmParameterSpec
         *    class so that the getIV functionality doesn't have to be
         *    replicated in each ParameterSpec.
         */
        if (params instanceof IvParameterSpec) {
            return ((IvParameterSpec)params).getIV();
        } else if (params instanceof RC2ParameterSpec) {
            return ((RC2ParameterSpec)params).getIV();
        } else if (params instanceof RC5ParameterSpec) {
            return ((RC5ParameterSpec)params).getIV();
        } else {
            throw new InvalidAlgorithmParameterException(
                "Don't know how to get an IV from a " +
                params.getClass().getName());
        }
    }

// Abstract methods
//............................................................................

    abstract int coreGetOutputSize(int inputLen);

    abstract void coreInit(boolean decrypt, Key key, 
                           AlgorithmParameterSpec params, SecureRandom random)
    throws InvalidKeyException, InvalidAlgorithmParameterException;


    abstract int coreUpdate(byte[] input, int inputOffset, int inputLen,
                            byte[] output, int outputOffset);

    abstract byte [] coreGetIV();

    abstract AlgorithmParameterSpec coreGetParamSpec();
    
    abstract boolean needsPadding();
    
}
