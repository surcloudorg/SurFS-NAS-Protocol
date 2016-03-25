/* $Id: ModeOFB.java,v 1.13 2003/02/04 18:38:31 gelderen Exp $
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
import javax.crypto.spec.IvParameterSpec;

/**
 * <B>Please read the comments in the source.</B>
 *
 * @author  Jeroen C. van Gelderen (gelderen@cryptix.org)
 * @author Paul Waserbrot (pw@cryptix.org)
 * @author Kevin Dana, Agorics Inc. (Agorics mod: 16164)
 * @version $Revision: 1.13 $
 */

final class ModeOFB extends Mode
{
    private final byte[] keyStreamBuf;


    private int keyStreamBufOffset;


    /** the IV which is used here */
    private byte [] IV = null;

    ModeOFB(BlockCipher cipher) {
        super(cipher);
        keyStreamBuf = new byte[CIPHER_BLOCK_SIZE];
    }


// Implementation
//............................................................................

    final int coreGetOutputSize(int inputLen) {
        // we are a stream cipher, we don't buffer anything
        return inputLen;
    }
    
    
    void coreInit(boolean decrypt, Key key, AlgorithmParameterSpec params,
                    SecureRandom random)
    throws InvalidKeyException, InvalidAlgorithmParameterException
    {
        // always use block cipher in encrypt mode
        cipher.coreInit(key, false);
        
        // set IV and crypt once to generate initial key stream bytes
        IV = extractIV(params);
        System.arraycopy(IV, 0, keyStreamBuf, 0, CIPHER_BLOCK_SIZE);
        cipher.coreCrypt(keyStreamBuf, 0, keyStreamBuf, 0);
        keyStreamBufOffset = 0;
    }


    final int coreUpdate(byte[] input, int inputOffset, int inputLen,
               byte[] output, int outputOffset)
    {
        int todo = inputLen;
        while( todo-- > 0 ) {
            if( keyStreamBufOffset >= CIPHER_BLOCK_SIZE ) {
                cipher.coreCrypt(keyStreamBuf, 0, keyStreamBuf, 0);
                keyStreamBufOffset = 0;
            }
            output[outputOffset++] = (byte)
                (input[inputOffset++] ^ keyStreamBuf[keyStreamBufOffset++]);
        }
        return inputLen;
    }


    final byte [] coreGetIV()
    {
        return IV;
    }

    final AlgorithmParameterSpec coreGetParamSpec()
    {
        if (IV == null)
           return new IvParameterSpec(generateIV());
        return new IvParameterSpec(IV);
    }

    final boolean needsPadding()
    {
        return false;
    }
}
