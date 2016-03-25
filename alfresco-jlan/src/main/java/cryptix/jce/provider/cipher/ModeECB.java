/* $Id: ModeECB.java,v 1.12 2001/08/06 18:06:50 edwin Exp $
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

/**
 * <B>Please read the comments in the source.</B>
 *
 * @author  Jeroen C. van Gelderen (gelderen@cryptix.org)
 * @author Paul Waserbrot (pw@cryptix.org)
 * @version $Revision: 1.12 $
 */


final class ModeECB extends Mode
{
    /** buffers incomplete blocks */
    private final byte[] buf; // we count the buffer with bufCount from Mode.java



    ModeECB(BlockCipher cipher) {
        super(cipher);
        buf = new byte[CIPHER_BLOCK_SIZE];
    }


// Implementation
//............................................................................

    final int coreGetOutputSize(int inputLen) {
        return ((bufCount+inputLen)/CIPHER_BLOCK_SIZE)*CIPHER_BLOCK_SIZE;
    }


    final void coreInit(boolean decrypt, Key key, AlgorithmParameterSpec params,
                    SecureRandom random)
    throws InvalidKeyException, InvalidAlgorithmParameterException
    {
        cipher.coreInit(key, decrypt);
    }


    int coreUpdate(byte[] input, int inputOffset, int inputLen,
               byte[] output, int outputOffset)
    {
        // Invariant: bufCount < CIPHER_BLOCK_SIZE bytes

        int ret = 0;
        int remainder;
        while(inputLen >= (remainder = CIPHER_BLOCK_SIZE - bufCount)) {
            System.arraycopy(input, inputOffset, buf, bufCount, remainder);
            cipher.coreCrypt(buf, 0, output, outputOffset);
            inputLen     -= remainder;
            inputOffset  += remainder;
            outputOffset += CIPHER_BLOCK_SIZE;
            ret          += CIPHER_BLOCK_SIZE;
            bufCount      = 0;
        }

        // Invariant: bufCount < CIPHER_BLOCK_SIZE bytes

        System.arraycopy(input, inputOffset, buf, bufCount, inputLen);
        bufCount += inputLen;

        // Invariant: bufCount < CIPHER_BLOCK_SIZE bytes

        return ret;
    }

    final byte [] coreGetIV() 
    {
        return (byte []) null;
    }

    final AlgorithmParameterSpec coreGetParamSpec() 
    {
        return (AlgorithmParameterSpec) null;
    }

    final boolean needsPadding()
    {
        return true;
    }
}
