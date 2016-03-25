/* $Id: ModeCBC.java,v 1.13 2003/02/04 18:38:31 gelderen Exp $
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

final class ModeCBC extends Mode
{
    /** buffers incomplete blocks */
    private final byte[] buf; // we count the buf with bufCount from Mode.java


    /** previous ciphertext block (during decryption only) */
    private final byte[] prevBlock;
    
    
    /** the IV which is used here */
    private byte [] IV = null;

    ModeCBC(BlockCipher cipher) {
        super(cipher);
        buf       = new byte[CIPHER_BLOCK_SIZE];
        prevBlock = new byte[CIPHER_BLOCK_SIZE];
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
        // set IV
        IV = extractIV(params);
        
        if(decrypt) {
            System.arraycopy(IV, 0, prevBlock, 0, CIPHER_BLOCK_SIZE);
            bufCount = 0;
        } else {
            System.arraycopy(IV, 0, buf, 0, CIPHER_BLOCK_SIZE);
            bufCount = 0;
        }
    }


    int coreUpdate(byte[] input, int inputOffset, int inputLen,
               byte[] output, int outputOffset)
    {
        if(decrypt) {
            int ret = 0;
            int remainder;
            while(inputLen >= (remainder = CIPHER_BLOCK_SIZE - bufCount)) {
                
                for( int i=0; i<remainder; i++)
                    buf[bufCount++] = input[inputOffset++];

                // encrypt to output
                cipher.coreCrypt(buf, 0, output, outputOffset);
                
                // xor in previous block
                for( int i=0; i<CIPHER_BLOCK_SIZE; i++)
                    output[outputOffset++] ^= prevBlock[i];
                
                // store cipher text as IV for next block
                for( int i=0; i<CIPHER_BLOCK_SIZE; i++)
                    prevBlock[i] = buf[i];
                
                inputLen     -= CIPHER_BLOCK_SIZE;
                ret          += CIPHER_BLOCK_SIZE;
                bufCount      = 0;
            }
            
            for( int i=0; i<inputLen; i++)
                buf[bufCount++] = input[inputOffset++];

            return ret;

        } else {
            int ret = 0;
            int remainder;
            while(inputLen >= (remainder = CIPHER_BLOCK_SIZE - bufCount)) {
                for( int i=0; i<remainder; i++)
                    buf[bufCount++] ^= input[inputOffset++];

                cipher.coreCrypt(buf, 0, buf, 0);
                System.arraycopy(buf, 0, output, outputOffset, CIPHER_BLOCK_SIZE);
                inputLen     -= remainder;
                outputOffset += CIPHER_BLOCK_SIZE;
                ret          += CIPHER_BLOCK_SIZE;
                bufCount      = 0;
            }

            for( int i=0; i<inputLen; i++)
                buf[bufCount++] ^= input[inputOffset++];

            return ret;
        }
        
        
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
        return true;
    }
}
