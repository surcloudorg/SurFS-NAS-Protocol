/* $Id: Null.java,v 1.6 2000/07/28 02:41:49 gelderen Exp $
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

import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.BadPaddingException;
import javax.crypto.CipherSpi;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;


/**
 * Null cipher (identity transformation).
 *
 * @version $Revision: 1.6 $
 * @author  Jeroen C. van Gelderen (gelderen@cryptix.org)
 */
public final class Null extends CipherSpi
{
    /**
     * The block size of this cipher. Being a stream cipher this value
     * is 1!
     */
    private static final int BLOCK_SIZE = 1;


// Constructor
//............................................................................

    public Null() {
        super();
    }


    /**
     * Always throws a CloneNotSupportedException (cloning of ciphers is not
     * supported for security reasons).
     */
    public final Object clone() throws CloneNotSupportedException {
        throw new CloneNotSupportedException();
    }


// Implementation of JCE methods
//............................................................................

    protected final void engineSetMode(String mode)
    throws NoSuchAlgorithmException 
    {
        if(mode.equalsIgnoreCase("ECB"))
            return;
        else
            throw new NoSuchAlgorithmException();
    }
    
    
    protected final void engineSetPadding(String padding)
    throws NoSuchPaddingException 
    {
        if(padding.equalsIgnoreCase("None") ||
           padding.equalsIgnoreCase("NoPadding") )
        {
            return;
        }

        throw new NoSuchPaddingException();
    }
    
    
    /**
     * Returns the length of an input block, in bytes.
     *
     * @return the length in bytes of an input block for this cipher.
     */
    public int engineGetBlockSize () 
    { 
        return BLOCK_SIZE; 
    }


    /**
     * Return output size given input length. We don't buffer so this method
     * always returns inputLen.
     */
    protected final int engineGetOutputSize(int inputLen) 
    {
        return inputLen;
    }
    

    /**
     * We don't use IVs.
     *
     * FIXME: maybe return whatever was set?
     */
    protected final byte[] engineGetIV() 
    {
        return null;
    }
    
    
    protected final AlgorithmParameters engineGetParameters() 
    {
        return null;
    }
    

    protected final void engineInit(int opmode, Key key, SecureRandom random)
    throws InvalidKeyException 
    {
    }


    protected final void
    engineInit(int opmode, Key key, AlgorithmParameterSpec params,
               SecureRandom random)
    throws InvalidKeyException, InvalidAlgorithmParameterException 
    {
        engineInit(opmode, key, random);
    }


    protected final void
    engineInit(int opmode, Key key, AlgorithmParameters params,
               SecureRandom random)
    throws InvalidKeyException, InvalidAlgorithmParameterException 
    {
        engineInit(opmode, key, random);
    }
    
    
    protected final int
    engineUpdate(byte[] input, int inputOffset, int inputLen,
                 byte[] output, int outputOffset)
    throws ShortBufferException 
    {
        if( output.length-outputOffset < inputLen )
            throw new ShortBufferException();

        return this.internalUpdate(input, inputOffset, inputLen,
                                   output, outputOffset);
    }
    
    
    protected final byte[]
    engineUpdate(byte[] input, int inputOffset, int inputLen) 
    {
        byte[] tmp  = new byte[this.engineGetOutputSize(inputLen)];
        this.internalUpdate(input, inputOffset, inputLen, tmp, 0);
        return tmp;
    }
    
    
    protected final int
    engineDoFinal(byte[] input, int inputOffset, int inputLen,
                  byte[] output, int outputOffset)
    throws ShortBufferException, IllegalBlockSizeException, BadPaddingException
    {
        return engineUpdate(input, inputOffset, inputLen, output, outputOffset);
    }
    
    
    protected final byte[]
    engineDoFinal(byte[] input, int inputOffset, int inputLen)
    throws IllegalBlockSizeException, BadPaddingException 
    {
        byte[] tmp  = new byte[this.engineGetOutputSize(inputLen)];
        this.internalUpdate(input, inputOffset, inputLen, tmp, 0);
        return tmp;
    }


    private final int 
    internalUpdate(byte[] input, int inputOffset, int inputLen,
                   byte[] output, int outputOffset)
    {
        System.arraycopy(input, inputOffset, output, outputOffset, inputLen);
        return inputLen;
    }
}
