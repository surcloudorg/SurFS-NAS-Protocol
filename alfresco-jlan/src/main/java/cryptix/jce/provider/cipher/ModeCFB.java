/* $Id: ModeCFB.java,v 1.5 2003/02/04 18:38:31 gelderen Exp $
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


/**
 * @author  Jeroen C. van Gelderen (gelderen@cryptix.org)
 * @author Kevin Dana, Agorics Inc. (Agorics mod: 16164)
 * @version $Revision: 1.5 $
 */
/*package*/ class ModeCFB extends Mode {

    /**
     * Key stream aka encrypted shift register.
     */
    private final byte[] keyStreamBuf;


    /**
     * Ptr to next usable byte in key stream buffer.
     */
    private int keyStreamPtr;


    /**
     * Shift register. Implemented as a circular buffer.
     */
    private final byte[] shiftReg;


    /**
     * Where the next shifted-in byte will be put.
     */
    private int shiftRegPtr;


    /**
     * How many bytes we have processed. Used to determine when to 'sync'.
     */
    protected long byteCount;


    /**
     * Feedback size in bytes. Valid settings are between 1 and
     * the underlying cipher's blocksize inclusive.
     */
    private int feedbackSize;
    

    /** Decrypt mode? */
    private boolean decrypt;


    /** IV. */
    private byte [] iVec = null;


    /**
     * Construct CFB mode with a feedback size equal to the block size of
     * the underlying cipher.
     */
    /*package*/ ModeCFB(BlockCipher cipher) {
        super(cipher);
        this.keyStreamBuf = new byte[CIPHER_BLOCK_SIZE];
        this.shiftReg= new byte[CIPHER_BLOCK_SIZE];
        this.feedbackSize = CIPHER_BLOCK_SIZE;
    }


    /**
     * Construct CFB mode with the given feedback size. Feedback size must
     * be expressed in bits, be a multiple of 8, greater than 0 and smaller
     * than the underlying cipher's block size.
     *
     * @throws NoSuchAlgorithmException
     *         If an invalid feedback size is specified.
     */
    /*package*/ ModeCFB(BlockCipher cipher, int feedbackSize) 
        throws NoSuchAlgorithmException
    {
        super(cipher);

        if( feedbackSize==0 || (feedbackSize%8)!=0 )
            throw new NoSuchAlgorithmException(
                "Feedback size is 0 or not a multiple of 8 bits.");

        feedbackSize = feedbackSize/8;

        if( (feedbackSize < 1) || (feedbackSize > CIPHER_BLOCK_SIZE) )
            throw new NoSuchAlgorithmException(
                "Feedback size <1 or >CIPHER_BLOCK_SIZE");

        this.keyStreamBuf = new byte[CIPHER_BLOCK_SIZE];
        this.shiftReg= new byte[CIPHER_BLOCK_SIZE];
        this.feedbackSize = feedbackSize;
    }


// Implementation
//............................................................................


    /**
     * Shift a byte into the shift register and 'sync' (encrypt shift reg) if
     * neccessary.
     */
    private void shiftInByte(byte b) {
        this.shiftReg[(this.shiftRegPtr++)%CIPHER_BLOCK_SIZE] = b;
        this.byteCount++;
        if(needCrank()) crank();
    }


    /**
     * Sync aka encrypt the shift register to yield the next block of
     * key stream bytes.
     */
    private void crank() {

        for(int i=0; i<CIPHER_BLOCK_SIZE; i++)
            this.keyStreamBuf[i] = 
                this.shiftReg[(this.shiftRegPtr++)%CIPHER_BLOCK_SIZE];

        // generate key stream bytes by encrypting shift register
        this.cipher.coreCrypt(this.keyStreamBuf, 0, this.keyStreamBuf, 0);
        this.keyStreamPtr = 0;
    }


    /**
     * Sync policy, can be overridden in subclasses.
     */
    protected boolean needCrank() {
        return (this.byteCount%this.feedbackSize == 0);
    }


    final int coreGetOutputSize(int inputLen) {
        // we effectively are a stream cipher and don't buffer anything
        return inputLen;
    }


    void coreInit(boolean decrypt, Key key, AlgorithmParameterSpec params,
                  SecureRandom random)
    throws InvalidKeyException, InvalidAlgorithmParameterException
    {
        // always use cipher in encrypt mode
        cipher.coreInit(key, false);

        this.decrypt = decrypt;
        
        // set IV
        iVec = extractIV(params);
        int iVecLen = iVec.length;
        if(iVecLen != CIPHER_BLOCK_SIZE)
            throw new InvalidAlgorithmParameterException(
                "Invalid IV specified, incorrect length.");

        this.byteCount = 0;
        System.arraycopy(iVec, 0, this.shiftReg, 0, iVecLen);
        crank();
    }


    int coreUpdate(byte[] input, int inputOffset, int inputLen,
                   byte[] output, int outputOffset)
    {
        int todo = inputLen;
        while(todo-- > 0) {
            byte kb = this.keyStreamBuf[this.keyStreamPtr++];
            byte ib = input[inputOffset++];
            byte ob = (byte)(ib ^ kb);
            shiftInByte( this.decrypt ? ib : ob );
            output[outputOffset++] = ob;
        }
        return inputLen;
    }


    final byte [] coreGetIV() 
    {
        return iVec;
    }


    final AlgorithmParameterSpec coreGetParamSpec()
    {
        if (iVec == null)
           return new IvParameterSpec(generateIV());
        else
            return new IvParameterSpec(iVec);
    }   

    final boolean needsPadding()
    {
        return false;
    }
}
