/* $Id: RC4.java,v 1.6 2003/02/15 13:42:36 gelderen Exp $
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
 * This class implements the RC4<sup>TM</sup> stream cipher.
 * <p>
 * The source code (C version) from which this port was done, is the one
 * posted to the sci.crypt, alt.security, comp.security.misc, and
 * alt.privacy newsgroups on Wed, 14 Sep 1994 06:35:31 GMT by
 * "David Sterndark" &lt;sterndark@netcom.com&gt;
 * (Message-ID: &lt;sternCvKL4B.Hyy@netcom.com&gt;)
 * <p>
 * RC4 (TM) was designed by Ron Rivest, and was previously a trade secret of
 * RSA Data Security, Inc. The algorithm is now in the public domain. The name
 * "RC4" is a trademark of RSA Data Security, Inc.
 * <p>
 * References:
 * <ul>
 *   <li> Bruce Schneier,
 *        "Section 17.1 RC4,"
 *        <cite>Applied Cryptography, 2nd edition</cite>,
 *        John Wiley &amp; Sons, 1996.
 * </ul>
 *
 * @version $Revision: 1.6 $
 * @author  Raif S. Naffah
 * @author  David Hopwood
 * @since   Cryptix 2.2.2
 */
public final class RC4 extends CipherSpi
{

// RC4 constants and variables
//............................................................................

    /** Contents of the current set S-box. */
    private final int[] sBox = new int[256];

    /**
     * The two indices for the S-box computation referred to as i and j
     * in Schneier.
     */
    private int x, y;

    /**
     * The block size of this cipher. Being a stream cipher this value
     * is 1!
     */
    private static final int BLOCK_SIZE = 1;


// Constructor
//............................................................................

    /**
     * Constructs an RC4 cipher object, in the UNINITIALIZED state.
     * This calls the Cipher constructor with <i>implBuffering</i> false,
     * <i>implPadding</i> false and the provider set to "Cryptix".
     */
    public RC4()
    {
        super();
    }


    /**
     * Always throws a CloneNotSupportedException (cloning of ciphers is not
     * supported for security reasons).
     */
    public final Object clone() throws CloneNotSupportedException
    {
        throw new CloneNotSupportedException();
    }


// Implementation of JCE methods
//............................................................................

    protected final void engineSetMode(String mode)
    throws NoSuchAlgorithmException
    {
        throw new NoSuchAlgorithmException();
    }


    protected final void engineSetPadding(String padding)
    throws NoSuchPaddingException
    {
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


    protected int engineGetKeySize(Key key)
    throws InvalidKeyException
    {
        if( key==null )
            throw new IllegalArgumentException("Key missing");

        if( !key.getFormat().equalsIgnoreCase("RAW") )
            throw new InvalidKeyException("Wrong format: RAW bytes needed");

        byte[] userkey = key.getEncoded();
        if(userkey == null)
            throw new InvalidKeyException("RAW bytes missing");

        return (userkey.length * 8);
    }


    protected final int engineGetOutputSize(int inputLen)
    {
        return inputLen;
    }


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
        makeKey(key);
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
        int bufSize = output.length - outputOffset;
        if( bufSize < inputLen )
            throw new ShortBufferException();

        return privateEngineUpdate(input, inputOffset, inputLen,
                                   output, outputOffset);
    }


    protected final byte[]
    engineUpdate(byte[] input, int inputOffset, int inputLen)
    {
        byte[] tmp  = new byte[this.engineGetOutputSize(inputLen)];
        privateEngineUpdate(input, inputOffset, inputLen, tmp, 0);
        return tmp;
    }


    private final int
    privateEngineUpdate(byte[] input, int inputOffset, int inputLen,
                        byte[] output, int outputOffset)
    {
        rc4(input, inputOffset, inputLen, output, outputOffset);
        return inputLen;
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
        return engineUpdate(input, inputOffset, inputLen);
    }


// Own methods
//............................................................................

    /**
     * RC4 encryption/decryption.
     *
     * @param  in           the input data.
     * @param  inOffset     the offset into in specifying where the data starts.
     * @param  inLen        the length of the subarray.
     * @param  out          the output array.
     * @param  outOffset    the offset indicating where to start writing into
     *                      the out array.
     */
    private void rc4(byte[] in, int inOffset, int inLen,
                     byte[] out, int outOffset)
    {
        int xorIndex, t;

        for (int i = 0; i < inLen; i++)
        {
            x = (x + 1) & 0xFF;
            y = (sBox[x] + y) & 0xFF;

            t = sBox[x];
            sBox[x] = sBox[y];
            sBox[y] = t;

            xorIndex = (sBox[x] + sBox[y]) & 0xFF;
            out[outOffset++] = (byte)(in[inOffset++] ^ sBox[xorIndex]);
        }
    }

    /**
     * Expands a user-key to a working key schedule.
     * <p>
     * The key bytes are first extracted from the user-key and then
     * used to build the contents of this key schedule.
     * <p>
     * The method's only exceptions are when the user-key's contents
     * are null, or a byte array of zero length.
     *
     * @param  key  the user-key object to use.
     * @exception InvalidKeyException if one of the following occurs: <ul>
     *                <li> key.getEncoded() == null;
     *                <li> The encoded byte array form of the key is zero-length;
     *              </ul>
     */
    private void makeKey(Key key)
    throws InvalidKeyException
    {
        byte[] userkey = key.getEncoded();
        if (userkey == null)
            throw new InvalidKeyException("Null user key");

        int len = userkey.length;
        if (len == 0)
            throw new InvalidKeyException("Invalid user key length");

        x =  y = 0;
        for (int i = 0; i < 256; i++)
            sBox[i] = i;

        int i1 = 0, i2 = 0, t;

        for (int i = 0; i < 256; i++)
        {
            i2 = ((userkey[i1] & 0xFF) + sBox[i] + i2) & 0xFF;

            t = sBox[i];
            sBox[i] = sBox[i2];
            sBox[i2] = t;

            i1 = (i1 + 1) % len;
        }
    }
}
