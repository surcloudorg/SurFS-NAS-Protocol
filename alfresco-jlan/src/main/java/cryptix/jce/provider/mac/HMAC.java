/* $Id: HMAC.java,v 1.6 2000/02/09 20:32:58 gelderen Exp $
 *
 * Copyright (C) 1995-2000 The Cryptix Foundation Limited.
 * All rights reserved.
 *
 * Use, modification, copying and distribution of this software is subject
 * the terms and conditions of the Cryptix General Licence. You should have
 * received a copy of the Cryptix General Licence along with this library;
 * if not, you can download a copy from http://www.cryptix.org/ .
 */
package cryptix.jce.provider.mac;


import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.MacSpi;


/**
 * Abstract class implementing the methods common to an HMAC. Subclasses
 * implement specifics (just the name of MessageDigest to use + size).
 *
 * @author Jeroen C. van Gelderen (gelderen@cryptix.org)
 * @version $Revision: 1.6 $
 */
class HMAC extends MacSpi
{
    /** Inner and outer padding constants */
    private static final byte
        IPAD = (byte)0x36,
        OPAD = (byte)0x5C;

    /** Underlying MessageDigest */
    private final MessageDigest md;

    /** Block size and length of underlying MessageDigest */
    private final int
        mdBlockSize,
        mdLen;

    /** Inner and outer IVs */
    private final byte[]
        iv_i,
        iv_o;


    /**
     * Construct an HMAC on top of a MessageDigest.
     */
    protected HMAC(String mdName, int mdBlockSize, int mdLen)
    {
        try
        {
            this.md          = MessageDigest.getInstance(mdName);
            this.mdBlockSize = mdBlockSize;
            this.mdLen       = mdLen;
            this.iv_i        = new byte[mdBlockSize];
            this.iv_o        = new byte[mdBlockSize];
        }
        catch( NoSuchAlgorithmException e )
        {
            throw new RuntimeException(
                "Underlying MesageDigest not found: "+mdName);
        }
    }


    /**
     * Private constructor used for cloning.
     */
    private HMAC(MessageDigest md, int mdBlockSize, int mdLen,
                 byte[] iv_i, byte[] iv_o)
    {
        this.md          = md;
        this.mdBlockSize = mdBlockSize;
        this.mdLen       = mdLen;
        this.iv_i        = new byte[mdBlockSize];
        this.iv_o        = new byte[mdBlockSize];
    }


    /**
     * Return the length of this Mac which equals the length of the underlying
     * MessageDigest.
     */
    protected final int engineGetMacLength()
    {
        return mdLen;
    }


    protected final void engineInit(Key key, AlgorithmParameterSpec params)
    throws InvalidKeyException, InvalidAlgorithmParameterException
    {
        if( params!=null )
            throw new InvalidAlgorithmParameterException(
                "HMAC doesn't take AlgorithmParameters.");

        if( !key.getFormat().equals("RAW") )
            throw new InvalidKeyException(
                "HMAC accepts keys in 'RAW' format only.");

        // extract the keybytes
        byte[] keyBytes = key.getEncoded();

        // hash down if key > blocksize
        if( keyBytes.length > this.mdBlockSize )
        {
            md.reset();
            keyBytes = md.digest( keyBytes );
        }

        // zero both iv's
        for( int i=0; i<iv_i.length; i++ )
            iv_i[i] = iv_o[i] = 0x00;

        // copy key into iv_i and xor with IPAD
        System.arraycopy( keyBytes, 0, iv_i, 0, keyBytes.length );
        for( int i=0; i<iv_i.length; i++ )
            iv_i[i] ^= IPAD;

        // copy key into iv_o and xor with OPAD
        System.arraycopy( keyBytes, 0, iv_o, 0, keyBytes.length );
        for( int i=0; i<iv_i.length; i++ )
            iv_o[i] ^= OPAD;

        // reset the engine to initial state
        engineReset();
    }


    protected final void engineUpdate(byte input)
    {
        md.update(input);
    }


    protected final void engineUpdate(byte[] input, int offset, int len)
    {
        md.update(input, offset, len);
    }


    protected final byte[] engineDoFinal()
    {
        // FIXME: don't create temporary objects here

        // obtain the inner hash and reset underlying MessageDigest
        byte[] tmp = md.digest();
        md.reset();

        // finish mac computation by prepending the inner hash with
        // the inner IV and hashing the result
        md.update(iv_o);
        md.update(tmp);
        byte[] output = md.digest();

        // reset engine and return mac
        engineReset();
        return output;
    }


    protected final void engineReset()
    {
        // reset digest and hash in the inner IV
        md.reset();
        md.update(iv_i);
    }


    /**
     * Clone this HMAC object. We support cloning if the underlying
     * MessageDigest does support cloning.
     */
    public Object clone()
    throws CloneNotSupportedException
    {
        MessageDigest md = (MessageDigest)this.md.clone();
        return new HMAC(
            md,
            this.mdBlockSize,
            this.mdLen,
            (byte[])this.iv_i.clone(),
            (byte[])this.iv_o.clone() );
    }
}