/* $Id: SKIPJACK.java,v 1.5 2000/02/10 01:31:42 gelderen Exp $
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


import java.security.InvalidKeyException;
import java.security.Key;


/**
 * SKIPJACK
 *
 * @version $Revision: 1.5 $
 * @author  Jeroen C. van Gelderen (gelderen@cryptix.org)
 */
public final class SKIPJACK
extends BlockCipher
{
    
// Constants and static variables
//............................................................................

    private static final int
        BLOCK_SIZE = 8,
        KEY_LENGTH = 10;

    private static final int F[] =
    {
        0xA3, 0xD7, 0x09, 0x83, 0xF8, 0x48, 0xF6, 0xF4,
        0xB3, 0x21, 0x15, 0x78, 0x99, 0xB1, 0xAF, 0xF9,
        0xE7, 0x2D, 0x4D, 0x8A, 0xCE, 0x4C, 0xCA, 0x2E,
        0x52, 0x95, 0xD9, 0x1E, 0x4E, 0x38, 0x44, 0x28,
        0x0A, 0xDF, 0x02, 0xA0, 0x17, 0xF1, 0x60, 0x68,
        0x12, 0xB7, 0x7A, 0xC3, 0xE9, 0xFA, 0x3D, 0x53,
        0x96, 0x84, 0x6B, 0xBA, 0xF2, 0x63, 0x9A, 0x19,
        0x7C, 0xAE, 0xE5, 0xF5, 0xF7, 0x16, 0x6A, 0xA2,
        0x39, 0xB6, 0x7B, 0x0F, 0xC1, 0x93, 0x81, 0x1B,
        0xEE, 0xB4, 0x1A, 0xEA, 0xD0, 0x91, 0x2F, 0xB8,
        0x55, 0xB9, 0xDA, 0x85, 0x3F, 0x41, 0xBF, 0xE0,
        0x5A, 0x58, 0x80, 0x5F, 0x66, 0x0B, 0xD8, 0x90,
        0x35, 0xD5, 0xC0, 0xA7, 0x33, 0x06, 0x65, 0x69,
        0x45, 0x00, 0x94, 0x56, 0x6D, 0x98, 0x9B, 0x76,
        0x97, 0xFC, 0xB2, 0xC2, 0xB0, 0xFE, 0xDB, 0x20,
        0xE1, 0xEB, 0xD6, 0xE4, 0xDD, 0x47, 0x4A, 0x1D,
        0x42, 0xED, 0x9E, 0x6E, 0x49, 0x3C, 0xCD, 0x43,
        0x27, 0xD2, 0x07, 0xD4, 0xDE, 0xC7, 0x67, 0x18,
        0x89, 0xCB, 0x30, 0x1F, 0x8D, 0xC6, 0x8F, 0xAA,
        0xC8, 0x74, 0xDC, 0xC9, 0x5D, 0x5C, 0x31, 0xA4,
        0x70, 0x88, 0x61, 0x2C, 0x9F, 0x0D, 0x2B, 0x87,
        0x50, 0x82, 0x54, 0x64, 0x26, 0x7D, 0x03, 0x40,
        0x34, 0x4B, 0x1C, 0x73, 0xD1, 0xC4, 0xFD, 0x3B,
        0xCC, 0xFB, 0x7F, 0xAB, 0xE6, 0x3E, 0x5B, 0xA5,
        0xAD, 0x04, 0x23, 0x9C, 0x14, 0x51, 0x22, 0xF0,
        0x29, 0x79, 0x71, 0x7E, 0xFF, 0x8C, 0x0E, 0xE2,
        0x0C, 0xEF, 0xBC, 0x72, 0x75, 0x6F, 0x37, 0xA1,
        0xEC, 0xD3, 0x8E, 0x62, 0x8B, 0x86, 0x10, 0xE8,
        0x08, 0x77, 0x11, 0xBE, 0x92, 0x4F, 0x24, 0xC5,
        0x32, 0x36, 0x9D, 0xCF, 0xF3, 0xA6, 0xBB, 0xAC,
        0x5E, 0x6C, 0xA9, 0x13, 0x57, 0x25, 0xB5, 0xE3,
        0xBD, 0xA8, 0x3A, 0x01, 0x05, 0x59, 0x2A, 0x46
    };


// Instance variables
//............................................................................

    /**
     * Twelf-byte array of subkeys. It's 12 to save on modulus operations. 
     * The last 2 bytes must be equal to the first two bytes.
     */
    private final int[] K = new int[12];
    
    /** We are in decrypt mode */
    private boolean decrypt;


// Constructor
//............................................................................

    public SKIPJACK() 
    {
        super(BLOCK_SIZE);
    }


// Implementation of abstract methods
//............................................................................
 
    protected void coreInit(Key key, boolean decrypt)
    throws InvalidKeyException 
    {
        byte[] userkey = key.getEncoded();
        if( userkey == null )
            throw new InvalidKeyException("Null user key");

        if( userkey.length != KEY_LENGTH )
            throw new InvalidKeyException("Invalid user key length");
            
        for( int i=0; i<K.length; i++)
            K[i] = userkey[i%KEY_LENGTH]&0xFF;
            
        this.decrypt = decrypt;
    }

    
    protected void coreCrypt(byte[] in, int inOffset, byte[] out, int outOffset) 
    {
        if(decrypt)
            blockDecrypt(in, inOffset, out, outOffset);
        else
            blockEncrypt(in, inOffset, out, outOffset);
    }


// Private parts
//............................................................................

    /**
     * Encrypt a single, 8-byte block. Input and output may overlap.
     */
    private final void blockEncrypt(byte[] in, int inOffset, byte[] out, int outOffset)
    {
        int w1 = (in[inOffset++]&0xFF) << 8 | (in[inOffset++]&0xFF);
        int w2 = (in[inOffset++]&0xFF) << 8 | (in[inOffset++]&0xFF);
        int w3 = (in[inOffset++]&0xFF) << 8 | (in[inOffset++]&0xFF);
        int w4 = (in[inOffset++]&0xFF) << 8 | (in[inOffset  ]&0xFF);

        // A
        w1  = G(w1, 0); w4 ^= w1 ^ 1;
        w4  = G(w4, 4); w3 ^= w4 ^ 2;
        w3  = G(w3, 8); w2 ^= w3 ^ 3;
        w2  = G(w2, 2); w1 ^= w2 ^ 4;
        w1  = G(w1, 6); w4 ^= w1 ^ 5;
        w4  = G(w4, 0); w3 ^= w4 ^ 6;
        w3  = G(w3, 4); w2 ^= w3 ^ 7;
        w2  = G(w2, 8); w1 ^= w2 ^ 8;
        // B
        w2 ^= w1 ^  9; w1  = G(w1, 2);
        w1 ^= w4 ^ 10; w4  = G(w4, 6);
        w4 ^= w3 ^ 11; w3  = G(w3, 0);
        w3 ^= w2 ^ 12; w2  = G(w2, 4);
        w2 ^= w1 ^ 13; w1  = G(w1, 8);
        w1 ^= w4 ^ 14; w4  = G(w4, 2);
        w4 ^= w3 ^ 15; w3  = G(w3, 6);
        w3 ^= w2 ^ 16; w2  = G(w2, 0);
        // A
        w1  = G(w1, 4); w4 ^= w1 ^ 17;
        w4  = G(w4, 8); w3 ^= w4 ^ 18;
        w3  = G(w3, 2); w2 ^= w3 ^ 19;
        w2  = G(w2, 6); w1 ^= w2 ^ 20;
        w1  = G(w1, 0); w4 ^= w1 ^ 21;
        w4  = G(w4, 4); w3 ^= w4 ^ 22;
        w3  = G(w3, 8); w2 ^= w3 ^ 23;
        w2  = G(w2, 2); w1 ^= w2 ^ 24;
        // B
        w2 ^= w1 ^ 25; w1  = G(w1, 6);
        w1 ^= w4 ^ 26; w4  = G(w4, 0);
        w4 ^= w3 ^ 27; w3  = G(w3, 4);
        w3 ^= w2 ^ 28; w2  = G(w2, 8);
        w2 ^= w1 ^ 29; w1  = G(w1, 2);
        w1 ^= w4 ^ 30; w4  = G(w4, 6);
        w4 ^= w3 ^ 31; w3  = G(w3, 0);
        w3 ^= w2 ^ 32; w2  = G(w2, 4);

        out[outOffset++] = (byte)(w1 >>> 8);
        out[outOffset++] = (byte)(w1      );
        out[outOffset++] = (byte)(w2 >>> 8);
        out[outOffset++] = (byte)(w2      );
        out[outOffset++] = (byte)(w3 >>> 8);
        out[outOffset++] = (byte)(w3      );
        out[outOffset++] = (byte)(w4 >>> 8);
        out[outOffset  ] = (byte)(w4      );
    }

    
    /** G-function used by blockEncrypt */
    private final int G(int in, int counter)
    {
        int low  = (in & 0x000000FF);
        int high = (in             ) >>> 8;

        high ^= F[low  ^ K[counter  ]];
        low  ^= F[high ^ K[counter+1]];
        high ^= F[low  ^ K[counter+2]];
        low  ^= F[high ^ K[counter+3]];

        return (high << 8) | low;
    }


    /**
     * Decrypt a single block. Input and output may overlap.
     */
    private final void blockDecrypt(byte[] in, int inOffset, byte[] out, int outOffset)
    {
        int w1 = (in[inOffset++]&0xFF) << 8 | (in[inOffset++]&0xFF);
        int w2 = (in[inOffset++]&0xFF) << 8 | (in[inOffset++]&0xFF);
        int w3 = (in[inOffset++]&0xFF) << 8 | (in[inOffset++]&0xFF);
        int w4 = (in[inOffset++]&0xFF) << 8 | (in[inOffset  ]&0xFF);

        // B-1
        w2  = GINV(w2,  7); w3 ^= w2 ^ 32;
        w3  = GINV(w3,  3); w4 ^= w3 ^ 31;
        w4  = GINV(w4,  9); w1 ^= w4 ^ 30;
        w1  = GINV(w1,  5); w2 ^= w1 ^ 29;
        w2  = GINV(w2, 11); w3 ^= w2 ^ 28;
        w3  = GINV(w3,  7); w4 ^= w3 ^ 27;
        w4  = GINV(w4,  3); w1 ^= w4 ^ 26;
        w1  = GINV(w1,  9); w2 ^= w1 ^ 25;
        // A-1
        w1 ^= w2 ^ 24; w2 = GINV(w2,  5);
        w2 ^= w3 ^ 23; w3 = GINV(w3, 11);
        w3 ^= w4 ^ 22; w4 = GINV(w4,  7);
        w4 ^= w1 ^ 21; w1 = GINV(w1,  3);
        w1 ^= w2 ^ 20; w2 = GINV(w2,  9);
        w2 ^= w3 ^ 19; w3 = GINV(w3,  5);
        w3 ^= w4 ^ 18; w4 = GINV(w4, 11);
        w4 ^= w1 ^ 17; w1 = GINV(w1,  7);
        // B-1
        w2  = GINV(w2,  3); w3 ^= w2 ^ 16;
        w3  = GINV(w3,  9); w4 ^= w3 ^ 15;
        w4  = GINV(w4,  5); w1 ^= w4 ^ 14;
        w1  = GINV(w1, 11); w2 ^= w1 ^ 13;
        w2  = GINV(w2,  7); w3 ^= w2 ^ 12;
        w3  = GINV(w3,  3); w4 ^= w3 ^ 11;
        w4  = GINV(w4,  9); w1 ^= w4 ^ 10;
        w1  = GINV(w1,  5); w2 ^= w1 ^  9;
        // A-1
        w1 ^= w2 ^ 8; w2 = GINV(w2, 11);
        w2 ^= w3 ^ 7; w3 = GINV(w3,  7);
        w3 ^= w4 ^ 6; w4 = GINV(w4,  3);
        w4 ^= w1 ^ 5; w1 = GINV(w1,  9);
        w1 ^= w2 ^ 4; w2 = GINV(w2,  5);
        w2 ^= w3 ^ 3; w3 = GINV(w3, 11);
        w3 ^= w4 ^ 2; w4 = GINV(w4,  7);
        w4 ^= w1 ^ 1; w1 = GINV(w1,  3);

        out[outOffset++] = (byte)(w1 >>> 8);
        out[outOffset++] = (byte)(w1      );
        out[outOffset++] = (byte)(w2 >>> 8);
        out[outOffset++] = (byte)(w2      );
        out[outOffset++] = (byte)(w3 >>> 8);
        out[outOffset++] = (byte)(w3      );
        out[outOffset++] = (byte)(w4 >>> 8);
        out[outOffset  ] = (byte)(w4      );

    }


    /** G-inverse function used by blockDecrypt */
    private final int GINV(int in, int counter)
    {
        int low  = (in & 0x000000FF);
        int high = (in             ) >>> 8;

        low  ^= F[high ^ K[counter  ]];
        high ^= F[low  ^ K[counter-1]];
        low  ^= F[high ^ K[counter-2]];
        high ^= F[low  ^ K[counter-3]];

        return (high << 8) | low;
    }
}