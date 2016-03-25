/* $Id: DESKeyGenerator.java,v 1.7 2000/02/19 02:57:54 gelderen Exp $
 *
 * Copyright (C) 1995-1999 The Cryptix Foundation Limited.
 * All rights reserved.
 *
 * Use, modification, copying and distribution of this software is subject
 * the terms and conditions of the Cryptix General Licence. You should have
 * received a copy of the Cryptix General Licence along with this library;
 * if not, you can download a copy from http://www.cryptix.org/ .
 */
package cryptix.jce.provider.key;


/**
 * A key generator for DES.
 *
 * @version $Revision: 1.7 $
 * @author  Jeroen C. van Gelderen (gelderen@cryptix.org)
 */
public class DESKeyGenerator extends RawKeyGenerator
{
    public DESKeyGenerator()
    {
        super("DES", 56);
    }


    /** Test for weak keys */
    protected boolean isWeak( byte[] key )
    {
        return isWeak( key, 0 );
    }


    /**
     * Returns true iff the bytes at key[offset..offset+7] represent a weak
     * or semi-weak single DES key. It can be called either before or after
     * setting parity bits.
     * <p>
     * (This checks for the 16 weak and semi-weak keys as given by Schneier,
     * <cite>Applied Cryptography 2nd ed.</cite>, tables 12.11 and 12.12. It
     * does not check for the possibly-weak keys in table 12.13.)
     */
    private boolean isWeak(byte[] key, int offset)
    {
        int a = (key[offset  ] & 0xFE) << 8 | (key[offset+1] & 0xFE);
        int b = (key[offset+2] & 0xFE) << 8 | (key[offset+3] & 0xFE);
        int c = (key[offset+4] & 0xFE) << 8 | (key[offset+5] & 0xFE);
        int d = (key[offset+6] & 0xFE) << 8 | (key[offset+7] & 0xFE);

        return (a == 0x0000 || a == 0xFEFE) &&
               (b == 0x0000 || b == 0xFEFE) &&
               (c == 0x0000 || c == 0xFEFE) &&
               (d == 0x0000 || d == 0xFEFE);
    }


    protected boolean isValidSize( int size )
    {
        return size==56 ? true : false;
    }


    protected int strengthToBits(int strength) {
        if(strength!=56)
            throw new RuntimeException("Invalid strength value");

        return 64;
    }


    /**
     * Fix the parity
     */
    protected byte[] fixUp( byte[] key ) {
        int b;
        for (int i = 0; i < key.length; i++) {
            b = key[i];
            key[i] = (byte)((b & 0xFE) |
                              (((b >> 1) ^
                                (b >> 2) ^
                                (b >> 3) ^
                                (b >> 4) ^
                                (b >> 5) ^
                                (b >> 6) ^
                                (b >> 7)) & 0x01));
        }
        return key;
    }

}
