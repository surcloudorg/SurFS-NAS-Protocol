/* $Id: TripleDESKeyGenerator.java,v 1.1 2000/07/31 00:55:45 gelderen Exp $
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
 * A key generator for TripleDES.
 *
 * @version $Revision: 1.1 $
 * @author  Jeroen C. van Gelderen (gelderen@cryptix.org)
 */
public class TripleDESKeyGenerator extends RawKeyGenerator {

    private static final int
        STRENGTH = 168,
        BIT_LEN  = 192;


    public TripleDESKeyGenerator() {
        super("TripleDES", STRENGTH);
    }


    /** Test for weak keys */
    protected boolean isWeak( byte[] key ) {
        return false;
    }


    protected boolean isValidSize( int size ) {
        return (size==STRENGTH) ? true : false;
    }


    protected int strengthToBits(int strength) {

        if(strength!=STRENGTH)
            throw new RuntimeException(
                "Invalid strength value (" + strength + ")" );

        return BIT_LEN;
    }


    /**
     * Fix the parity.
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
