/* $Id: IDEAKeyGenerator.java,v 1.6 2000/02/19 02:57:54 gelderen Exp $
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
 * A key generator for IDEA.
 * <p>
 * IDEA keys have a fixed length of 128 bits.
 * <p>
 *
 * @version $Revision: 1.6 $
 * @author  David Hopwood
 * @author  Jeroen C. van Gelderen (gelderen@cryptix.org)
 * @since   Cryptix 2.2.0a, 2.2.2
 */
public class IDEAKeyGenerator extends RawKeyGenerator
{
    public IDEAKeyGenerator()
    {
        super("IDEA", 128);
    }


    /**
     * Returns true iff the byte array <i>key</i> represents a
     * weak IDEA key.
     * <p>
     * IDEA has two non-overlapping classes of weak keys (bit numbering
     * is from left to right, e.g. 0 denotes the most significant bit of
     * the first byte):
     * <ul>
     *   <li> Keys with zeros in bit positions 0-25, 29-71, and 75-110
     *        (inclusive) and any value in bits 26-28, 72-74, and 111-127.
     *        There are 2^23 weak keys in this class.
     *        <p>
     *   <li> Keys with zeros in bit positions 0-25, 41-71, 84-98, and
     *        123-127 and any value in bit positions 26-40, 72-83, and
     *        99-122.  There are 2^51 weak keys in this class.
     * </ul>
     *
     * @param key   the byte array containing user key data.
     */
    protected boolean isWeak( byte[] key )
    {
        // keys with any 1 in bits 0-25, 41-71, or 84-98 are OK.
        if(  key[0]          != 0
         ||  key[1]          != 0
         ||  key[2]          != 0
         || (key[3] & 0xC0)  != 0
         || (key[5] & 0x7F)  != 0
         ||  key[6]          != 0
         ||  key[7]          != 0
         ||  key[8]          != 0
         || (key[10] & 0x0F) != 0
         ||  key[11]         != 0
         || (key[12] & 0xE0) != 0)
            return false;

        // keys additionally with all 0s in bits 29-71 and 75-110 are weak.
        if( (key[3] & 0x07)  == 0
         &&  key[4]          == 0
         &&  key[5]          == 0
         /* 6, 7, 8 done */
         && (key[9] & 0x1F)  == 0
         &&  key[10]         == 0
         /* 11 done */
         &&  key[12]         == 0
         && (key[13] & 0xFE) == 0)
            return true;

        // keys additionally with all 0s in bits 123-127 are weak.
        if ((key[15] & 0x1F) == 0)
            return true;

        // otherwise OK.
        return false;
    }


    protected boolean isValidSize( int size )
    {
        return size==128 ? true : false;
    }
}
