/* $Id: SHA1.java,v 1.6 2001/06/25 15:39:55 gelderen Exp $
 *
 * Copyright (C) 1995-2000 The Cryptix Foundation Limited.
 * All rights reserved.
 *
 * Use, modification, copying and distribution of this software is subject to
 * the terms and conditions of the Cryptix General Licence. You should have
 * received a copy of the Cryptix General Licence along with this library;
 * if not, you can download a copy from http://www.cryptix.org/ .
 */

package cryptix.jce.provider.md;


/**
 * SHA-1 message digest algorithm.
 *
 * @version $Revision: 1.6 $
 * @author  Jeroen C. van Gelderen
 */
public final class SHA1 extends SHA implements Cloneable {

// Constructors
//...........................................................................

    public SHA1() {
        super();
    }

    private SHA1(SHA1 src) {
        super(src);
    }

    public Object clone() {
        return new SHA1(this);
    }

// Concreteness
//...........................................................................

    protected void expand(int[] W) {
        // expand the block to 80 words, according to the SHA1 spec
        for( int i=16; i<80; i++ ){
            int j = W[i-16] ^ W[i-14] ^ W[i-8] ^ W[i-3];
            W[i] = (j << 1) | (j >>> -1);
        }
    }
}