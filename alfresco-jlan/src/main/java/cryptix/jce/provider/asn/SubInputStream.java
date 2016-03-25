/* $Id: SubInputStream.java,v 1.2 2000/08/17 01:56:23 gelderen Exp $
 *
 * Copyright (c) 2000 The Cryptix Development Team. All rights reserved.
 */

package cryptix.jce.provider.asn;


import java.io.InputStream;
import java.io.IOException;


/**
 * An InputStream that will return a limited (user-specified) number of bytes.
 *
 * @version $Revision: 1.2 $
 * @author  Jeroen C. van Gelderen (gelderen@cryptix.org)
 */
public final class SubInputStream extends InputStream {

// Instance variables
//............................................................................

    private int len;


    private final InputStream is;


// Ctor
//............................................................................

    /**
     * Construct a SubInputStream (layered on top of a normal InputStream) that
     * will return up to 'len' bytes before EOFing.
     */
    public SubInputStream(InputStream is, int len) {

        if( len < 0 ) throw new IllegalArgumentException("len: < 0");

        this.is = is;
        this.len = len;
    }


// InputStream methods
//............................................................................

    public int available() throws IOException {
        return (this.len > 0) ? this.is.available() : 0;
    }

    public int read() throws IOException {
        return (this.len-- <= 0) ? -1 : this.is.read();
    }
}
