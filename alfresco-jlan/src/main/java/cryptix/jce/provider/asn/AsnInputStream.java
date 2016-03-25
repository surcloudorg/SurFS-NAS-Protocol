/* $Id: AsnInputStream.java,v 1.1 2000/08/25 01:11:43 gelderen Exp $
 *
 * Copyright (c) 2000 The Cryptix Foundation Limited. All rights reserved.
 */

package cryptix.jce.provider.asn;


import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.IOException;


/**
 * @version $Revision: 1.1 $
 * @author  Jeroen C. van Gelderen (gelderen@cryptix.org)
 */
public final class AsnInputStream {

// Instance variables
//............................................................................

    private final InputStream is;


//............................................................................

    /**
     * Convenience method that constructs an AsnInputStream on top of a
     * ByteArrayInputStream on top of the given buffer.
     */
    public AsnInputStream(byte[] data) {
        this.is = new ByteArrayInputStream(data);
    }


    /**
     * Constructs an AsnInputStream on top of the given InputStream.
     */
    public AsnInputStream(InputStream is) {
        this.is = is;
    }


//............................................................................

    public AsnObject read() throws IOException {
        int tagAsInt = this.is.read();
        if(tagAsInt == -1)
            throw new IOException("End of stream.");

        byte tag = (byte)tagAsInt;

        switch(tag) {
        case AsnObject.TAG_OBJECT_ID: return new AsnObjectId(this);
        case AsnObject.TAG_BITSTRING: return new AsnBitString(this);
        case AsnObject.TAG_INTEGER:   return new AsnInteger(this);
        case AsnObject.TAG_NULL:      return new AsnNull(this);
        case AsnObject.TAG_SEQUENCE:  return new AsnSequence(this);
//        case AsnObject.TAG_SET:       return new AsnSet(this);
        default:                      return new AsnUnknown(tag, this);
        }
    }


    /**
     * Delegates to the underlying InputStream.
     */
    public int available() throws IOException {
        return this.is.available();
    }


// AsnObject callbacks
//............................................................................

    /**
     * Reads a variable length length field from the underlying stream.
     */
    /*package*/ int readLength() throws IOException {

        int b = this.is.read();
        if( b == -1 ) 
            throw new IOException("Unexpected end of stream.");

        // short form
        if( b <= 127 ) 
            return b;

        // strip of high bit
        b = b&0x7F;

        // long form
        if( b > 4 )
            throw new IOException("Length too big.");

        int t, res = 0;
        while( b-- > 0 ) {
            if( (t=this.is.read()) == -1 )
                throw new IOException("Unexpected end of stream.");
            res = (res<<8) | t;
        }

        if( res < 0 )
            throw new IOException("Negative length.");

        return res;
    }


    /*package*/ byte readByte() throws IOException {
        return this.readBytes(1)[0];
    }


    /*package*/ byte[] readBytes(int todo) throws IOException {
        byte[] res = new byte[todo];
        int done, off = 0;
        while( todo > 0 ) {
            if( (done = this.is.read(res, off, todo)) == -1 )
                throw new IOException("EOF");
            todo -= done;
            off  += done;
        }
        return res;
    }


    /**
     * Returns a SubInputStream that allows up to 'len' bytes to be read.
     */
    /*package*/ AsnInputStream getSubStream(int len) {
        return new AsnInputStream( new SubInputStream(this.is, len) );
    }
}
