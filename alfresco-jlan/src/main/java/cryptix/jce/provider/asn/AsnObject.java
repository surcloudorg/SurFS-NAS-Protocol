/* $Id: AsnObject.java,v 1.2 2000/08/25 01:04:36 gelderen Exp $
 *
 * Copyright (c) The Cryptix Foundation Limited. All rights reserved.
 */

package cryptix.jce.provider.asn;


import java.io.IOException;


/**
 * Base class of all ASN objects. Provides type safety and common functionality.
 * AsnObjects can encode themselves to AsnOutputStreams. All AsnObjects are
 * immutable.
 *
 * @version $Revision: 1.2 $
 * @author  Jeroen C. van Gelderen (gelderen@cryptix.org)
 */
public abstract class AsnObject {

    /*package*/ static final byte
        TAG_MASK             = 0x1F,
        TAG_INTEGER          = 0x02,
        TAG_BITSTRING        = 0x03,
        TAG_NULL             = 0x05,
        TAG_OBJECT_ID        = 0x06,
        TAG_SEQUENCE         = 0x10 | 0x20,
        TAG_SET              = 0x11 | 0x20,
        TAG_PRINTABLE_STRING = 0x13,
        TAG_UTCTime          = 0x17;


    private final byte tag;


// Ctors and java.lang.Object methods
//............................................................................

    protected AsnObject(byte tag) {
        this.tag = tag;
    }


    public final boolean equals(Object o) {
        throw new RuntimeException("AsnObject.equals(...) not implemented.");
    }


    public final int hashCode() {
        throw new RuntimeException("AsnObject.hashCode(...) not implemented.");
    }


    /**
     * Returns a human readable String representation by calling toString("").
     */
    public final String toString() {
        return this.toString("");
    }


// AsnOutputStream callbacks
//............................................................................

    /**
     * Write the contents of this AsnObject to the given AsnOutputStream.
     *
     * @throws IOException
     */
    /*package*/ final void encode(AsnOutputStream os) throws IOException {
        os.writeType( this.tag );
        os.writeLength( this.getEncodedLengthOfPayload(os) );
        this.encodePayload(os);
    }


    /**
     * Obtain the length of the encoding of this AsnObject. Nothing is written
     * to the AsnOutputStream instance but it's getLengthOfLength(...) method
     * is called.
     */
    /*package*/ final int getEncodedLength(AsnOutputStream os) {
        int len = this.getEncodedLengthOfPayload(os);
        len += os.getLengthOfLength(len);
        len += 1; // tag
        return len;
    }


    /*package*/ final byte getTag() {
        return this.tag;
    }


// Abstract AsnObject methods
//............................................................................

    /**
     * Write out this object's payload. Called upon by AsnObject.encode(...)
     * after it has written the type tag and length field.
     *
     * @throws IOException
     */
    protected abstract void encodePayload(AsnOutputStream os) 
    throws IOException;


    /** 
     * Returns no. of bytes encodePayload will write out when called on
     * the given AsnOutputStream.
     *
     * This is used by constructed types to determine the aggregrated
     * length of their components.
     *
     * The stream argument is included for future proofing. Different
     * streams may support different encodings for the length field.
     * This obviously doesn't apply to DER :-)
     */
    protected abstract int getEncodedLengthOfPayload(AsnOutputStream os);


    /**
     * Returns a human readable, indented (with 'prefix') String representation
     * of the AsnObject. The 'prefix' argument is neccessary to allow multi-line
     * output to be properly indented.
     */
    public abstract String toString(String prefix);
}
