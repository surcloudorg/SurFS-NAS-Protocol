/* $Id: AsnInteger.java,v 1.1 2000/08/25 01:04:36 gelderen Exp $
 *
 * Copyright (c) 2000 The Cryptix Foundation Limited. All rights reserved.
 */

package cryptix.jce.provider.asn;


import java.io.IOException;
import java.math.BigInteger;


/**
 * Immutable object representing an ASN.1 INTEGER.
 *
 * @version $Revision: 1.1 $
 * @author  Jeroen C. van Gelderen (gelderen@cryptix.org)
 */
public final class AsnInteger extends AsnObject
{

//............................................................................

    private final BigInteger val;


//............................................................................

    /*package*/ AsnInteger(AsnInputStream is) throws IOException {
        super(AsnObject.TAG_INTEGER);

        int len = is.readLength();
        byte[] data = is.readBytes(len);
        this.val = new BigInteger(data);
    }


    public AsnInteger(BigInteger value) {
        super(AsnObject.TAG_INTEGER);

        this.val = value;
    }


    public String toString(String prefix) {
        return prefix + "BIGINTEGER (" + this.val.toString() + ")";
    }


//............................................................................

    public BigInteger toBigInteger() {
        return this.val;
    }


//............................................................................

    /** Write out payload. */
    protected void encodePayload(AsnOutputStream os) throws IOException {
        os.writeBytes( this.val.toByteArray() );
    }


    /** 
     * Returns no. of bytes encodePayload will write out when called on
     * the given AsnOutputStream.
     */
    protected int getEncodedLengthOfPayload(AsnOutputStream os) {
        return this.val.toByteArray().length;
    }
}
