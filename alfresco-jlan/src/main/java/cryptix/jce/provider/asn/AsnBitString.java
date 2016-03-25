/* $Id: AsnBitString.java,v 1.1 2000/08/25 01:04:36 gelderen Exp $
 *
 * Copyright (c) 2000 The Cryptix Foundation Limited. All rights reserved.
 */

package cryptix.jce.provider.asn;


import java.io.IOException;
import java.math.BigInteger;


/**
 * Immutable object representing an ASN.1 BIT STRING. The bit length MUST be
 * a multiple of eight or an exception will be thrown.
 *
 * @version $Revision: 1.1 $
 * @author  Jeroen C. van Gelderen (gelderen@cryptix.org)
 */
public final class AsnBitString extends AsnObject
{
    private final byte[] val;


    /**
     * @throws AsnException
     *         If length is negative of length%8 != 0.
     */
    /*package*/ AsnBitString(AsnInputStream is)
        throws AsnException, IOException
    {
        super(AsnObject.TAG_BITSTRING);

        int len = is.readLength() - 1; // subtract 1 'unused' byte
        if(len < 0)
            throw new AsnException("Negative length.");

        // verify multiple of 8 bits
        byte unused = is.readByte();
        if(unused != 0)
            throw new AsnException("Length not a multiple of 8.");
        
        this.val = is.readBytes(len);
    }


    public AsnBitString(byte[] value) {
        super(AsnObject.TAG_BITSTRING);
        this.val = (byte[])(value.clone());
    }


    public String toString(String prefix) {
        return "BIT_STRING";
    }


    public byte[] toByteArray() {
        return (byte[])this.val.clone();
    }


    /** Write out payload. */
    protected void encodePayload(AsnOutputStream os) throws IOException {
        os.writeByte((byte)0x00); // no. of unsed bits (always 0)
        os.writeBytes(this.val);
    }


    protected int getEncodedLengthOfPayload(AsnOutputStream os) {
        return this.val.length+1; // plus 1 byte for 'unused bits field'
    }
}
