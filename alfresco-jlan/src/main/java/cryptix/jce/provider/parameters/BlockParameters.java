/* $Id: BlockParameters.java,v 1.5 2000/07/31 13:21:34 pw Exp $
 *
 * Copyright (C) 1995-2000 The Cryptix Foundation Limited.
 * All rights reserved.
 *
 * Use, modification, copying and distribution of this software is subject
 * the terms and conditions of the Cryptix General Licence. You should have
 * received a copy of the Cryptix General Licence along with this library;
 * if not, you can download a copy from http://www.cryptix.org/ .
 */
package cryptix.jce.provider.parameters;

import java.security.AlgorithmParametersSpi;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.AlgorithmParameterSpec;
import java.io.IOException;
import javax.crypto.spec.IvParameterSpec;

/**
 * <B>Please read the comments in the source.</B>
 *
 * @author Paul Waserbrot (pw@cryptix.org)
 * @version $Revision: 1.5 $
 */

public final class BlockParameters
  extends AlgorithmParametersSpi {

  private String algorithm;
  private byte [] iv = null;
        
  public BlockParameters () {
    super();
  }

  protected final void engineInit(AlgorithmParameterSpec paramSpec)
    throws InvalidParameterSpecException {

    // Since we uses Iv:s check if an instance of IvParameterSpec
    if (paramSpec instanceof IvParameterSpec) {
      iv = ((IvParameterSpec)paramSpec).getIV();
    } else
      throw new InvalidParameterSpecException("Wrong ParameterSpec");
          
    return;
  }
  
  protected final void engineInit(byte[] params)
    throws IOException {
    /* COMMENT FROM SUN:s JCE API. WILL BE REMOVED!!!
     * Imports the specified parameters and decodes them according to 
     * the primary decoding format for parameters. The primary decoding 
     * format for parameters is ASN.1, if an ASN.1 specification for this 
     * type of parameters exists.
     * Parameters:
     *      params - the encoded parameters.
     * Throws:
     *      IOException - on decoding errors
     */

    /* FIXME: Use some en/decoding in the future. For now, use just a
     * byte-array. (pw)
     */
    this.iv = params;

    return;
  }
  
  protected final void engineInit(byte[] params, String format)
    throws IOException {
    /* COMMENT FROM SUN:s JCE API. WILL BE REMOVED!!!
     * Imports the parameters from params and decodes them according to 
     * the specified decoding format. If format is null, the primary 
     * decoding format for parameters is used. The primary decoding format 
     * is ASN.1, if an ASN.1 specification for these parameters exists.
     * Parameters:
     *      params - the encoded parameters.
     *      format - the name of the decoding format.
     * Throws:
     *      IOException - on decoding errors
     */

    /* FIXME: shall we implement this one? That is, will we use 
     * more encodings than one???
     */
    throw new RuntimeException("Method init(byte[] params, String format) "+
                               "not implemented");
  }
  
  protected final AlgorithmParameterSpec engineGetParameterSpec(Class paramSpec)
    throws InvalidParameterSpecException {
    
    // Check and see if Class paramSpec is the same as IvParameterSpec
    try {
      if (!Class.forName("javax.crypto.spec.IvParameterSpec").isAssignableFrom(paramSpec))
        throw new InvalidParameterSpecException("Class is not "+
                                                "IvParameterSpec assignable");
    } catch (ClassNotFoundException e) {
      throw new InvalidParameterSpecException("Class is not IvParameterSpec");
    }
    return new IvParameterSpec(iv);
  }
  
  protected final byte[] engineGetEncoded()
    throws IOException {
    /* COMMENT FROM SUN:s JCE API. WILL BE REMOVED!!!
     * Returns the parameters in their primary encoding format. The 
     * primary encoding format for parameters is ASN.1, if an ASN.1 
     * specification for this type of parameters exists.
     * Returns:
     *     the parameters encoded using the specified encoding scheme.
     * Throws:
     *     IOException - on encoding errors.
     */

    /* FIXME: Use some en/decoding in the future. For now, use just a
     * byte-array. (pw)
     */
    return iv;
  }
  
  protected final byte[] engineGetEncoded(String format)
    throws IOException {
    /* COMMENT FROM SUN:s JCE API. WILL BE REMOVED!!!
     * Returns the parameters encoded in the specified format. If 
     * format is null, the primary encoding format for parameters is 
     * used. The primary encoding format is ASN.1, if an ASN.1 
     * specification for these parameters exists.
     * Parameters:
     *     format - the name of the encoding format.
     * Returns:
     *     the parameters encoded using the specified encoding scheme.
     * Throws:
     *     IOException - on encoding errors.
     */

    /* FIXME: shall we implement this one? That is, will we use 
     * more encodings than one???
     */
    throw new RuntimeException("Method getEncoded(String format) "+
                               "not implemented");
  }

  protected final String engineToString() {
    return "iv:["+hexDump(iv)+"]";
  }

  /*
   * Static method for converting to hexadecimal strings.
   *
   * author  David Hopwood and  Raif Naffah
   * minor changes Paul Waserbrot (pw@cryptix.org)
   * since   Cryptix 2.2.0a, 2.2.2
   */
  private final String hexDump (byte [] b) {
    char[] hex = {'0','1','2','3','4','5','6','7','8','9',
                  'A','B','C','D','E','F'};

    char[] buf = new char[b.length * 2];
    int i, j, k;

    i = j = 0;    
    for (; i < b.length; i++) {
      k = b[i];
      buf[j++] = hex[(k >>> 4) & 0x0F];
      buf[j++] = hex[ k & 0x0F];
    }
    return new String(buf);
  }
}
