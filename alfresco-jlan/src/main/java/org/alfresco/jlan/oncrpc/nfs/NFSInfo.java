package org.alfresco.jlan.oncrpc.nfs;

import static org.alfresco.jlan.oncrpc.nfs.NFSServer.MaxRequestSize;

public abstract class NFSInfo {

    private static NFSInfo nfsinfo = null;

    public static synchronized void setNFSInfo(NFSInfo info) {
        nfsinfo = info;
    }

    public static int getMaxSize() {
        if (nfsinfo == null) {
            return 65535;
        } else {
            int size = nfsinfo.getBlockSize();
            
            size = 1024 * (size / 1024) - 1;
            if (size < 65535) {
                size = 65535;
            }
            if (size > MaxRequestSize) {
                size = MaxRequestSize;
            }
            return size;
        }
    }

    public abstract int getBlockSize();
}
