/*
 * Copyright (C) 2016 SurCloud.
 *
 * This file is part of JLAN for SurFS
 *
 * JLAN for SurFS is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * JLAN for SurFS is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with JLAN for SurFS. If not, see <http://www.gnu.org/licenses/>.
 */

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
