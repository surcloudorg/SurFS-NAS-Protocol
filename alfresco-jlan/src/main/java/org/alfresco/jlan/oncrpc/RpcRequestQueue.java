/*
 * Copyright (C) 2006-2008 Alfresco Software Limited.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.

 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.

 * As a special exception to the terms and conditions of version 2.0 of 
 * the GPL, you may redistribute this Program in connection with Free/Libre 
 * and Open Source Software ("FLOSS") applications as described in Alfresco's 
 * FLOSS exception.  You should have recieved a copy of the text describing 
 * the FLOSS exception, and it is also available here: 
 * http://www.alfresco.com/legal/licensing"
 */
package org.alfresco.jlan.oncrpc;

import java.util.concurrent.LinkedBlockingQueue;
import org.alfresco.jlan.oncrpc.nfs.NFS;

/**
 * RPC Request Queue Class
 *
 * <p>
 * Provides a request queue for a thread pool of worker threads.
 *
 * @author gkspencer
 */
public class RpcRequestQueue {

    private final LinkedBlockingQueue<RpcPacket> m_queue = new LinkedBlockingQueue<>();
    private final LinkedBlockingQueue<RpcPacket> m_queue_head = new LinkedBlockingQueue<>();

    /**
     * Add a request to the queue
     *
     * @param req RpcPacket
     */
    public final void addRequest(RpcPacket req) {
        int pid = req.getProcedureId();
        if (pid == NFS.ProcWrite || pid == NFS.ProcRead || pid == NFS.ProcCommit) {
            m_queue.add(req);
        } else {
            m_queue_head.add(req);
        }
    }

    /**
     * Remove a request from the head of the queue
     *
     * @return RpcPacket
     * @exception InterruptedException
     */
    public final RpcPacket removeRequestHead() throws InterruptedException {
        return m_queue_head.take();
    }

    /**
     * Remove a request from the head of the queue
     *
     * @return RpcPacket
     * @exception InterruptedException
     */
    public final RpcPacket removeRequest() throws InterruptedException {
        return m_queue.take();
    }
}
