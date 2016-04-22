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
/***************************************************************************
 *
 * Copyright (C) 2016 SurCloud.
 *
 * This file was modified by SurCloud and is part of JLAN for SurFS, you
 * can redistribute and/or modify it under the same license terms as above.
 *
 * JLAN for SurFS is likewise distributed WITHOUT ANY WARRANTY.
 */
package org.alfresco.jlan.oncrpc;

import org.alfresco.jlan.debug.Debug;

/**
 * ONC/RPC Request Thread Pool Class
 *
 * <p>
 * Processes RPC requests using a pool of worker threads.
 *
 * @author gkspencer
 */
public class RpcRequestThreadPool {

    //	Default/minimum/maximum number of worker threads to use
    public static final int DefaultWorkerThreads = 8;
    public static final int MinimumWorkerThreads = 4;
    public static final int MaximumWorkerThreads = 50;

    //	Queue of RPC requests
    private RpcRequestQueue m_queue;
    //	Worker threads
    private ThreadWorker[] m_workers;
    //	RPC dispatcher
    private RpcProcessor m_rpcProcessor;
    //	Debug enable flag
    private static boolean m_debug = true;

    /**
     * Thread Worker Inner Class
     */
    protected class ThreadWorker implements Runnable {

        private final boolean dataMsg;

        //Worker thread
        private final Thread mi_thread;
        //Worker unique id
        private final int mi_id;
        //Shutdown flag
        private boolean mi_shutdown = false;

        /**
         * Class constructor
         *
         * @param name String
         * @param id int
         * @param dataMsg
         */
        public ThreadWorker(String name, int id, boolean dataMsg) {
            this.dataMsg = dataMsg;
            mi_id = id;//Save the thread id	    
            mi_thread = new Thread(this);//Create the worker thread
            mi_thread.setName(name);
            mi_thread.setDaemon(true);
            mi_thread.start();
        }

        /**
         * Request the worker thread to shutdown
         */
        public final void shutdownRequest() {
            mi_shutdown = true;
            try {
                mi_thread.interrupt();
            } catch (Exception ex) {
            }
        }

        /**
         * Run the thread
         */
        @Override
        public void run() {
            RpcPacket rpc = null;
            RpcPacket response = null;
            while (mi_shutdown == false) {//	Loop until shutdown
                try {
                    //	Wait for an RPC request to be queued
                    if (dataMsg) {
                        rpc = m_queue.removeRequest();
                    } else {
                        rpc = m_queue.removeRequestHead();
                    }
                } catch (InterruptedException ex) {
                    if (mi_shutdown == true) {//	Check for shutdown
                        break;
                    }
                }
                //If the request is valid process it
                if (rpc != null) {
                    try {
                        //Process the request

                        response = m_rpcProcessor.processRpc(rpc);
                        if (response != null) {
                            response.getPacketHandler().sendRpcResponse(response);
                        }

                    } catch (Throwable ex) {
                        //Do not display errors if shutting down
                        if (mi_shutdown == false) {
                            Debug.println("Worker " + Thread.currentThread().getName() + ":");
                            Debug.println(ex);
                        }
                    } finally {
                        //Release the RPC packet(s) back to the packet pool
                        if (rpc.getClientProtocol() == Rpc.TCP && rpc.isAllocatedFromPool()) {
                            rpc.getOwnerPacketPool().releasePacket(rpc);
                        }
                        if (response != null && response.getClientProtocol() == Rpc.TCP
                                && response.getBuffer() != rpc.getBuffer() && response.isAllocatedFromPool()) {
                            response.getOwnerPacketPool().releasePacket(response);
                        }
                    }
                }
            }
        }
    };

    /**
     * Class constructor
     *
     * @param threadName String
     * @param rpcServer RpcProcessor
     */
    public RpcRequestThreadPool(String threadName, RpcProcessor rpcServer) {
        this(threadName, DefaultWorkerThreads, rpcServer);
    }

    /**
     * Class constructor
     *
     * @param threadName String
     * @param poolSize int
     * @param rpcServer RpcProcessor
     */
    public RpcRequestThreadPool(String threadName, int poolSize, RpcProcessor rpcServer) {
        //Save the RPC handler
        m_rpcProcessor = rpcServer;
        //Check that we have at least minimum worker threads
        if (poolSize < MinimumWorkerThreads) {
            poolSize = MinimumWorkerThreads;
        }
        //Create the request queue
        m_queue = new RpcRequestQueue();
        //Create the worker threads
        int headSize = poolSize / 4;
        if (headSize <= 0) {
            headSize = 1;
        }
        m_workers = new ThreadWorker[poolSize];
        for (int i = 0; i < headSize; i++) {
            m_workers[i] = new ThreadWorker(threadName + (i + 1), i, false);
        }
        for (int i = headSize; i < m_workers.length; i++) {
            m_workers[i] = new ThreadWorker(threadName + (i + 1), i, true);
        }
    }

    /**
     * Check if debug output is enabled
     *
     * @return boolean
     */
    public final static boolean hasDebug() {
        return m_debug;
    }

    /**
     * Queue an RPC request to the thread pool for processing
     *
     * @param pkt RpcPacket
     */
    public final void queueRpcRequest(RpcPacket pkt) {
        m_queue.addRequest(pkt);
    }

    /**
     * Shutdown the thread pool and release all resources
     */
    public void shutdownThreadPool() {
        //Shutdown the worker threads
        if (m_workers != null) {
            for (ThreadWorker m_worker : m_workers) {
                m_worker.shutdownRequest();
            }
        }
    }
}
