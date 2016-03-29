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

package com.surfs.nas.mnt;

import com.surfs.nas.client.NasRandomAccessor;
import com.surfs.nas.client.SurFile;
import java.io.IOException;
import java.util.Map;
import org.alfresco.jlan.server.filesys.FileInfo;
import org.alfresco.jlan.server.filesys.NetworkFile;

public class SurNetworkFile extends NetworkFile {


    private static final Map<String, SurNetworkFile> fileChache = new java.util.concurrent.ConcurrentHashMap<>();

    public static SurNetworkFile getSurNetworkFile(String path) {
        return fileChache.get(path);
    }

    public static SurNetworkFile closeSurNetworkFile(SurFile surfile) {
        SurNetworkFile snf = fileChache.get(surfile.getPath());
        if (snf != null) {
            try {
                snf.closeFile();
                snf.needUpdate = true;
            } catch (IOException ex) {
            }
        }
        return snf;
    }

    private final SurFile m_file;
    private NasRandomAccessor m_io = null;
    private final FileInfo finfo;

    public SurNetworkFile(SurFile surfile) throws IOException {
        super(surfile.getName());
        this.m_file = surfile;
        long flen = m_file.length();
        setFileSize(flen);
        long modDate = m_file.lastModified();
        setModifyDate(modDate);
        setCreationDate(modDate);
        setFileId(surfile.getFileId());
        finfo = new FileInfo(surfile.getName(), flen, 0);
        finfo.setModifyDateTime(modDate);
        finfo.setFileId(this.getFileId());
        finfo.setCreationDateTime(modDate);
        finfo.setChangeDateTime(modDate);
    }

    @Override
    public FileInfo getFileInformation() {
        return finfo;
    }

    private boolean needUpdate = false;

    @Override
    public void openFile(boolean createFlag) throws IOException {
        synchronized (m_file) {
            if (m_io == null) {
                if (needUpdate) {
                    m_file.queryMeta(true);
                    needUpdate = false;
                }
                m_io = new NasRandomAccessor(m_file);
                fileChache.put(m_file.getPath(), this);
                setClosed(false);
                //setFileId(m_file.getFileId());
                //finfo.setFileId(this.getFileId());
                if (m_file.getMeta() != null) {
                    finfo.setFileSize(m_file.getMeta().getLength());
                    this.setFileSize(m_file.getMeta().getLength());
                    finfo.setModifyDateTime(m_file.getMeta().getLastModified());
                    this.setModifyDate(m_file.getMeta().getLastModified());
                }
               
            }
        }
    }

    /**
     * 关闭
     *
     * @throws IOException
     */
    @Override
    public void closeFile() throws IOException {
        synchronized (m_file) {
            if (m_io != null) {
                fileChache.remove(m_file.getPath());
                m_io.close();
                m_io = null;

                setClosed(true);
            }
        }
    }

    @Override
    public void flushFile() throws IOException {
    }

    @Override
    public int readFile(byte[] buf, int len, int pos, long fileOff) throws IOException {
        openFile(false);
        return m_io.read(buf, pos, len, fileOff);
    }

    @Override
    public void writeFile(byte[] buf, int len, int pos, long fileOff) throws IOException {
        openFile(false);
        m_io.write(buf, pos, len, fileOff);
        if (m_file.getMeta() != null) {
            finfo.setFileSize(m_file.getMeta().getLength());
            this.setFileSize(m_file.getMeta().getLength());
            finfo.setModifyDateTime(m_file.getMeta().getLastModified());
            this.setModifyDate(m_file.getMeta().getLastModified());
        }
        incrementWriteCount();
    }

    @Override
    public void truncateFile(long siz) throws IOException {
        openFile(false);
        if (siz != m_file.getMeta().getLength()) {
            m_io.setLength(siz);
            if (m_file.getMeta() != null) {
                finfo.setFileSize(m_file.getMeta().getLength());
                this.setFileSize(m_file.getMeta().getLength());
                finfo.setModifyDateTime(m_file.getMeta().getLastModified());
                this.setModifyDate(m_file.getMeta().getLastModified());
            }
        }
    }

    @Override
    public long seekFile(long pos, int typ) throws IOException {
        throw new UnsupportedOperationException("Not supported yet.");
    }
}
