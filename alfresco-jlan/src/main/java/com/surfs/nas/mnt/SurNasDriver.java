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

import com.surfs.nas.client.SurfsDiskSize;
import com.surfs.nas.StorageConfig;
import com.surfs.nas.StorageSources;
import com.surfs.nas.client.SurFile;
import com.surfs.nas.client.SurFileFactory;
import com.surfs.nas.error.ArgumentException;
import com.surfs.nas.error.SessionTimeoutException;
import java.io.FileNotFoundException;
import java.io.IOException;
import org.alfresco.config.ConfigElement;
import org.alfresco.jlan.server.SrvSession;
import org.alfresco.jlan.server.core.DeviceContext;
import org.alfresco.jlan.server.core.DeviceContextException;
import org.alfresco.jlan.server.filesys.AccessDeniedException;
import org.alfresco.jlan.server.filesys.DirectoryNotEmptyException;
import org.alfresco.jlan.server.filesys.DiskDeviceContext;
import org.alfresco.jlan.server.filesys.DiskInterface;
import org.alfresco.jlan.server.filesys.FileAttribute;
import org.alfresco.jlan.server.filesys.FileInfo;
import org.alfresco.jlan.server.filesys.FileName;
import org.alfresco.jlan.server.filesys.FileOpenParams;
import org.alfresco.jlan.server.filesys.FileStatus;
import org.alfresco.jlan.server.filesys.FileSystem;
import org.alfresco.jlan.server.filesys.NetworkFile;
import org.alfresco.jlan.server.filesys.SearchContext;
import org.alfresco.jlan.server.filesys.TreeConnection;
import org.alfresco.jlan.server.filesys.DiskSizeInterface;
import org.alfresco.jlan.server.filesys.FileType;
import org.alfresco.jlan.server.filesys.SrvDiskInfo;

public class SurNasDriver implements DiskInterface, DiskSizeInterface {

    public static String poolname;

  
    static {
        StorageConfig.initClient();
        poolname = System.getProperty("com.surfs.nas.mnt.SurfsNasDriver.PoolName", StorageSources.getDefaultStoragePool().getName());
    }

    @Override
    public void createDirectory(SrvSession sess, TreeConnection tree, FileOpenParams params) throws IOException {
        String path = tree.getContext().getDeviceName() + params.getPath();
        SurFile sf = SurFileFactory.newInstance(path, poolname);
        int retrytimes = 0;
        while (true) {
            try {
                sf.mkdirs();
                return;
            } catch (Exception e) {
                try {
                    if (retrytimes++ >= sf.getStoragePool().getClientSourceMgr().getGlobleProperties().getErrRetryTimes()) {
                        
                        throw e instanceof IOException ? (IOException) e : new IOException(e);
                    }
                    Thread.sleep(sf.getStoragePool().getClientSourceMgr().getGlobleProperties().getReadTimeout() * 1000);
                } catch (InterruptedException ex) {//退出
                    
                    throw e instanceof IOException ? (IOException) e : new IOException(e);
                }
            }
        }
    }

    @Override
    public void deleteDirectory(SrvSession sess, TreeConnection tree, String dir) throws IOException {
        SurFile delDir = SurFileFactory.newInstance(tree.getContext().getDeviceName() + dir, poolname);
        int retrytimes = 0;
        while (true) {
            try {
                if (delDir.exists() && delDir.isDirectory()) {
                    if (!delDir.isEmptyDirectory()) {
                        throw new DirectoryNotEmptyException();
                    }
                    delDir.delete();
                    return;
                }
            } catch (DirectoryNotEmptyException e) {
                throw e;
            } catch (Exception e) {
                try {
                    if (retrytimes++ >= delDir.getStoragePool().getClientSourceMgr().getGlobleProperties().getErrRetryTimes()) {
                       
                        throw e instanceof IOException ? (IOException) e : new IOException(e);
                    }
                    Thread.sleep(delDir.getStoragePool().getClientSourceMgr().getGlobleProperties().getReadTimeout() * 1000);
                } catch (InterruptedException ex) {//退出
                   
                    throw e instanceof IOException ? (IOException) e : new IOException(e);
                }
            }
        }
    }

    @Override
    public void deleteFile(SrvSession sess, TreeConnection tree, String name) throws IOException {
        SurFile delFile = SurFileFactory.newInstance(tree.getContext().getDeviceName() + name, poolname);
        int retrytimes = 0;
        while (true) {
            try {
                if (delFile.exists() && delFile.isFile()) {
                    SurNetworkFile.closeSurNetworkFile(delFile);
                    delFile.delete();
                }
                return;
            } catch (Exception e) {
                try {
                    if (retrytimes++ >= delFile.getStoragePool().getClientSourceMgr().getGlobleProperties().getErrRetryTimes()) {
                       
                        throw e instanceof IOException ? (IOException) e : new IOException(e);
                    }
                    Thread.sleep(delFile.getStoragePool().getClientSourceMgr().getGlobleProperties().getReadTimeout() * 1000);
                } catch (InterruptedException ex) {//退出
                    
                    throw e instanceof IOException ? (IOException) e : new IOException(e);
                }
            }
        }
    }

    @Override
    public int fileExists(SrvSession sess, TreeConnection tree, String name) {
        try {
            SurFile chkFile = SurFileFactory.newInstance(tree.getContext().getDeviceName() + name, poolname);
            if (chkFile.exists()) {
                if (chkFile.isFile()) {
                    return FileStatus.FileExists;
                } else {
                    return FileStatus.DirectoryExists;
                }
            } else {
                return FileStatus.NotExist;
            }
        } catch (IOException ex) {
            return FileStatus.NotExist;
        }
    }

    @Override
    public void flushFile(SrvSession sess, TreeConnection tree, NetworkFile file) throws IOException {
        try {
            file.flushFile();
        } catch (IOException r) {
            try {
                file.closeFile();
            } catch (Exception e) {
            }
            if (r instanceof SessionTimeoutException) {
                return;
            }
            throw r;
        }
    }

    @Override
    public FileInfo getFileInformation(SrvSession sess, TreeConnection tree, String name) throws IOException {
        try {
            SurFile file = SurFileFactory.newInstance(tree.getContext().getDeviceName() + name, poolname);
            if (file.exists()) {
                if (file.isFile()) {
                    long flen = file.length();
                    FileInfo finfo = new FileInfo(file.getName(), flen, 0);
                    long fdate = file.lastModified();
                    finfo.setModifyDateTime(fdate);
                    finfo.setFileId(file.getFileId());
                    finfo.setCreationDateTime(fdate);
                    finfo.setChangeDateTime(fdate);
                    //log.info("getFileInformation[{0}]", new Object[]{finfo.toString()});
                    return finfo;
                } else {
                    int fattr = FileAttribute.Directory;
                    FileInfo finfo = new FileInfo(file.getName(), 0, fattr);
                    finfo.setFileType(FileType.Directory);
                    long fdate = SurFile._globalCreateDate;
                    finfo.setFileAttributes(fattr);
                    finfo.setModifyDateTime(fdate);
                    finfo.setFileId(file.getFileId());
                    finfo.setCreationDateTime(fdate);
                    finfo.setChangeDateTime(fdate);
                    return finfo;
                }
            } else {
                return null;
            }
        } catch (ArgumentException ae) {
            return null;
        }
    }

    @Override
    public boolean isReadOnly(SrvSession sess, DeviceContext ctx) throws IOException {
        return false;
    }

    @Override
    public NetworkFile createFile(SrvSession sess, TreeConnection tree, FileOpenParams params) throws IOException {
        String path = tree.getContext().getDeviceName() + params.getPath();
        SurFile sf = SurFileFactory.newInstance(path, poolname);
        int retrytimes = 0;
        if (!sf.exists()) {
            while (true) {
                try {
                    SurFile parent = sf.getParentFile();
                    parent.mkdirs();
                    sf.createNewFile();
                    break;
                } catch (Exception e) {
                    try {
                        if (retrytimes++ >= sf.getStoragePool().getClientSourceMgr().getGlobleProperties().getErrRetryTimes()) {
                           
                            throw e instanceof IOException ? (IOException) e : new IOException(e);
                        }
                        Thread.sleep(sf.getStoragePool().getClientSourceMgr().getGlobleProperties().getCheckSpaceInterval() * 1000);

                    } catch (InterruptedException ex) {//退出
                  
                        throw e instanceof IOException ? (IOException) e : new IOException(e);
                    }
                }
            }
        }
        SurNetworkFile file = new SurNetworkFile(sf);
        if (params.isReadOnlyAccess()) {
            file.setGrantedAccess(NetworkFile.READONLY);
        } else {
            file.setGrantedAccess(NetworkFile.READWRITE);
        }
        file.setFullName(sf.getPath().substring(tree.getContext().getDeviceName().length()));
        return file;
    }

    @Override
    public NetworkFile openFile(SrvSession sess, TreeConnection tree, FileOpenParams params) throws IOException {
        String path = tree.getContext().getDeviceName() + params.getPath();
        SurFile file = SurFileFactory.newInstance(path, poolname);
        if (!file.exists()) {
          
            throw new FileNotFoundException(path);
        }
        SurNetworkFile netFile = new SurNetworkFile(file);
        netFile.setFullName(file.getPath().substring(tree.getContext().getDeviceName().length()));
        if (params.isReadOnlyAccess()) {
            netFile.setGrantedAccess(NetworkFile.READONLY);
        } else {
            netFile.setGrantedAccess(NetworkFile.READWRITE);
        }
        if (file.isDirectory()) {
            netFile.setAttributes(FileAttribute.Directory);
        }
        return netFile;
    }

    @Override
    public void closeFile(SrvSession sess, TreeConnection tree, NetworkFile file) throws IOException {
        file.closeFile();
        if (file.hasDeleteOnClose()) {
            if (file.isDirectory()) {
                deleteDirectory(sess, tree, file.getFullName());
            } else {
                deleteFile(sess, tree, file.getFullName());
            }
        }
    }

    @Override
    public int writeFile(SrvSession sess, TreeConnection tree, NetworkFile file, byte[] buf, int bufoff, int siz, long fileoff) throws IOException {
        if (file.isDirectory()) {
            throw new AccessDeniedException();
        }
        ((SurDeviceContext) tree.getContext()).getSurfsDiskSize().checkDiskSpace();
        file.writeFile(buf, siz, bufoff, fileoff);
        return siz;
    }

    @Override
    public int readFile(SrvSession sess, TreeConnection tree, NetworkFile file, byte[] buf, int bufPos, int siz, long filePos) throws IOException {
        if (file.isDirectory()) {
            throw new AccessDeniedException();
        }
        int rdlen = file.readFile(buf, siz, bufPos, filePos);
        if (rdlen == -1) {
            rdlen = 0;
        }
        return rdlen;
    }

    @Override
    public void renameFile(SrvSession sess, TreeConnection tree, String oldName, String newName) throws IOException {
        SurFile oldFile = SurFileFactory.newInstance(tree.getContext().getDeviceName() + oldName, poolname);
        if (!oldFile.exists()) {
            throw new FileNotFoundException("Rename file, does not exist " + oldName);
        }
        SurFile newFile = SurFileFactory.newInstance(tree.getContext().getDeviceName() + newName, poolname);
        int retrytimes = 0;
        while (true) {
            try {
                if (newFile.exists()) {
                    SurNetworkFile.closeSurNetworkFile(newFile);
                    newFile.delete();
                }
                SurNetworkFile.closeSurNetworkFile(oldFile);
                oldFile.renameTo(newFile);
                return;
            } catch (Exception e) {
                try {
                    if (retrytimes++ >= oldFile.getStoragePool().getClientSourceMgr().getGlobleProperties().getErrRetryTimes()) {
                       
                        throw e instanceof IOException ? (IOException) e : new IOException(e);
                    }
                    Thread.sleep(oldFile.getStoragePool().getClientSourceMgr().getGlobleProperties().getReadTimeout() * 1000);
                } catch (InterruptedException ex) {//退出
                  
                    throw e instanceof IOException ? (IOException) e : new IOException(e);
                }
            }
        }
    }

    @Override
    public long seekFile(SrvSession sess, TreeConnection tree, NetworkFile file, long pos, int typ) throws IOException {
        return file.seekFile(pos, typ);
    }

    @Override
    public void setFileInformation(SrvSession sess, TreeConnection tree, String name, FileInfo info) throws IOException {
        /*
         if (info.hasSetFlag(FileInfo.SetModifyDate)) {
         SurFile file = SurFileFactory.newInstance(tree.getContext().getDeviceName() + name, poolname);
         if (file.exists()) {
         if (file.isFile()) {
         file.getMeta().setLastModified(info.getModifyDateTime());
         }
         }
         }
         */
    }

    @Override
    public SearchContext startSearch(SrvSession sess, TreeConnection tree, String searchPath, int attrib) throws FileNotFoundException {
        String path = tree.getContext().getDeviceName() + searchPath;
        String[] paths = FileName.splitPath(path);
        int retrytimes = 0;
        while (true) {
            try {
                SurFile file = SurFileFactory.newInstance(paths[0], poolname);
                SurFileSearchContext ctx = new SurFileSearchContext(file, paths[1], attrib);
                return ctx;
            } catch (Exception e) {
                try {
                    if (retrytimes++ >= StorageSources.getStoragePool(poolname).getClientSourceMgr().getGlobleProperties().getErrRetryTimes()) {
                     
                        return null;
                    }
                    Thread.sleep(StorageSources.getStoragePool(poolname).getClientSourceMgr().getGlobleProperties().getReadTimeout() * 1000);
                } catch (IOException ex) {//不可能
                } catch (InterruptedException ex) {//退出
                    
                    return null;
                }
            }
        }
    }

    @Override
    public void truncateFile(SrvSession sess, TreeConnection tree, NetworkFile file, long siz) throws IOException {
        file.truncateFile(siz);
    }

    @Override
    public DeviceContext createContext(String shareName, ConfigElement args) throws DeviceContextException {
        SurFile sf;
        try {
            sf = SurFileFactory.newInstance(shareName, poolname);
            if (!(sf.exists() && sf.isDirectory())) {
                throw new DeviceContextException("");
            }
        } catch (IOException ex) {
            throw new DeviceContextException(ex.getMessage());
        }
        SurDeviceContext ctx;
        try {
            ctx = new SurDeviceContext(sf);
        } catch (IOException ex) {
       
            throw new DeviceContextException(ex.getMessage());
        }
        ctx.open();
        ctx.setFilesystemAttributes(FileSystem.CasePreservedNames + FileSystem.UnicodeOnDisk);
        ctx.setFilesystemType(FileSystem.TypeNTFS);

        return ctx;
    }

    @Override
    public void treeOpened(SrvSession sess, TreeConnection tree) {
    }

    @Override
    public void treeClosed(SrvSession sess, TreeConnection tree) {
    }

    @Override
    public void getDiskInformation(DiskDeviceContext ctx, SrvDiskInfo diskDev) throws IOException {
        SurDeviceContext sctx = (SurDeviceContext) ctx;
        SurfsDiskSize surfsDiskSize = sctx.getSurfsDiskSize();
        diskDev.setBlockSize(surfsDiskSize.getBlockSize());
        diskDev.setBlocksPerAllocationUnit(surfsDiskSize.getBlockPerunit());
        long free = surfsDiskSize.getFreeUnits();
        diskDev.setFreeUnits(free < 0 ? 0 : free);
        diskDev.setTotalUnits(surfsDiskSize.getTotalUnits());
    }
}
