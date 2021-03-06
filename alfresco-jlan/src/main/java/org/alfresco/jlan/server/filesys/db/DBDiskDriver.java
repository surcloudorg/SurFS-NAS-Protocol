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

package org.alfresco.jlan.server.filesys.db;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.ArrayList;

import org.alfresco.jlan.debug.Debug;
import org.alfresco.jlan.locking.LockConflictException;
import org.alfresco.jlan.server.SrvSession;
import org.alfresco.jlan.server.core.DeviceContext;
import org.alfresco.jlan.server.core.DeviceContextException;
import org.alfresco.jlan.server.filesys.AccessDeniedException;
import org.alfresco.jlan.server.filesys.DiskDeviceContext;
import org.alfresco.jlan.server.filesys.DiskFullException;
import org.alfresco.jlan.server.filesys.DiskInterface;
import org.alfresco.jlan.server.filesys.DiskOfflineException;
import org.alfresco.jlan.server.filesys.DiskSizeInterface;
import org.alfresco.jlan.server.filesys.DiskVolumeInterface;
import org.alfresco.jlan.server.filesys.FileAttribute;
import org.alfresco.jlan.server.filesys.FileExistsException;
import org.alfresco.jlan.server.filesys.FileIdInterface;
import org.alfresco.jlan.server.filesys.FileInfo;
import org.alfresco.jlan.server.filesys.FileName;
import org.alfresco.jlan.server.filesys.FileNameException;
import org.alfresco.jlan.server.filesys.FileOpenParams;
import org.alfresco.jlan.server.filesys.FileSharingException;
import org.alfresco.jlan.server.filesys.FileStatus;
import org.alfresco.jlan.server.filesys.FileType;
import org.alfresco.jlan.server.filesys.NetworkFile;
import org.alfresco.jlan.server.filesys.SearchContext;
import org.alfresco.jlan.server.filesys.SrvDiskInfo;
import org.alfresco.jlan.server.filesys.SymbolicLinkInterface;
import org.alfresco.jlan.server.filesys.TreeConnection;
import org.alfresco.jlan.server.filesys.VolumeInfo;
import org.alfresco.jlan.server.filesys.cache.FileState;
import org.alfresco.jlan.server.filesys.cache.FileStateCache;
import org.alfresco.jlan.server.filesys.cache.FileStateLockManager;
import org.alfresco.jlan.server.filesys.loader.NamedFileLoader;
import org.alfresco.jlan.server.filesys.quota.QuotaManager;
import org.alfresco.jlan.server.locking.FileLockingInterface;
import org.alfresco.jlan.server.locking.LockManager;
import org.alfresco.jlan.smb.SharingMode;
import org.alfresco.jlan.smb.WinNT;
import org.alfresco.jlan.smb.server.ntfs.NTFSStreamsInterface;
import org.alfresco.jlan.smb.server.ntfs.StreamInfo;
import org.alfresco.jlan.smb.server.ntfs.StreamInfoList;
import org.alfresco.jlan.util.WildCard;
import org.alfresco.config.ConfigElement;

/**
 * Database Disk Driver Class
 *
 * @author gkspencer
 */
public class DBDiskDriver implements DiskInterface, DiskSizeInterface, DiskVolumeInterface, NTFSStreamsInterface,
  FileLockingInterface, FileIdInterface, SymbolicLinkInterface {

  //  Attributes attached to the file state
  
  public static final String DBStreamList   = "DBStreamList";
  
  //  Default mode values for files/folders, if not specified in the file/folder create parameters
  
  public static final int DefaultNFSFileMode    = 0644;
  public static final int DefaultNFSDirMode     = 0755;
  
  //  Maximum file name length
  
  public static final int MaxFileNameLen  = 255;
  
  //  Lock manager
  
  private static LockManager _lockManager = new FileStateLockManager();
  
  //  Enable/disable debug output
  
  private boolean m_debug = false;
  
  /**
   * Close the specified file
   * 
   * @param sess  Session details
   * @param tree  Tree connection
   * @param file  Network file details
   * @exception IOException
   */
  public void closeFile(SrvSession sess, TreeConnection tree, NetworkFile file)
    throws IOException {
    
    //  Access the database context

    DBDeviceContext dbCtx = (DBDeviceContext) tree.getContext();

    //  Check if the file is an NTFS stream
    
    if ( file.isStream()) {
      
      //  Close the NTFS stream
      
      closeStream(sess, tree, file);
      
      //  Check if the stream is marked for deletion
      
      if ( file.hasDeleteOnClose())
        deleteStream(sess, tree, file.getFullNameStream());
      return;    
    }
    
    //  Debug
    
    if ( Debug.EnableInfo && hasDebug())
      Debug.println("DB closeFile() file=" + file.getFullName());
      
    //  Close the file

    dbCtx.getFileLoader().closeFile(sess, file);

    //  Access the JDBC file
    
    DBNetworkFile jdbcFile = null;
    
    if ( file instanceof DBNetworkFile) {
      
      //  Access the JDBC file
      
      jdbcFile = (DBNetworkFile) file;

      //  Decrement the open file count
      
      FileState fstate = jdbcFile.getFileState();

      //  Check if the file state is valid, if not then check the main file state cache

      if ( fstate == null) {
        
        //  Check the main file state cache
              
        fstate = getFileState(file.getFullName(), dbCtx, false);
      }
      else {
        
        //  Decrement the open file count for this file
        
        fstate.decrementOpenCount();
      }

      //  Release any locks on the file owned by this session
      
      if ( jdbcFile.hasLocks()) {
        
        //  Get the lock manager
        
        FileLockingInterface flIface = (FileLockingInterface) this;
        LockManager lockMgr = flIface.getLockManager(sess, tree);
        
        //  DEBUG
        
        if ( Debug.EnableInfo && hasDebug())
          Debug.println("Releasing locks for closed file, file=" + jdbcFile.getFullName() + ", locks=" + jdbcFile.numberOfLocks());
          
        //  Release all locks on the file owned by this session
        
        lockMgr.releaseLocksForFile(sess, tree, file);
      }
      
      //  Check if we have a valid file state
            
      if ( fstate != null) {
        
        //  Update the cached file size
        
        DBFileInfo finfo = (DBFileInfo) fstate.findAttribute(FileState.FileInformation);
        if ( finfo != null && file.getWriteCount() > 0) {
          
          //  Update the file size
          
          finfo.setSize(jdbcFile.getFileSize());
          
          //  Update the modified date/time
          
          finfo.setModifyDateTime(jdbcFile.getModifyDate());
          
          //  DEBUG
          
          if ( Debug.EnableInfo && hasDebug())
            Debug.println("  File size=" + jdbcFile.getFileSize() + ", modifyDate=" + jdbcFile.getModifyDate());
        }

        //  DEBUG
        
        if ( Debug.EnableInfo && hasDebug())
          Debug.println("  Open count=" + jdbcFile.getFileState().getOpenCount());
      }
      
      //  Check if the file/directory is marked for delete
      
      if ( file.hasDeleteOnClose()) {
        
        //  Check for a file or directory
        
        if ( file.isDirectory())
          deleteDirectory(sess, tree, file.getFullName());
        else
          deleteFile(sess, tree, file.getFullName());
        
        //  DEBUG

        if ( Debug.EnableInfo && hasDebug())
          Debug.println("  Marked for delete");
      }
    }
    else if ( Debug.EnableError)
      Debug.println("closeFile() Not DBNetworkFile file=" + file);
      
    //  Check if the file was opened for write access, if so then update the file size and modify date/time
    
    if ( file.getGrantedAccess() != NetworkFile.READONLY && file.isDirectory() == false &&
         file.getWriteCount() > 0) {
      
      //  DEBUG
      
      if ( Debug.EnableInfo && hasDebug())
        Debug.println("  Update file size=" + file.getFileSize());
        
      //  Get the current date/time
      
      long modifiedTime = 0L;
      if ( file.hasModifyDate())
        modifiedTime = file.getModifyDate();
      else
        modifiedTime = System.currentTimeMillis();

      //  Check if the modified time is earlier than the file creation date/time
      
      if ( file.hasCreationDate() && modifiedTime < file.getCreationDate()) {
        
        //  Use the creation date/time for the modified date/time
        
        modifiedTime = file.getCreationDate();
        
        //  DEBUG
        
        if ( Debug.EnableInfo && hasDebug())
          Debug.println("Close file using creation date/time for modified date/time");
      }
      
      //  Update the file details
      
      try {
        
        //  Update the file details

        FileInfo finfo = new FileInfo();
        
        finfo.setFileSize( file.getFileSize());
        finfo.setModifyDateTime(modifiedTime);
        
        finfo.setFileInformationFlags(FileInfo.SetFileSize + FileInfo.SetModifyDate);

        //  Call the database interface
        
        dbCtx.getDBInterface().setFileInformation(file.getDirectoryId(), file.getFileId(), finfo);
      }
      catch (DBException ex) {
      }
    }
  }

  /**
   * Create a new directory
   * 
   * @param sess   Session details
   * @param tree   Tree connection
   * @param params Directory create parameters
   * @exception IOException
   */
  public void createDirectory(SrvSession sess, TreeConnection tree, FileOpenParams params)
    throws IOException {

    //  Access the database context

    DBDeviceContext dbCtx = (DBDeviceContext) tree.getContext();

    // Check if the database is online
    
    if ( dbCtx.getDBInterface().isOnline() == false)
      throw new DiskOfflineException( "Database is offline");
    
    //  Get, or create, a file state for the new path. Initially this will indicate that the directory
    //  does not exist.
    
    FileState fstate = getFileState(params.getPath(), dbCtx, false);
    if ( fstate != null && fstate.fileExists() == true)
      throw new FileExistsException("Path " + params.getPath() + " exists");

    //  If there is no file state check if the directory exists
    
    if ( fstate == null) {

      //  Create a file state for the new directory
      
      fstate = getFileState(params.getPath(), dbCtx, true);
      
      //  Get the file details for the directory
      
      if ( getFileDetails(params.getPath(), dbCtx, fstate) != null)
        throw new FileExistsException("Path " + params.getPath() + " exists");
    }

    //  Find the parent directory id for the new directory
    
    int dirId = findParentDirectoryId(dbCtx,params.getPath(),true);
    if ( dirId == -1)
      throw new IOException("Cannot find parent directory");
      
    //  Create the new directory entry
    
    try {

      //  Get the directory name
      
      String[] paths = FileName.splitPath(params.getPath());
      String dname = paths[1];

      //  Check if the directory name is too long
      
      if ( dname != null && dname.length() > MaxFileNameLen)
        throw new FileNameException("Directory name too long, " + dname);
      
      //  If retention is enabled check if the file is a temporary folder
      
      boolean retain = true;
      
      if ( dbCtx.hasRetentionPeriod()) {
        
        //  Check if the file is marked delete on close
        
        if ( params.isDeleteOnClose())
          retain = false;
      }
      
      //  Set the default NFS file mode, if not set
      
      if ( params.hasMode() == false)
        params.setMode(DefaultNFSDirMode);

      //  Make sure the create directory option is enabled
      
      if ( params.hasCreateOption( WinNT.CreateDirectory) == false)
        throw new IOException( "Create directory called for non-directory");
      
      //  Use the database interface to create the new file record
      
      int fid = dbCtx.getDBInterface().createFileRecord(dname, dirId, params, retain);

      //  Indicate that the path exists
      
      fstate.setFileStatus( FileStatus.DirectoryExists);
      
      //  Set the file id for the new directory
      
      fstate.setFileId(fid);
      
      //  If retention is enabled get the expiry date/time
      
      if ( dbCtx.hasRetentionPeriod() && retain == true) {
        RetentionDetails retDetails = dbCtx.getDBInterface().getFileRetentionDetails(dirId, fid);
        if ( retDetails != null)
          fstate.setRetentionExpiryDateTime(retDetails.getEndTime());
      }
      
      //  Check if the file loader handles create directory requests
      
      if ( fid != -1 && dbCtx.getFileLoader() instanceof NamedFileLoader) {
        
        //  Create the directory in the filesystem/repository
        
        NamedFileLoader namedLoader = (NamedFileLoader) dbCtx.getFileLoader();
        namedLoader.createDirectory(params.getPath(), fid);
      }
    }
    catch (Exception ex) {
      Debug.println(ex);
    }
  }

  /**
   * Create a new file entry
   * 
   * @param sess SrvSession
   * @param tree TreeConnection
   * @param params FileOpenParams
   * @return NetworkFile
   */
  public NetworkFile createFile(SrvSession sess, TreeConnection tree, FileOpenParams params)
    throws IOException {

    //  Access the database context

    DBDeviceContext dbCtx = (DBDeviceContext) tree.getContext();

    // Check if the database is online
    
    if ( dbCtx.getDBInterface().isOnline() == false)
      throw new DiskOfflineException( "Database is offline");
    
    //  Set the session in the file open parameters
    
    params.setSession( sess);
    
    //  Get, or create, a file state for the new file
    
    FileState fstate = getFileState(params.getPath(), dbCtx, true);
    if ( fstate.fileExists()) {
      
      //  Check if the file creation is a new stream
      
      if ( params.isStream() == false)
        throw new FileExistsException("File exists, " + params.getPath());
        
      //  Create a new stream associated with the existing file
      
      return createStream(params, fstate, dbCtx);
    }
      
    //  Split the path string and find the directory id to attach the file to
    
    int dirId = findParentDirectoryId(dbCtx,params.getPath(),true);
    if ( dirId == -1)
      throw new IOException("Cannot find parent directory");

    //  Check if the allocation size for the new file is greater than the maximum allowed file size
    
    if ( dbCtx.hasMaximumFileSize() && params.getAllocationSize() > dbCtx.getMaximumFileSize())
      throw new DiskFullException( "Required allocation greater than maximum file size");
    
    //  Create a new file
    
    DBNetworkFile file = null;

    try {

      //  Get the file name
      
      String[] paths = FileName.splitPath(params.getPath());
      String fname = paths[1];
      
      //  Check if the file name is too long
      
      if ( fname != null && fname.length() > MaxFileNameLen)
        throw new FileNameException("File name too long, " + fname);
      
      //  If retention is enabled check if the file is a temporary file
      
      boolean retain = true;
      
      if ( dbCtx.hasRetentionPeriod()) {
        
        //  Check if the file is marked delete on close
        
        if ( params.isDeleteOnClose())
          retain = false;
      }
      
      //  Set the default NFS file mode, if not set
      
      if ( params.hasMode() == false)
        params.setMode(DefaultNFSFileMode);
      
      //  Create a new file record
      
      int fid = dbCtx.getDBInterface().createFileRecord(fname, dirId, params, retain);

      //  Indicate that the file exists
        
      fstate.setFileStatus( FileStatus.FileExists);

      //  Save the file id
        
      fstate.setFileId(fid);

      //  If retention is enabled get the expiry date/time
      
      if ( dbCtx.hasRetentionPeriod() && retain == true) {
        RetentionDetails retDetails = dbCtx.getDBInterface().getFileRetentionDetails(dirId, fid);
        if ( retDetails != null)
          fstate.setRetentionExpiryDateTime(retDetails.getEndTime());
      }
      
      //  Create a network file to hold details of the new file entry

      file = (DBNetworkFile) dbCtx.getFileLoader().openFile(params, fid, 0, dirId, true, false);
      file.setFullName(params.getPath());
      file.setDirectoryId(dirId);
      file.setAttributes(params.getAttributes());
      file.setFileState(fstate);
        
      //  Open the file
        
      file.openFile(true);
    }
    catch (DBException ex) {
      
      // Remove the file state for the new file
      
      dbCtx.getStateCache().removeFileState( fstate.getPath());
      
      // DEBUG
      
      Debug.println("Create file error: " + ex.toString());
//      Debug.println(ex);
    }

    //  Return the new file details

    if (file == null)
      throw new IOException( "Failed to create file " + params.getPath());
    else {
      
      //  Update the file state
    
      fstate.incrementOpenCount();
    }

    //  Return the network file
    
    return file;
  }

  /**
   * Delete a directory
   * 
   * @param sess  Session details
   * @param tree  Tree connection
   * @param dir   Path of directory to delete
   * @exception IOException
   */
  public void deleteDirectory(SrvSession sess, TreeConnection tree, String dir)
    throws IOException {
    
    //  Debug
    
    if ( Debug.EnableInfo && hasDebug())
      Debug.println("DB deleteDirectory() dir=" + dir);
      
    //  Access the JDBC context

    DBDeviceContext dbCtx = (DBDeviceContext) tree.getContext();

    // Check if the database is online
    
    if ( dbCtx.getDBInterface().isOnline() == false)
      throw new DiskOfflineException( "Database is offline");
    
    //  Get the file state for the path
    
    FileState fstate = getFileState(dir,dbCtx,false);
    if ( fstate != null && fstate.fileExists() == false)
      throw new FileNotFoundException("Path does not exist, " + dir);

    //  Create a file state if it does not exist
    
    if ( fstate == null)
      fstate = getFileState(dir,dbCtx,true);
            
    //  Get the directory details

    DBFileInfo dinfo = getFileDetails(dir, dbCtx,fstate);
    if ( dinfo == null)
      throw new FileNotFoundException(dir);
    
    //  Check if the directory contains any files
    
    try {

      //  Check if the file loader handles delete directory requests. Called first as the loader may throw an exception
      //  to stop the directory being deleted.
      
      if ( dbCtx.isTrashCanEnabled() == false && dbCtx.getFileLoader() instanceof NamedFileLoader) {
        
        //  Delete the directory in the filesystem/repository
        
        NamedFileLoader namedLoader = (NamedFileLoader) dbCtx.getFileLoader();
        namedLoader.deleteDirectory(dir, dinfo.getFileId());
      }

      //  Delete the directory file record, or mark as deleted if the trashcan is enabled
      
      dbCtx.getDBInterface().deleteFileRecord(dinfo.getDirectoryId(), dinfo.getFileId(), dbCtx.isTrashCanEnabled());
        
      //  Indicate that the path does not exist

      fstate.setFileStatus( FileStatus.NotExist);
      fstate.setFileId(-1);
      fstate.removeAttribute(FileState.FileInformation);
    }
    catch (DBException ex) {
      ex.printStackTrace(System.err);
      throw new IOException();
    }
  }

  /**
   * Delete a file
   * 
   * @param sess  Session details
   * @param tree  Tree connection
   * @param name  Name of file to delete
   * @exception IOException
   */
  public void deleteFile(SrvSession sess, TreeConnection tree, String name)
    throws IOException {

    //  Access the JDBC context

    DBDeviceContext dbCtx = (DBDeviceContext) tree.getContext();

    // Check if the database is online
    
    if ( dbCtx.getDBInterface().isOnline() == false)
      throw new DiskOfflineException( "Database is offline");
    
    //  Check if the file name is a stream
    
    if ( FileName.containsStreamName(name)) {
      
      //  Delete a stream within a file
      
      deleteStream(sess, tree, name);
      return;
    }
    
    //  Get the file state for the path
    
    FileState fstate = getFileState(name, dbCtx, false);
    if ( fstate != null && fstate.fileExists() == false)
      throw new FileNotFoundException("File does not exist, " + name);
    
    //  Create a file state for the file, if not already valid
    
    if ( fstate == null)
      fstate = getFileState(name, dbCtx, true);
        
    try {

      //  Check if the file is within an active retention period
      
      getRetentionDetailsForState( dbCtx, fstate);
      
      if ( fstate.hasActiveRetentionPeriod())
        throw new AccessDeniedException("File retention active");

      //  Get the file details
      
      DBFileInfo dbInfo = getFileDetails(name, dbCtx, fstate);
      if ( dbInfo == null)
        throw new FileNotFoundException(name);
      
      //  DEBUG
      
      if ( Debug.EnableInfo && hasDebug())
        Debug.println("DBDiskDriver deleteFile() name=" + name + ", state=" + fstate);
      
      //  Delete the file in the filesystem/repository, the loader may prevent the file delete by throwing
      //  an exception
      
      if ( dbCtx.isTrashCanEnabled() == false)
        dbCtx.getFileLoader().deleteFile(name, dbInfo.getFileId(), 0);

      //  If the file is a symbolic link delete the symbolic link record
      
      if ( dbInfo.isFileType() == FileType.SymbolicLink)
        dbCtx.getDBInterface().deleteSymbolicLinkRecord( dbInfo.getDirectoryId(), dbInfo.getFileId());
      
      //  Delete the file record

      dbCtx.getDBInterface().deleteFileRecord(dbInfo.getDirectoryId(), dbInfo.getFileId(), dbCtx.isTrashCanEnabled());
      
      //  Indicate that the path does not exist

      fstate.setFileStatus( FileStatus.NotExist);
      fstate.setFileId(-1);
      fstate.removeAttribute(FileState.FileInformation);
      
      //  Check if there is a quota manager, if so then release the file space
      
      if ( dbCtx.hasQuotaManager()) {
        
        //  Release the file space back to the filesystem free space
        
        dbCtx.getQuotaManager().releaseSpace(sess, tree, dbInfo.getFileId(), null, dbInfo.getSize());
      }
    }
    catch (DBException ex) {
      Debug.println(ex);
      throw new IOException();
    }
  }

  /**
   * Check if the specified file exists, and it is a file.
   *
   * @param sess  Session details
   * @param tree  Tree connection
   * @param name  File name
   * @return int
   */
  public int fileExists(SrvSession sess, TreeConnection tree, String name) {

    //  Access the JDBC context

    DBDeviceContext dbCtx = (DBDeviceContext) tree.getContext();

    //  Check if the path contains an NTFS stream name

    int fileSts = FileStatus.NotExist;
        
    if ( FileName.containsStreamName(name)) {
      
      //  Split the path into directory, file and stream name components
      
      String[] paths = FileName.splitPathStream(name);    

      //  Get, or create, the file state for main file path
      
      String filePath = paths[0] + paths[1];
      FileState fstate = getFileState(filePath,dbCtx,true);

      //  Check if the top level file exists
      
      if ( fstate != null && fstate.fileExists() == true) {
        
        //  Get the top level file details
      
        DBFileInfo dbInfo = getFileDetails(name, dbCtx, fstate);
        
        if ( dbInfo != null) {

          //  Checkif the streams list is cached
          
          StreamInfoList streams = (StreamInfoList) fstate.findAttribute(DBStreamList);
          
          //  Get the list of available streams

          if ( streams == null) {
            
            //  Load the streams list for the file
            
            streams = loadStreamList(fstate, dbInfo, dbCtx, true);
            
            //  Cache the streams list
            
            if ( streams != null)
              fstate.addAttribute(DBStreamList, streams);
          }
          
          if ( streams != null && streams.numberOfStreams() > 0) {
            
            //  Check if the required stream exists
            
            if ( streams.findStream(paths[2]) != null)
              fileSts = FileStatus.FileExists;
          }
        }
      }

      //  Debug
  
      if ( Debug.EnableInfo && hasDebug())
        Debug.println("DB fileExists() name=" + filePath + ", stream=" + paths[2] + ", fileSts=" + FileStatus.asString(fileSts));
    }
    else {

      //  Get, or create, the file state for the path
      
      FileState fstate = getFileState( name, dbCtx, true);
  
      //  Check if the file exists status has been cached
      
      fileSts = fstate.getFileStatus();
      
      if ( fstate.getFileStatus() == FileStatus.Unknown) {
        
        //  Get the file details
        
        DBFileInfo dbInfo = getFileDetails(name,dbCtx,fstate);
        if ( dbInfo != null) {
          if ( dbInfo.isDirectory() == true)
            fileSts = FileStatus.DirectoryExists;
          else
            fileSts = FileStatus.FileExists;
        }
        else {
          
          //  Indicate that the file does not exist
          
          fstate.setFileStatus( FileStatus.NotExist);
          fileSts = FileStatus.NotExist;
        }
        
        //  Debug
    
        if ( Debug.EnableInfo && hasDebug())
          Debug.println("DB fileExists() name=" + name + ", fileSts=" + FileStatus.asString(fileSts));
      }
      else {
        
        //  DEBUG
        
        if ( Debug.EnableInfo && hasDebug())
          Debug.println("@@ Cache hit - fileExists() name=" + name + ", fileSts=" + FileStatus.asString(fileSts));
      }
    }
    
    //  Return the file exists status
    
    return fileSts;
  }

  /**
   * Flush buffered data for the specified file
   * 
   * @param sess  Session details
   * @param tree  Tree connection
   * @param file  Network file
   * @exception IOException
   */
  public void flushFile(SrvSession sess, TreeConnection tree, NetworkFile file)
    throws IOException {
    
    //  Debug
    
    if ( Debug.EnableInfo && hasDebug())
      Debug.println("DB flushFile()");
      
    //  Flush any buffered data
    
    file.flushFile();
  }

  /**
   * Return file information about the specified file
   * 
   * @param sess  Session details
   * @param tree  Tree connection
   * @param name  File name
   * @return SMBFileInfo
   * @exception IOException
   */
  public FileInfo getFileInformation(SrvSession sess, TreeConnection tree, String name)
    throws IOException {

    //  Check for the null file name
    
    if (name == null)
      return null;

    //  Access the JDBC context

    DBDeviceContext dbCtx = (DBDeviceContext) tree.getContext();

    // Check if the database is online
    
    if ( dbCtx.getDBInterface().isOnline() == false)
      throw new DiskOfflineException( "Database is offline");
    
    //  Check if the path is a file stream
    
    FileState fstate = null;
    FileInfo finfo = null;
    
    if ( FileName.containsStreamName(name)) {

      //  Check if there is an active file state for the stream
      
      fstate = getFileState(name,dbCtx,true);
      
      if ( fstate != null) {
        
        //  Check if the file information is available
        
        finfo = (FileInfo) fstate.findAttribute(FileState.FileInformation);
      }

      //  If the cached file information is not available then create it
      
      if ( finfo == null) {     

        //  Split the path into directory, file and stream name components
        
        String[] paths = FileName.splitPathStream(name);    
  
        //  Get, or create, the file state for main file path
        
        String filePath = paths[0] + paths[1];
        FileState parent = getFileState(filePath,dbCtx,true);
  
        //  Check if the top level file exists
        
        if ( parent != null && parent.fileExists() == true) {
          
          //  Get the top level file details
        
          DBFileInfo dbInfo = getFileDetails(name,dbCtx,parent);
          
          if ( dbInfo != null) {
  
            //  Get the list of available streams
            
            StreamInfoList streams = loadStreamList(parent, dbInfo, dbCtx, true);
            
            if ( streams != null && streams.numberOfStreams() > 0) {
              
              //  Get the details for the stream, if the information is valid copy it to a file information
              //  object
              
              StreamInfo sInfo = streams.findStream(paths[2]);
              
              if ( sInfo != null) {
                
                //  Create a file information object, copy the stream details to it
                
                finfo = new DBFileInfo(paths[1], name, dbInfo.getFileId(), dbInfo.getDirectoryId());
                finfo.setFileId(sInfo.getFileId());
                finfo.setFileSize(sInfo.getSize());
                
                //  Use the parent files timestamps for now
                
                finfo.setCreationDateTime(dbInfo.getCreationDateTime());
                finfo.setAccessDateTime(dbInfo.getAccessDateTime());
                finfo.setModifyDateTime(dbInfo.getModifyDateTime());
                
                //  Attach to the file state
                
                fstate.addAttribute(FileState.FileInformation, finfo);
                
                //  DEBUG
                
                if ( Debug.EnableInfo && hasDebug())
                  Debug.println("getFileInformation() stream=" + name + ", info=" + finfo);
              }
            }
          }
        }
      }
    }
    else {

      //  Get, or create, the file state for the path
      
      fstate = getFileState(name, dbCtx, true);
      
      //  Get the file details for the path
      
      DBFileInfo dbInfo = getFileDetails(name, dbCtx, fstate);
  
      //  Set the full file/path name
      
      if ( dbInfo != null)
        dbInfo.setFullName(name);
      finfo = dbInfo;
    }

    //  DEBUG
    
    if ( Debug.EnableInfo && hasDebug() && finfo != null)
      Debug.println("getFileInformation info=" + finfo.toString());

    //  Return the file information

    return finfo;
  }

  /**
   * Determine if the disk device is read-only.
   *
   * @param sess  Session details
   * @param ctx   Device context
   * @return true if the device is read-only, else false
   * @exception IOException  If an error occurs.
   */
  public boolean isReadOnly(SrvSession sess, DeviceContext ctx)
    throws IOException {
    return false;
  }

  /**
   * Open a file
   * 
   * @param sess    Session details
   * @param tree    Tree connection
   * @param params  File open parameters
   * @return NetworkFile
   * @exception IOException
   */
  public NetworkFile openFile(SrvSession sess, TreeConnection tree, FileOpenParams params)
    throws IOException {

    //  Access the JDBC context

    DBDeviceContext dbCtx = (DBDeviceContext) tree.getContext();

    // Check if the database is online
    
    if ( dbCtx.getDBInterface().isOnline() == false)
      throw new DiskOfflineException( "Database is offline");
    
    //  Set the session if the file open parameters
    
    params.setSession( sess);
    
    //  Get, or create, the file state
    
    FileState fstate = getFileState(params.getPath(), dbCtx, true);
    
    //  Check if we are opening a stream associated with the main file
    
    if ( fstate != null && params.isStream()) {
      
      //  Open an NTFS stream
      
      return openStream(params, fstate, dbCtx);
    }
    
    //  Get the file name
    
    String[] paths = FileName.splitPath(params.getPath());
    String fname = paths[1];
    
    //  Check if the file name is too long
    
    if ( fname != null && fname.length() > MaxFileNameLen)
      throw new FileNameException("File name too long, " + fname);
    
    //  Get the file information
    
    DBFileInfo finfo = getFileDetails(params.getPath(), dbCtx, fstate);
    
    if (finfo == null)
      throw new AccessDeniedException();

    //  If retention is enabled get the expiry date/time
    
    if ( dbCtx.hasRetentionPeriod()) {
      try {
        
        //  Get the file retention expiry date/time
        
        RetentionDetails retDetails = dbCtx.getDBInterface().getFileRetentionDetails(finfo.getDirectoryId(), finfo.getFileId());
        if ( retDetails != null)
          fstate.setRetentionExpiryDateTime( retDetails.getEndTime());
      }
      catch (DBException ex) {
        throw new AccessDeniedException("Retention error, " + ex.getMessage());
      }
    }
    
    //  Check if the file shared access indicates exclusive file access
    
    if ( params.getSharedAccess() == SharingMode.NOSHARING && fstate.getOpenCount() > 0)
      throw new FileSharingException("File already open, " + params.getPath());

    //  Check if the file is read-only and write access has been requested
    
    if (( params.isReadWriteAccess() || params.isWriteOnlyAccess())) {
      
      //  Check if the file is read-only
      
      if ( finfo.isReadOnly())
        throw new AccessDeniedException("Read-only file");
      else if ( fstate.hasActiveRetentionPeriod())
        throw new AccessDeniedException("File retention active");
    }

    //  Create a JDBC network file and open the top level file

    if ( Debug.EnableInfo && hasDebug())
      Debug.println("DB openFile() name=" + params.getPath());
      
    DBNetworkFile jdbcFile = (DBNetworkFile) dbCtx.getFileLoader().openFile(params, finfo.getFileId(), 0,
                                                                                  finfo.getDirectoryId(), false, finfo.isDirectory());

    jdbcFile.setFileDetails(finfo);
    jdbcFile.setFileState(fstate);
        
    //  Set the file owner
    
    if ( sess != null)
      jdbcFile.setOwnerSessionId(sess.getUniqueId());
      
    //  Update the file open count
    
    fstate.setFileStatus( finfo.isDirectory() ? FileStatus.DirectoryExists : FileStatus.FileExists);
    fstate.incrementOpenCount();
    
    //  Return the network file
        
    return jdbcFile;
  }

  /**
   * Read a block of data from a file
   * 
   * @param sess  Session details
   * @param tree  Tree connection
   * @param file  Network file
   * @param buf   Buffer to return data to
   * @param bufPos Starting position in the return buffer
   * @param siz   Maximum size of data to return
   * @param pos   File offset to read data
   * @return Number of bytes read
   * @exception IOException
   */
  public int readFile(SrvSession sess, TreeConnection tree, NetworkFile file, byte[] buf, int bufPos, int siz, long pos)
    throws IOException {
      
    //  Debug
      
    if ( Debug.EnableInfo && hasDebug())
      Debug.println("DB readFile() filePos=" + pos + ", len=" + siz);

    //  Access the JDBC context

    DBDeviceContext dbCtx = (DBDeviceContext) tree.getContext();

    // Check if the database is online
    
    if ( dbCtx.getDBInterface().isOnline() == false)
      throw new DiskOfflineException( "Database is offline");

    //  Check that the network file is our type

    int rxsiz = 0;
    
    if (file instanceof DBNetworkFile) {

      //  Access the JDBC network file
      
      DBNetworkFile jfile = (DBNetworkFile) file;

      //  Check if there are any locks on the file
      
      //  Check if there are any locks on the file
      
      if ( jfile.hasFileState() && jfile.getFileState().hasActiveLocks()) {
        
        //  Check if this session has write access to the required section of the file
        
        if ( jfile.getFileState().canReadFile( pos, siz, sess.getProcessId()) == false)
          throw new LockConflictException();
      }
      
      //  Debug
      
      if ( jfile.getFileState().getOpenCount() == 0)
        Debug.println("**** readFile() Open Count Is ZERO ****");
      
      //  Read from the file

      rxsiz = jfile.readFile(buf, siz, bufPos, pos);
      
      //  Check if we have reached the end of file
      
      if ( rxsiz == -1)
        rxsiz = 0;
    }

    //  Return the actual read length

    return rxsiz;
  }

  /**
   * Rename a file
   * 
   * @param sess  Session details
   * @param tree  Tree connection
   * @param oldName Existing file name
   * @param newName New file name
   * @exception IOException
   */
  public void renameFile(SrvSession sess, TreeConnection tree, String oldName, String newName)
    throws IOException {
    
    //  Debug
    
    if ( Debug.EnableInfo && hasDebug())
      Debug.println("DB renameFile() from=" + oldName + " to=" + newName);

    //  Access the JDBC context

    DBDeviceContext dbCtx = (DBDeviceContext) tree.getContext();

    // Check if the database is online
    
    if ( dbCtx.getDBInterface().isOnline() == false)
      throw new DiskOfflineException( "Database is offline");
    
    //  Get, or create, the file state for the existing file
    
    FileState fstate = getFileState(oldName, dbCtx, true);
    
    try {

      //  Get the file name
      
      String[] paths = FileName.splitPath( newName);
      String fname = paths[1];
      
      //  Check if the file name is too long
      
      if ( fname != null && fname.length() > MaxFileNameLen)
        throw new FileNameException("Destination name too long, " + fname);
      
      //  Check if the file is within an active retention period
      
      getRetentionDetailsForState( dbCtx, fstate);
      
      if ( fstate.hasActiveRetentionPeriod())
        throw new AccessDeniedException("File retention active");

      //  Get the file id of the existing file
      
      int fid = fstate.getFileId();
      int dirId = -1;
      
      if ( fid == -1) {
        
        //  Split the current path string and find the file id of the existing file/directory
        
        dirId = findParentDirectoryId(dbCtx, oldName, true);
        if ( dirId == -1)
          throw new FileNotFoundException(oldName);
    
        //  Get the current file/directory name
  
        String[] oldPaths = FileName.splitPath(oldName);
        fname = oldPaths[1];
        
        //  Get the file id
        
        fid = getFileId(oldName, fname, dirId, dbCtx);
        if ( fid == -1)
          throw new FileNotFoundException(oldName);
          
        //  Update the file state
        
        fstate.setFileId(fid);
      }

      //  Get the existing file/directory details
      
      DBFileInfo curInfo = getFileDetails(oldName, dbCtx, fstate);
      if ( dirId == -1 && curInfo != null)
        dirId = curInfo.getDirectoryId();
      
      //  Check if the new name file/folder already exists
      
      DBFileInfo newInfo = getFileDetails(newName, dbCtx);
      if ( newInfo != null)
        throw new FileExistsException("Rename to file/folder already exists," + newName);
        
      //  Check if the loader handles rename requests, an exception may be thrown by the loader
      //  to prevent the file/directory rename.
      
      if ( dbCtx.getFileLoader() instanceof NamedFileLoader) {
        
        //  Rename the file/directory
        
        NamedFileLoader namedLoader = (NamedFileLoader) dbCtx.getFileLoader();
        namedLoader.renameFileDirectory(oldName, fid, newName, curInfo.isDirectory());
      }
      
      //  Get the new file/directory name
      
      int newDirId = findParentDirectoryId(dbCtx, newName, true);
      if ( newDirId == -1)
        throw new FileNotFoundException(newName);
      String[] newPaths = FileName.splitPath(newName);
      String newFname = newPaths[1];

      //  Rename the file/folder, this may also link the file/folder to a new parent directory
      
      dbCtx.getDBInterface().renameFileRecord(dirId, fid, newFname, newDirId);

      //  Update the file state with the new file name/path
      
      dbCtx.getStateCache().renameFileState(newName, fstate, curInfo.isDirectory());

      // Remove any cached file information
      
      fstate.removeAttribute(FileState.FileInformation);
    }
    catch (DBException ex) {
      throw new FileNotFoundException(oldName);
    }
  }

  /**
   * Seek to the specified point within a file
   * 
   * @param sess  Session details
   * @param tree  Tree connection
   * @param file  Network file
   * @param pos   New file position
   * @param typ   Seek type
   * @return  New file position
   * @exception IOException
   */
  public long seekFile(SrvSession sess, TreeConnection tree, NetworkFile file, long pos, int typ)
    throws IOException {
    
    //  Debug
    
    if ( Debug.EnableInfo && hasDebug())
      Debug.println("DB seekFile()");

    //  Check that the network file is our type

    long newpos = 0;
    
    if (file instanceof DBNetworkFile) {

      //  Seek within the file

      DBNetworkFile jfile = (DBNetworkFile) file;
      newpos = jfile.seekFile(pos, typ);
    }

    //  Return the new file position

    return newpos;
  }

  /**
   * Set file information
   * 
   * @param sess  Session details
   * @param tree  Tree connection
   * @param name  File name
   * @param info  File information to be set
   * @exception IOException
   */
  public void setFileInformation(SrvSession sess, TreeConnection tree, String name, FileInfo info)
    throws IOException {
      
    //  Debug
    
    if ( Debug.EnableInfo && hasDebug())
      Debug.println("DB setFileInformation() name=" + name + ", info=" + info.toString());

    //  Access the JDBC context

    DBDeviceContext dbCtx = (DBDeviceContext) tree.getContext();

    // Check if the database is online
    
    if ( dbCtx.getDBInterface().isOnline() == false) {
      
      // Check if the delete on close flag is being set
      
      if ( info.getSetFileInformationFlags() == FileInfo.SetDeleteOnClose) {
        
        // Just return, file object will be marked for delete on close
        
        return;
      }
      else
        throw new DiskOfflineException( "Database is offline");
    }
    
    //  Get, or create, the file state
    
    FileState fstate = getFileState(name, dbCtx, true);
    
    //  Get the file details
    
    DBFileInfo dbInfo = getFileDetails( name, dbCtx, fstate);
    if ( dbInfo == null)
      throw new FileNotFoundException(name);

    try {

      //  Check if the file is within an active retention period
      
      getRetentionDetailsForState( dbCtx, fstate);
      
      if ( fstate.hasActiveRetentionPeriod())
        throw new AccessDeniedException("File retention active");
      
      //  Check if the loader handles set file information requests, an exception may be thrown by the loader
      //  to prevent the update
      
      if ( dbCtx.getFileLoader() instanceof NamedFileLoader) {
        
        //  Set the file information
        
        NamedFileLoader namedLoader = (NamedFileLoader) dbCtx.getFileLoader();
        namedLoader.setFileInformation(name, dbInfo.getFileId(), info);
      }

      //  Check if the inode change date/time has been set

      if ( info.hasChangeDateTime() == false) {
        info.setChangeDateTime(System.currentTimeMillis());
        if ( info.hasSetFlag(FileInfo.SetChangeDate) == false)
          info.setFileInformationFlags(info.getSetFileInformationFlags() + FileInfo.SetChangeDate);
      }
              
      //  Update the file information
      
      dbCtx.getDBInterface().setFileInformation(dbInfo.getDirectoryId(), dbInfo.getFileId(), info);
      
      //  Copy the updated values to the file state
      
      if ( info.hasSetFlag(FileInfo.SetFileSize))
        dbInfo.setFileSize(info.getSize());
      
      if ( info.hasSetFlag(FileInfo.SetAllocationSize))
        dbInfo.setAllocationSize(info.getAllocationSize());
      
      if ( info.hasSetFlag(FileInfo.SetAccessDate))
        dbInfo.setAccessDateTime(info.getAccessDateTime());
      
      if ( info.hasSetFlag(FileInfo.SetCreationDate))
        dbInfo.setAccessDateTime(info.getCreationDateTime());
      
      if ( info.hasSetFlag(FileInfo.SetModifyDate))
        dbInfo.setAccessDateTime(info.getModifyDateTime());
      
      if ( info.hasSetFlag(FileInfo.SetChangeDate))
        dbInfo.setAccessDateTime(info.getChangeDateTime());

      if ( info.hasSetFlag(FileInfo.SetGid))
        dbInfo.setGid(info.getGid());
      
      if ( info.hasSetFlag(FileInfo.SetUid))
        dbInfo.setUid(info.getUid());
      
      if ( info.hasSetFlag(FileInfo.SetMode))
        dbInfo.setMode(info.getMode());
      
      if ( info.hasSetFlag(FileInfo.SetAttributes))
        dbInfo.setFileAttributes(info.getFileAttributes());
      
      //  Update the file state
      
      fstate.setFileId(dbInfo.getFileId());
    }
    catch (DBException ex) {
      throw new IOException();
    }
  }

  /**
   * Start a search of the file system
   * 
   * @param sess SrvSession
   * @param tree TreeConnection
   * @param searchPath String
   * @param attrib int
   * @return SearchContext
   * @exception FileNotFoundException
   */
  public SearchContext startSearch(SrvSession sess, TreeConnection tree, String searchPath, int attrib)
    throws FileNotFoundException {

    //  Access the JDBC context

    DBDeviceContext dbCtx = (DBDeviceContext) tree.getContext();

    // Check if the database is online
    
    if ( dbCtx.getDBInterface().isOnline() == false)
      throw new FileNotFoundException( "Database is offline");
    
    //  Prepend a leading slash to the path if not on the search path
    
    if ( searchPath.startsWith("\\") == false)
      searchPath = "\\" + searchPath;
      
    //  Get the directory id for the last directory in the path
    
    int dirId = findParentDirectoryId(dbCtx,searchPath,true);
    if ( dirId == -1)
      throw new FileNotFoundException("Invalid path");

    //  Start the search
    
    SearchContext search = null;
    
    try {
    
      //  Check if the search path is a none wildcard search, the file information may be in the
      //  state cache
      
      if ( WildCard.containsWildcards( searchPath) == false) {
        
        //  Check if there is a file state for the search path
        
        FileState searchState = getFileState( searchPath, dbCtx, false);
        if ( searchState != null && searchState.fileExists() == true) {
          
          //  Check if the file state has the file information attached
          
          DBFileInfo finfo = (DBFileInfo) searchState.findAttribute(FileState.FileInformation);
          
          if ( finfo != null) {
            
            //  Create a single file search context using the cached file information
            
            search = new CachedSearchContext( finfo);
            
            //  DEBUG
            
            if ( Debug.EnableInfo && hasDebug())
              Debug.println("DB StartSearch using cached file information, path=" + searchPath + ", info=" + finfo);
          }
        }
      }
      
      //  Start the search via the database interface, if the search is not valid
      
      if ( search == null) {
      
        // Start the search

        DBSearchContext dbSearch = dbCtx.getDBInterface().startSearch(dirId, searchPath, attrib, DBInterface.FileAll, -1);
        
        // Check if files should be marked as offline
        
        dbSearch.setMarkAsOffline( dbCtx.hasOfflineFiles());
        dbSearch.setOfflineFileSize( dbCtx.getOfflineFileSize());
        
        search = dbSearch;  
      }
    }
    catch ( DBException ex) {
      throw new FileNotFoundException();
    }

    //  Return the search context

    return search;
  }

  /**
   * Truncate a file to the specified size
   * 
   * @param sess   Server session
   * @param tree   Tree connection
   * @param file   Network file details
   * @param siz    New file length
   * @exception java.io.IOException The exception description.
   */
  public void truncateFile(SrvSession sess, TreeConnection tree, NetworkFile file, long siz)
    throws java.io.IOException {
      
    //  Debug
    
    if ( Debug.EnableInfo && hasDebug())
      Debug.println("DB truncateFile()");

    //  Check that the network file is our type

    if (file instanceof DBNetworkFile) {

      //  Access the JDBC context

      DBDeviceContext dbCtx = (DBDeviceContext) tree.getContext();

      //  Get the JDBC file
      
      DBNetworkFile jfile = (DBNetworkFile) file;
      
      //  Get, or create, the file state
    
      FileState fstate = jfile.getFileState();
    
      //  Get the file details
    
      DBFileInfo dbInfo = getFileDetails(jfile.getFullName(),dbCtx,fstate);
      if ( dbInfo == null)
        throw new FileNotFoundException(jfile.getFullName());

      //  Check if the new file size is greater than the maximum allowed file size, if enabled
      
      if ( dbCtx.hasMaximumFileSize() && siz > dbCtx.getMaximumFileSize()) {
        
        // Mark the file to delete on close
        
        file.setDeleteOnClose( true);

        // Return a disk full error
        
        throw new DiskFullException( "Write is beyond maximum allowed file size");
      }
      
      //  Keep track of the allocation/release size in case the file resize fails
      
      long allocSize   = 0L;
      long releaseSize = 0L;
      
      //  Check if there is a quota manager

      QuotaManager quotaMgr = dbCtx.getQuotaManager();
            
      if ( dbCtx.hasQuotaManager()) {
        
        //  Determine if the new file size will release space or require space allocating
        
        if ( siz > dbInfo.getAllocationSize()) {
          
          //  Calculate the space to be allocated
          
          allocSize = siz - dbInfo.getAllocationSize();
          
          //  Allocate space to extend the file
          
          quotaMgr.allocateSpace(sess, tree, file, allocSize);
        }
        else {
          
          //  Calculate the space to be released as the file is to be truncated, release the space if
          //  the file truncation is successful
          
          releaseSize = dbInfo.getAllocationSize() - siz;
        }
      }
      
      //  Set the file length

      try {
        jfile.truncateFile(siz);
      }
      catch (IOException ex) {
        
        //  Check if we allocated space to the file
        
        if ( allocSize > 0 && quotaMgr != null)
          quotaMgr.releaseSpace(sess, tree, file.getFileId(), null, allocSize);

        //  Rethrow the exception
        
        throw ex;       
      }
      
      //  Check if space has been released by the file resizing
      
      if ( releaseSize > 0 && quotaMgr != null)
        quotaMgr.releaseSpace(sess, tree, file.getFileId(), null, releaseSize);
        
      //  Update the file information
      
      if ( allocSize > 0)
        dbInfo.setAllocationSize(dbInfo.getAllocationSize() + allocSize);
      else if ( releaseSize > 0)
        dbInfo.setAllocationSize(dbInfo.getAllocationSize() - releaseSize);
        
      //  Update the last file change date/time
                
      try {

        //  Build the file information to set the change date/time
        
        FileInfo finfo = new FileInfo();
        
        finfo.setChangeDateTime(System.currentTimeMillis());
        finfo.setFileInformationFlags(FileInfo.SetChangeDate);
        
        //  Set the file change date/time
        
        dbCtx.getDBInterface().setFileInformation(jfile.getDirectoryId(), jfile.getFileId(), finfo);
        
        //  Update the cached file information
        
        dbInfo.setChangeDateTime(finfo.getChangeDateTime());
        dbInfo.setAllocationSize(siz);
      }
      catch (Exception ex) {        
      }
    }
  }

  /**
   * Write a block of data to a file
   * 
   * @param sess  Session details
   * @param tree  Tree connection
   * @param file  Network file
   * @param buf   Data to be written
   * @param bufoff Offset of data within the buffer
   * @param siz   Number of bytes to be written
   * @param fileoff Offset within the file to start writing the data
   */
  public int writeFile(SrvSession sess,TreeConnection tree,NetworkFile file,byte[] buf,int bufoff,int siz,long fileoff)
    throws IOException {
      
    //  Debug
    
    if ( Debug.EnableInfo && hasDebug())
      Debug.println("DB writeFile()");

    //  Access the JDBC context

    DBDeviceContext dbCtx = (DBDeviceContext) tree.getContext();

    // Check if the database is online
    
    if ( dbCtx.getDBInterface().isOnline() == false)
      throw new DiskOfflineException( "Database is offline");

    //  Check that the network file is our type

    if (file instanceof DBNetworkFile) {

      //  Access the JDBC network file

      DBNetworkFile jfile = (DBNetworkFile) file;

      //  Check if there are any locks on the file
      
      if ( jfile.hasFileState() && jfile.getFileState().hasActiveLocks()) {
        
        //  Check if this session has write access to the required section of the file
        
        if ( jfile.getFileState().canWriteFile( fileoff, siz, sess.getProcessId()) == false)
          throw new LockConflictException();
      }
      
      // Check if there is a maximum file size, if so then check if the write is beyond the allowed file size
      
      if ( dbCtx.hasMaximumFileSize() && (fileoff + siz) > dbCtx.getMaximumFileSize()) {
        
        // Mark the file to delete on close
        
        file.setDeleteOnClose( true);

        // Return a disk full error
        
        throw new DiskFullException( "Write is beyond maximum allowed file size");
      }
      
      //  Check if there is a quota manager
      
      QuotaManager quotaMgr = dbCtx.getQuotaManager();
      
      if ( quotaMgr != null) {
        
        //  Get the file information
        
        DBFileInfo finfo = getFileDetails(jfile.getFullName(), dbCtx, jfile.getFileState());
        if ( finfo == null)
          throw new FileNotFoundException(jfile.getFullName());
        
        //  Check if the file requires extending
        
        long extendSize = 0L;
        long endOfWrite = fileoff + siz;
        
        if ( endOfWrite > finfo.getAllocationSize()) {
          
          //  Calculate the amount the file must be extended

          extendSize = endOfWrite - finfo.getAllocationSize();
          
          //  Allocate space for the file extend
          
          quotaMgr.allocateSpace(sess, tree, file, extendSize);
        }
                
        //  Write to the file
        
        try {
          jfile.writeFile(buf, siz, bufoff, fileoff);
        }
        catch (IOException ex) {
        
          //  Check if we allocated space to the file
        
          if ( extendSize > 0 && quotaMgr != null)
            quotaMgr.releaseSpace(sess, tree, file.getFileId(), null, extendSize);

          //  Rethrow the exception
        
          throw ex;       
        }

        //  Update the file information
      
        if ( extendSize > 0)
          finfo.setAllocationSize(endOfWrite);
      }
      else {      

        //  Write to the file
        
        jfile.writeFile(buf, siz, bufoff, fileoff);
      }
    }

    //  Return the actual write length

    return siz;
  }

  /**
   * Parse/validate the parameter string and create a device context for this share
   * 
   * @param shareName String
   * @param args ConfigElement
   * @return DeviceContext
   * @exception DeviceContextException
   */
  public DeviceContext createContext(String shareName, ConfigElement args)
    throws DeviceContextException {

    //  Check the arguments

    if (args.getChildCount() < 3)
      throw new DeviceContextException("Not enough context arguments");

    //  Check for the debug enable flags
    
    if ( args.getChild("Debug") != null)
      m_debug = true;

    //  Create the database device context

    DBDeviceContext ctx = new DBDeviceContext(args);

    //  Return the database device context

    return ctx;
  }


  /**
   * Get the file id for a file
   * 
   * @param path String
   * @param dbCtx DBDeviceContext
   * @return DBFileInfo
   */
  protected final DBFileInfo getFileDetails(String path, DBDeviceContext dbCtx) {
    return getFileDetails(path, dbCtx, null);
  }
  
  /**
   * Get the file id for a file
   * 
   * @param path String
   * @param dbCtx DBDeviceContext
   * @param fstate FileState
   * @return DBFileInfo
   */
  protected final DBFileInfo getFileDetails(String path, DBDeviceContext dbCtx, FileState fstate) {

    //  Check if the file details are attached to the file state
    
    if ( fstate != null) {
      
      //  Return the file information
      
      DBFileInfo finfo = (DBFileInfo) fstate.findAttribute(FileState.FileInformation);
      if ( finfo != null)
        return finfo;
    }
    
    //  Check for the root directory
    
    if ( path.length() == 0 || path.compareTo("\\") == 0) {
      
      //  Get the root directory information from the device context

      DBFileInfo rootDir = dbCtx.getRootDirectoryInfo();
      
      //  Mark the directory as existing
      
      if ( fstate != null)
        fstate.setFileStatus( FileStatus.DirectoryExists);
      return rootDir;
    }
    
    //  Split the path string and find the parent directory id
    
    int dirId = findParentDirectoryId(dbCtx,path,true);
    if ( dirId == -1)
      return null;

    //  Get the file name
    
    String[] paths = FileName.splitPathStream(path);
    String fname = paths[1];
    
    String filePath = null;
    
    if ( paths[0] != null && paths[0].endsWith(FileName.DOS_SEPERATOR_STR) == false)
      filePath = paths[0] + FileName.DOS_SEPERATOR_STR + paths[1];
    else
      filePath = paths[0] + paths[1];
      
    //  Get the file id for the specified file

    int fid = getFileId(filePath, fname, dirId, dbCtx);
    if (fid == -1)
      return null;
    
    //  Create the file information
    
    DBFileInfo finfo = getFileInfo( filePath, dirId, fid, dbCtx);
    if ( finfo != null && fstate != null) {
      
      //  Set various file state details
      
      fstate.setFileStatus( finfo.isDirectory() ? FileStatus.DirectoryExists : FileStatus.FileExists);
      fstate.setFileId(finfo.getFileId());
      
      //  Set the file name
      
      finfo.setFileName( fname);
      finfo.setFullName(path);
      
      // check if files should be marked as offline
      
      if ( dbCtx.hasOfflineFiles() && finfo.hasAttribute( FileAttribute.NTOffline) == false) {
        if ( dbCtx.getOfflineFileSize() == 0 || finfo.getSize() >= dbCtx.getOfflineFileSize())
          finfo.setFileAttributes( finfo.getFileAttributes() + FileAttribute.NTOffline);
      }
    }

    //  Check if the path is a file stream
    
    if ( paths[2] != null) {
      
      //  Get the file information for the stream
      
      finfo = getStreamInfo(fstate, paths, dbCtx);
    }
    
    //  Return the file/stream information
    
    return finfo;
  }
  
  /**
   * Get the file id for a file
   * 
   * @param path String
   * @param name String
   * @param dirId int
   * @param dbCtx DBDeviceContext
   * @return int
   */
  protected final int getFileId(String path, String name, int dirId, DBDeviceContext dbCtx) {

    //  Check if the file is in the cache
    
    FileStateCache cache = dbCtx.getStateCache();
    FileState state = null;
    
    if ( cache != null) {
      
      //  Search for the file state
      
      state = cache.findFileState(path);
      if ( state != null) {

        //  Checkif the file id is cached
        
        if ( state.getFileId() != -1) {
        
          //  Debug
          
          if ( Debug.EnableInfo && hasDebug())
            Debug.println("@@ Cache hit - getFileId() name=" + name);
          
          //  Return the file id
          
          return state.getFileId();
        }
        else if ( state.getFileStatus() == FileStatus.NotExist) {
          
          //  DEBUG
          
          if ( Debug.EnableInfo && hasDebug())
            Debug.println("@@ Cache hit - getFileStatus() name=" + name + ", sts=NotExist");
          
          //  Indicate that the file does not exist
          
          return -1;
        }
      }
    }
    
    //  Get the file id from the database
    
    int fileId = -1;
    
    try {
    
      //  Get the file id
      
      fileId = dbCtx.getDBInterface().getFileId(dirId, name, false, false);
    }
    catch (DBException ex) {
    }

    //  Update the cache entry, if available
    
    if ( state != null)
      state.setFileId(fileId);
      
    //  Return the file id, or -1 if the file was not found

    return fileId;
  }

  /**
   * Load the retention details for a file state, if enabled
   * 
   * @param dbCtx DBDeviceContext
   * @param fstate FileState
   * @exception DBException
   */
  protected final void getRetentionDetailsForState(DBDeviceContext dbCtx, FileState fstate)
    throws DBException {

    //  If retention is enabled get the expiry date/time
    
    if ( dbCtx.hasRetentionPeriod()) {
        
      //  Get the file retention expiry date/time
      
      RetentionDetails retDetails = dbCtx.getDBInterface().getFileRetentionDetails(-1, fstate.getFileId());
      if ( retDetails != null)
        fstate.setRetentionExpiryDateTime( retDetails.getEndTime());
    }
  }
  
  /**
   * Find the directory id for the parent directory in the specified path
   * 
   * @param ctx DBDeviceContext
   * @param path String
   * @param filePath boolean
   * @return int
   */
  protected final int findParentDirectoryId(DBDeviceContext ctx, String path, boolean filePath) {

    //  Split the path
    
    String[] paths = null;
    
    if ( path != null && path.startsWith("\\")) {

      //  Split the path
      
      paths = FileName.splitPath(path);
    }
    else {
      
      //  Add a leading slash to the path before parsing
      
      paths = FileName.splitPath("\\" + path);
    }
    
    if ( paths[0] != null && paths[0].compareTo("\\") == 0 || paths[0].startsWith("\\") == false)
      return 0;
      
    //  Check if the file is in the cache
    
    FileStateCache cache = ctx.getStateCache();
    FileState state = null;
    
    if ( cache != null) {
      
      //  Search for the file state
      
      state = cache.findFileState(paths[0]);
      if ( state != null && state.getFileId() != -1) {
        
        //  Debug
        
        if ( Debug.EnableInfo && hasDebug())
          Debug.println("@@ Cache hit - findParentDirectoryId() path=" + paths[0]);
        
        //  Return the file id
        
        return state.getFileId();
      }
    }

    //  Get the directory id list
    
    int[] ids = findParentDirectoryIdList(ctx,path,filePath);
    if ( ids == null)
      return -1;
      
    //  Check for the root directory id only
    
    if ( ids.length == 1)
      return ids[0];
      
    //  Return the directory id of the last directory
    
    int idx = ids.length - 1;
    if ( filePath == true && ids[ids.length - 1] == -1)
      idx--;
      
    return ids[idx];
  }
      
  /**
   * Find the directory ids for the specified path list
   * 
   * @param ctx DBDeviceContext
   * @param path String
   * @param filePath boolean
   * @return int[]
   */
  protected final int[] findParentDirectoryIdList(DBDeviceContext ctx, String path, boolean filePath) {

    //  Validate the paths and check for the root path
    
    String[] paths = FileName.splitAllPaths(path);
    
    if ( paths == null || paths.length == 0)
      return null;
    if ( paths[0].compareTo("*.*") == 0 || paths[0].compareTo("*") == 0 ||
        (filePath == true && paths.length == 1)) {
      int[] ids = { 0 };
      return ids;
    }
    if ( paths[0].startsWith("\\")) {
      
      //  Trim the leading slash from the first path
      
      paths[0] = paths[0].substring(1);
    }
      
    //  Find the directory id by traversing the list of directories
    
    int endIdx = paths.length - 1;
    if ( filePath == true)
      endIdx--;
      
    //  If there are no paths to check then return the root directory id
    
    if ( endIdx <= 1 && paths[0].length() == 0) {
      int[] ids = new int[1];
      ids[0] = 0;
      return ids;
    }

    //  Allocate the directory id list
    
    int[] ids = new int[paths.length];
    for ( int i = 0; i < ids.length; i++)
      ids[i] = -1;
      
    //  Build up the current path as we traverse the list
    
    StringBuffer pathStr = new StringBuffer("\\");
    
    //  Check for paths in the file state cache
    
    FileStateCache cache = ctx.getStateCache();
    FileState fstate = null;

    //  Traverse the path list, initialize the directory id to the root id
    
    int dirId = 0;
    int parentId = -1;
    int idx = 0;

    try {
      
      //  Loop until the end of the path list

      while ( idx <= endIdx) {
        
        //  Get the current path, and add to the full path string
        
        String curPath = paths[idx];
        pathStr.append(curPath);
        
        //  Check if there is a file state for the current path
        
        fstate = cache.findFileState(pathStr.toString());
        
        if ( fstate != null && fstate.getFileId() != -1) {
          
          //  Get the file id from the cached information

          ids[idx] = fstate.getFileId();
          parentId = dirId;
          dirId    = ids[idx];
        }
        else {
          
          //  Search for the current directory in the database

          parentId = dirId;
          dirId = ctx.getDBInterface().getFileId(dirId, curPath, true, true);
          
          if ( dirId != -1) {
            
            //  Get the next directory id

            ids[idx] = dirId;
            
            //  Check if we have a file state, or create a new file state for the current path
            
            if ( fstate != null) {
              
              //  Set the file id for the file state
              
              fstate.setFileId(dirId);
            }
            else {
              
              //  Create a new file state for the current path
              
              fstate = cache.findFileState(pathStr.toString(), true);
  
              //  Get the file information
              
              DBFileInfo finfo = ctx.getDBInterface().getFileInformation(parentId, dirId, DBInterface.FileAll);
              fstate.addAttribute(FileState.FileInformation, finfo);
              fstate.setFileStatus( finfo.isDirectory() ? FileStatus.DirectoryExists : FileStatus.FileExists);
              fstate.setFileId(dirId);
            }
          }
          else
            return null;
        }
            
        //  Update the path index
        
        idx++;
        
        //  Update the current path string
        
        pathStr.append("\\");
      }
    }
    catch (DBException ex) {
      Debug.println(ex);
      return null;
    }
    
    //  Return the directory id list
        
    return ids;
  }
  
  /**
   * Return file information about the specified file, using the internal file id
   * 
   * @param path String
   * @param dirId int
   * @param fid int
   * @param dbCtx DBDeviceContext
   * @return DBFileInfo
   * @exception IOException
   */
  public DBFileInfo getFileInfo(String path, int dirId, int fid, DBDeviceContext dbCtx) {

    //  Check if the file is in the cache
    
    FileState state = getFileState(path, dbCtx, true);
    
    if ( state != null && state.getFileId() != -1) {
        
      //  Debug
      
      if ( Debug.EnableInfo && hasDebug())
        Debug.println("@@ Cache hit - getFileInfo() path=" + path);
      
      //  Return the file information
      
      DBFileInfo finfo = (DBFileInfo) state.findAttribute(FileState.FileInformation);
      if ( finfo != null)
        return finfo;
    }
    
    //  Get the file information from the database
    
    DBFileInfo finfo = null;
    
    try {
      
      //  Get the file information
      
      finfo = dbCtx.getDBInterface().getFileInformation(dirId, fid, DBInterface.FileAll);
    }
    catch (DBException ex) {
      Debug.println(ex);
      finfo = null;
    }

    //  Set the full path for the file
    
    if ( finfo != null)
      finfo.setFullName(path);
      
    //  Update the cached information, if available
    
    if ( state != null && finfo != null) {
      state.addAttribute(FileState.FileInformation, finfo);
      state.setFileStatus( finfo.isDirectory() ? FileStatus.DirectoryExists : FileStatus.FileExists);
    }
      
    //  Return the file information

    return finfo;
  }

  /**
   * Get the details for a file stream
   * 
   * @param parent FileState
   * @param paths String[]
   * @param dbCtx DBDeviceContext
   * @return DBFileInfo
   */
  public DBFileInfo getStreamInfo(FileState parent, String[] paths, DBDeviceContext dbCtx) {

    //  Check if the file is in the cache

    String streamPath = paths[0] + paths[1] + paths[2];   
    FileState state = getFileState(streamPath, dbCtx, true);
    
    if ( state != null && state.getFileId() != -1) {
        
      //  Debug
      
      if ( Debug.EnableInfo && hasDebug())
        Debug.println("@@ Cache hit - getStreamInfo() path=" + streamPath);
      
      //  Return the file information
      
      DBFileInfo finfo = (DBFileInfo) state.findAttribute(FileState.FileInformation);
      if ( finfo != null)
        return finfo;
    }

    //  DEBUG
    
    if ( Debug.EnableInfo && hasDebug())
      Debug.println("DBDiskDriver getStreamInfo parent=" + parent.getPath() + ", stream=" + paths[2]);
      
    //  Get a list of the streams for the parent file
    
    DBFileInfo finfo = null;
    
    try {
      
      //  Get the list of streams

      StreamInfoList sList = (StreamInfoList) parent.findAttribute(DBStreamList);
      
      if ( sList == null) {
        
        //  No cached stream information, get the list from the database

        sList = dbCtx.getDBInterface().getStreamsList(parent.getFileId(), DBInterface.StreamAll);
        
        //  Cache the information
        
        parent.addAttribute(DBStreamList, sList);
      }

      //  Find the required stream information
      
      if ( sList != null) {
        
        //  Find the required stream information
        
        StreamInfo sInfo = sList.findStream(paths[2]);
        
        //  Convert the stream information to file information
        
        if ( sInfo != null) {
          
          //  Load the stream information
          
          finfo = new DBFileInfo();
          finfo.setFileId(parent.getFileId());
        
          //  Copy the stream information
        
          finfo.setFileName(sInfo.getName());
          finfo.setSize(sInfo.getSize());
        
          //  Get the file creation date, or use the current date/time

          if ( sInfo.hasCreationDateTime())
            finfo.setCreationDateTime(sInfo.getCreationDateTime());
        
          //  Get the modification date, or use the current date/time
        
          if ( sInfo.hasModifyDateTime())
            finfo.setModifyDateTime(sInfo.getModifyDateTime());
          else if ( sInfo.hasCreationDateTime())
            finfo.setModifyDateTime(sInfo.getCreationDateTime());
        
          //  Get the last access date, or use the current date/time
        
          if ( sInfo.hasAccessDateTime())
            finfo.setAccessDateTime(sInfo.getAccessDateTime());
          else if ( sInfo.hasCreationDateTime())
            finfo.setAccessDateTime(sInfo.getCreationDateTime());
        }
      }
    }
    catch ( DBException ex) {
      Debug.println(ex);
      finfo = null;
    }

    //  Set the full path for the file
    
    if ( finfo != null)
      finfo.setFullName(streamPath);
      
    //  Update the cached information, if available
    
    if ( state != null && finfo != null) {
      state.addAttribute(FileState.FileInformation, finfo);
      state.setFileStatus( FileStatus.FileExists);
    }
      
    //  Return the file information for the stream

    return finfo;
  }
  
  /**
   * Get the cached file state for the specified path
   * 
   * @param path String
   * @param ctx DBDeviceContext
   * @param create boolean
   * @return FileState
   */
  protected final FileState getFileState(String path, DBDeviceContext ctx, boolean create) {

    //  Access the file state cache
    
    FileStateCache cache = ctx.getStateCache();
    if ( cache == null)
      return null;

    //  Return the required file state
    
    return cache.findFileState(path, create);
  }

  /**
   * Connection opened to this disk device
   * 
   * @param sess  Server session
   * @param tree  Tree connection
   */
  public void treeOpened(SrvSession sess, TreeConnection tree) {
  }
  
  /**
   * Connection closed to this device
   * 
   * @param sess          Server session
   * @param tree          Tree connection
   */
  public void treeClosed(SrvSession sess, TreeConnection tree) {
  }
  
  /**
   * Check if general debug output is enabled
   * 
   * @return boolean
   */
  protected final boolean hasDebug() {
    return m_debug;
  }
  
  /**
   * Return disk information about a shared filesystem
   * 
   * @param ctx DiskDeviceContext
   * @param info SrvDiskInfo
   * @exception IOException
   */
  public final void getDiskInformation(DiskDeviceContext ctx, SrvDiskInfo info)
    throws IOException {

    //  Check if there is static disk size information available
    
    if ( ctx.hasDiskInformation())
      info.copyFrom(ctx.getDiskInformation());
        
    //  Check that the context is a JDBC context
    
    if ( ctx instanceof DBDeviceContext) {
      
      //  Access the associated file loader class, if it implements the disk size interface then call the loader
      //  to fill in the disk size details
      
      DBDeviceContext dbCtx = (DBDeviceContext) ctx;
      
      if ( dbCtx.getFileLoader() instanceof DiskSizeInterface) {
        
        //  Pass the disk size request to the associated file loader
        
        DiskSizeInterface sizeInterface = (DiskSizeInterface) dbCtx.getFileLoader();
        
        sizeInterface.getDiskInformation(ctx, info);
        
        //  DEBUG
        
        if ( Debug.EnableInfo && hasDebug())
          Debug.println("DBDiskDriver getDiskInformation() handed to file loader");
      }
    }
    
    //  Check if there is a quota manager, if so then get the current free space from the quota manager
    
    if ( ctx.hasQuotaManager()) {
      
      //  Get the free space, in bytes, from the quota manager
      
      long freeSpace = ctx.getQuotaManager().getAvailableFreeSpace();
      
      //  Convert the free space to free units
      
      long freeUnits = freeSpace / info.getUnitSize();
      info.setFreeUnits(freeUnits);
    }
  }
  
  /**
   * Determine if NTFS streams support is enabled. Check if the associated file loader
   * supports NTFS streams.
   * 
   * @param sess SrvSession
   * @param tree TreeConnection
   * @return boolean 
   */
  public boolean hasStreamsEnabled(SrvSession sess, TreeConnection tree) {

    //  Check that the context is a JDBC context
    
    if ( tree.getContext() instanceof DBDeviceContext) {
      
      //  Access the associated file loader class to check if it supports NTFS streams
      
      DBDeviceContext dbCtx = (DBDeviceContext) tree.getContext();
      if ( dbCtx.hasNTFSStreamsEnabled()) {
        
        //  Check if the file loader supports NTFS streams

        return dbCtx.getFileLoader().supportsStreams();
      }
    }
    
    //  Disable streams
    
    return false;
  }

  /**
   * Get the stream information for the specified file stream
   * 
   * @param sess SrvSession
   * @param tree TreeConnection
   * @param streamInfo StreamInfo
   * @return StreamInfo
   * @exception IOException 
   */
  public StreamInfo getStreamInformation(SrvSession sess, TreeConnection tree, StreamInfo streamInfo)
    throws IOException {

    //  DEBUG
    
    if ( Debug.EnableInfo && hasDebug())
      Debug.println("### getStreamInformation() called ###");
    
    // TODO Auto-generated method stub
    return null;
  }

  /**
   * Return the list of available streams for the specified file
   *
   * @param sess SrvSession
   * @param tree TreeConnection
   * @param fileName String
   * @return StreamInfoList
   * @exception IOException  
   */
  public StreamInfoList getStreamList(SrvSession sess, TreeConnection tree, String fileName)
    throws IOException {

    //  Access the JDBC context

    DBDeviceContext dbCtx = (DBDeviceContext) tree.getContext();

    //  Get the file state for the top level file
    
    FileState fstate = getFileState(fileName, dbCtx, true);
    
    //  Check if the file state already has the streams list cached
    
    StreamInfoList streamList = (StreamInfoList) fstate.findAttribute(DBStreamList);
    if ( streamList != null)
      return streamList;
    
    //  Get the main file information and convert to stream information
    
    DBFileInfo finfo = getFileDetails(fileName,dbCtx, fstate);
    
    //  Create the stream list
    
    streamList = new StreamInfoList();
    
    StreamInfo sinfo = new StreamInfo("::$DATA", finfo.getFileId(), 0, finfo.getSize(), finfo.getAllocationSize());
    streamList.addStream(sinfo);

    //  Get the list of streams
    
    StreamInfoList sList = loadStreamList(fstate, finfo, dbCtx, true);
    if ( sList != null) {
      
      //  Copy the stream information to the main list
      
      for ( int i = 0; i < sList.numberOfStreams(); i++) {
        
        //  Add the stream to the main list

        streamList.addStream(sList.getStreamAt(i));
      }
    }

    //  Cache the stream list
    
    fstate.addAttribute(DBStreamList, streamList);
    
    //  Return the stream list
        
    return streamList;
  }
  
  /**
   * Create a new stream with the specified parent file
   * 
   * @param params FileOpenParams
   * @param parent FileState
   * @param dbCtx DBDeviceContext
   * @return NetworkFile
   * @exception IOException
   */
  protected final NetworkFile createStream(FileOpenParams params, FileState parent, DBDeviceContext dbCtx)
    throws IOException {

    //  Get the file information for the parent file
    
    DBFileInfo finfo = getFileDetails(params.getPath(),dbCtx,parent);
    
    if (finfo == null)
      throw new AccessDeniedException();

    //  Get the list of streams for the file
    
    StreamInfoList streamList = (StreamInfoList) parent.findAttribute(DBStreamList);
    if ( streamList == null)
      streamList = loadStreamList(parent, finfo, dbCtx, true);
    
    if ( streamList == null)
      throw new AccessDeniedException();
      
    //  Check if the stream already exists
    
    if ( streamList.findStream(params.getStreamName()) != null)
      throw new FileExistsException("Stream exists, " + params.getFullPath());

    //  Create a new stream record

    DBNetworkFile file = null;

    try {

      //  Create a new stream record
      
      int stid = dbCtx.getDBInterface().createStreamRecord(params.getStreamName(), finfo.getFileId());
      
      //  Create a network file to hold details of the new stream

      file = (DBNetworkFile) dbCtx.getFileLoader().openFile(params, finfo.getFileId(), stid, finfo.getDirectoryId(), true, false);
      file.setFullName(params.getPath());
      file.setStreamId(stid);
      file.setStreamName(params.getStreamName());
      file.setDirectoryId(finfo.getDirectoryId());
      file.setAttributes(params.getAttributes());
      
      //  Create a new file state for the stream
      
      FileState fstate = getFileState(params.getFullPath(), dbCtx, true);
      file.setFileState(fstate);
      fstate.setFileStatus( FileStatus.FileExists);
      fstate.incrementOpenCount();
      
      //  Open the stream file
      
      file.openFile(true);
      
      //  Add an entry to the stream list for the new stream
      
      StreamInfo stream = new StreamInfo(params.getStreamName(), file.getFileId(), stid);
      streamList.addStream(stream);
      
      //  DEBUG
      
      if ( Debug.EnableInfo && hasDebug())
        Debug.println("createStream() file=" + params.getPath() + ", stream=" + params.getStreamName() + ", fid/stid=" + file.getFileId() + "/" + stid);
    }
    catch (DBException ex) {
      if ( Debug.EnableError && hasDebug()) {
        Debug.println("Error: " + ex.toString());
        Debug.println(ex);
      }
    }

    //  If the file/stream is not valid throw an exception
    
    if ( file == null)
      throw new AccessDeniedException(params.getFullPath());
      
    //  Return the network file for the new stream

    return file;
  }
  
  /**
   * Open an existing stream with the specified parent file
   * 
   * @param params FileOpenParams
   * @param parent FileState
   * @param dbCtx DBDeviceContext
   * @return NetworkFile
   * @exception IOException
   */
  protected final NetworkFile openStream(FileOpenParams params, FileState parent, DBDeviceContext dbCtx)
    throws IOException {

    //  Get the file information for the parent file
  
    DBFileInfo finfo = getFileDetails(params.getPath(),dbCtx,parent);
  
    if (finfo == null)
      throw new AccessDeniedException();

    //  Get the list of streams for the file
  
    StreamInfoList streamList = loadStreamList(parent, finfo, dbCtx, true);
    if ( streamList == null)
      throw new AccessDeniedException();
    
    //  Check if the stream exists

    StreamInfo sInfo = streamList.findStream(params.getStreamName());
    
    if ( sInfo == null)
      throw new FileNotFoundException("Stream does not exist, " + params.getFullPath());

    //  Get, or create, a file state for the stream
  
    FileState fstate = getFileState(params.getFullPath(), dbCtx, true);
              
    //  Check if the file shared access indicates exclusive file access
  
    if ( params.getSharedAccess() == SharingMode.NOSHARING && fstate.getOpenCount() > 0)
      throw new FileSharingException("File already open, " + params.getPath());

    //  Set the file information for the stream, using the stream information
    
    DBFileInfo sfinfo = new DBFileInfo(sInfo.getName(), params.getFullPath(), finfo.getFileId(), finfo.getDirectoryId());
    sfinfo.setFileSize(sInfo.getSize());
    
    fstate.addAttribute(FileState.FileInformation, sfinfo);
    
    //  Create a JDBC network file and open the stream

    if ( Debug.EnableInfo && hasDebug())
      Debug.println("DB openStream() file=" + params.getPath() + ", stream=" + sInfo.getName());
    
    DBNetworkFile jdbcFile = (DBNetworkFile) dbCtx.getFileLoader().openFile(params, finfo.getFileId(), sInfo.getStreamId(),
                                                                                  finfo.getDirectoryId(), false, false);

    jdbcFile.setFileState(fstate);
    jdbcFile.setFileSize(sInfo.getSize());

    //  Open the stream file, if not a directory
  
    jdbcFile.openFile(false);

    //  Update the file open count
  
    fstate.setFileStatus( FileStatus.FileExists);
    fstate.incrementOpenCount();
  
    //  Return the network file
      
    return jdbcFile;
  }
  
  /**
   * Close an NTFS stream
   *
   * @param sess  Session details
   * @param tree  Tree connection
   * @param stream  Network file details
   * @exception IOException
   */
  protected final void closeStream(SrvSession sess, TreeConnection tree, NetworkFile stream)
    throws IOException {

    //  Debug
    
    if ( Debug.EnableInfo && hasDebug())
      Debug.println("DB closeStream() file=" + stream.getFullName() + ", stream=" + stream.getStreamName() +
                         ", fid/stid=" + stream.getFileId() + "/" + stream.getStreamId());
    
    //  Access the JDBC context

    DBDeviceContext dbCtx = (DBDeviceContext) tree.getContext();

    //  Close the file

    dbCtx.getFileLoader().closeFile(sess, stream);

    //  Access the JDBC file
    
    DBNetworkFile jdbcFile = null;
    
    if ( stream instanceof DBNetworkFile) {
      
      //  Access the JDBC file
      
      jdbcFile = (DBNetworkFile) stream;

      //  Decrement the open file count
      
      FileState fstate = jdbcFile.getFileState();

      //  Check if the file state is valid, if not then check the main file state cache

      if ( fstate == null) {
        
        //  Check the main file state cache
              
        fstate = getFileState(stream.getFullName(), dbCtx, false);
      }
      else {
        
        //  Decrement the open file count for this file
        
        fstate.decrementOpenCount();
      }

      //  Check if we have a valid file state
            
      if ( fstate != null) {
        
        //  Update the cached file size
        
        FileInfo finfo = (FileInfo) fstate.findAttribute(FileState.FileInformation);
        if ( finfo != null && stream.getWriteCount() > 0) {
          
          //  Update the file size
          
          finfo.setSize(jdbcFile.getFileSize());
          
          //  Update the modified date/time
          
          finfo.setModifyDateTime(jdbcFile.getModifyDate());

          //  DEBUG
          
          if ( Debug.EnableInfo && hasDebug())
            Debug.println("  Stream size=" + jdbcFile.getFileSize() + ", modifyDate=" + jdbcFile.getModifyDate());
        }
      }
    }
    else
      Debug.println("closeFile() Not DBNetworkFile file=" + stream);
      
    //  Check if the stream was opened for write access, if so then update the stream size
    
    if ( stream.getGrantedAccess() != NetworkFile.READONLY && stream.isDirectory() == false &&
         stream.getWriteCount() > 0) {
      
      //  DEBUG
      
      if ( Debug.EnableInfo && hasDebug())
        Debug.println("  Update stream size=" + stream.getFileSize());
        
      //  Get the current date/time
      
      long modifiedTime = 0L;
      if ( stream.hasModifyDate())
        modifiedTime = stream.getModifyDate();
      else
        modifiedTime = System.currentTimeMillis();

      //  Check if the modified time is earlier than the file creation date/time
      
      if ( stream.hasCreationDate() && modifiedTime < stream.getCreationDate()) {
        
        //  Use the creation date/time for the modified date/time
        
        modifiedTime = stream.getCreationDate();
        
        //  DEBUG
        
        if ( Debug.EnableInfo && hasDebug())
          Debug.println("Close stream using creation date/time for modified date/time");
      }
      
      //  Update the in-memory stream information
      
      FileState parent = getFileState(stream.getFullName(), dbCtx, false);
      StreamInfo sInfo = null;
      
      if ( parent != null) {
        
        //  Check if the stream list has been loaded
        
        StreamInfoList streamList = loadStreamList(parent, null, dbCtx, false);
        if ( streamList != null) {
          
          //  Find the stream information
          
          sInfo = streamList.findStream(stream.getStreamName());
          if ( sInfo != null) {
            
            //  Update the stream size
            
            sInfo.setSize(stream.getFileSize());
            
            //  DEBUG
            
            if ( Debug.EnableInfo && hasDebug())
              Debug.println("Updated stream file size");
          }
        }
      }

      //  Update the file details for the file stream in the database
      
      try {

        //  Check if the file strea, details are valid
        
        if ( sInfo == null) {
          
          //  Create the stream information
          
          sInfo = new StreamInfo();
          
          sInfo.setSize(stream.getFileSize());
          sInfo.setStreamId(stream.getStreamId());
        }
        
        //  Set the modify date/time for the stream
        
        sInfo.setModifyDateTime(System.currentTimeMillis());

        //  Update the stream details
        
        dbCtx.getDBInterface().setStreamInformation(stream.getDirectoryId(), stream.getFileId(), stream.getStreamId(), sInfo);
      }
      catch (DBException ex) {
      }
    }
  }
  
  /**
   * Delete a stream within a file
   * 
   * @param sess SrvSession
   * @param tree TreeConnection
   * @param name String
   * @exception IOException
   */
  protected final void deleteStream(SrvSession sess, TreeConnection tree, String name)
    throws IOException {

    //  Access the JDBC context

    DBDeviceContext dbCtx = (DBDeviceContext) tree.getContext();

    //  Parse the path string to get the directory, file name and stream name
    
    String[] paths = FileName.splitPathStream(name);

    //  Get, or create, the file state for main file path and stream
      
    String filePath = paths[0] + paths[1];
    FileState fstate = getFileState(filePath, dbCtx, true);
    FileState sstate = getFileState(name, dbCtx, false);

    //  Check if the file is within an active retention period
    
    if ( fstate.hasActiveRetentionPeriod())
      throw new AccessDeniedException("File retention active");


    //  Get the top level file information
    
    DBFileInfo finfo = getFileDetails(filePath,dbCtx, fstate);
    
    //  Get the stream list for the top level file
    
    StreamInfoList streamList = (StreamInfoList) fstate.findAttribute(DBStreamList);
    if ( streamList == null)
      streamList = loadStreamList(fstate, finfo, dbCtx, true);
    
    if ( streamList == null)
      throw new FileNotFoundException("Stream not found, " + name);
    
    //  Find the required stream details
    
    StreamInfo sInfo = streamList.findStream(paths[2]);
    if ( sInfo == null)
      throw new FileNotFoundException("Stream not found, " + name);

    //  Delete the stream record from the database
    
    try {

      //  Call the file loader to delete the stream data
      
      dbCtx.getFileLoader().deleteFile(name, sInfo.getFileId(), sInfo.getStreamId());
      
      //  Delete the stream record
      
      dbCtx.getDBInterface().deleteStreamRecord(sInfo.getFileId(), sInfo.getStreamId(), dbCtx.isTrashCanEnabled());
      
      //  Remove the stream information from the in memory list
        
      streamList.removeStream(sInfo.getName());
        
      //  Set the streams file state to indicate that it does not exist
        
      if ( sstate != null)
        sstate.setFileStatus( FileStatus.NotExist);
    }
    catch (DBException ex) {
      Debug.println("Error: " + ex.toString());
      Debug.println(ex);
    }
  }
  
  /**
   * Load the stream list for the specified file
   * 
   * @param fstate FileState
   * @param finfo DBFileInfo
   * @param dbCtx DBDeviceContext
   * @param dbLoad boolean
   * @return StreamInfoList
   */
  protected final StreamInfoList loadStreamList(FileState fstate, DBFileInfo finfo, DBDeviceContext dbCtx, boolean dbLoad) {

    //  Check if the stream list has already been loaded
    
    StreamInfoList sList = (StreamInfoList) fstate.findAttribute(FileState.StreamsList);
    
    //  If the streams list is not loaded then load it from the database

    if ( sList == null && dbLoad == true) {   

      //  Load the streams list from the database
      
      try {

        //  Load the streams list
        
        sList = dbCtx.getDBInterface().getStreamsList(finfo.getFileId(), DBInterface.StreamAll);
      }
      catch (DBException ex) {
      }
    }
        
    //  Return the streams list
    
    return sList;
  }

  /**
   *  Rename a stream
   *
   * @param sess SrvSession 
   * @param tree TreeConnection
   * @param oldName String
   * @param newName String
   * @param overWrite boolean
   * @exception IOException
   */
  public void renameStream(SrvSession sess, TreeConnection tree, String oldName, String newName, boolean overWrite)
    throws IOException {
  }

  /**
   * Return the volume information
   * 
   * @param ctx DiskDeviceContext
   * @return VolumeInfo 
   */
  public VolumeInfo getVolumeInformation(DiskDeviceContext ctx) {
    
    //  Check if the context has volume information
    
    VolumeInfo volInfo = ctx.getVolumeInformation();
    
    if ( volInfo == null) {
      
      //  Create volume information for the filesystem
      
      volInfo = new VolumeInfo(ctx.getDeviceName());
      
      //  Add to the device context
      
      ctx.setVolumeInformation(volInfo);
    }

    //  Check if the serial number is valid
    
    if ( volInfo.getSerialNumber() == 0) {
      
      //  Generate a random serial number
      
      volInfo.setSerialNumber(new java.util.Random().nextInt());      
    }
    
    //  Check if the creation date is valid
    
    if ( volInfo.hasCreationDateTime() == false) {
      
      //  Set the creation date to now
      
      volInfo.setCreationDateTime(new java.util.Date());
    }
    
    //  Return the volume information
    
    return volInfo;
  }
  
  /**
   * Return the lock manager implementation
   * 
   * @param sess SrvSession
   * @param tree TreeConnection
   * @return LockManager 
   */
  public LockManager getLockManager(SrvSession sess, TreeConnection tree) {
    
    //  Return the file state lock manager
    
    return _lockManager;
  }
  
  /**
   * Convert a file id to a share relative path
   *
   * @param sess SrvSession
   * @param tree TreeConnection
   * @param dirid int
   * @param fileid
   * @return String
   * @exception FileNotFoundException 
   */
  public String buildPathForFileId(SrvSession sess, TreeConnection tree, int dirid, int fileid)
    throws FileNotFoundException {

    // Access the JDBC context
    
    DBDeviceContext dbCtx = (DBDeviceContext) tree.getContext();

    //  Build an array of folder names working back from the files id
    
    ArrayList names = new ArrayList(16);
      
    try {

      //  Loop, walking backwards up the tree until we hit root
      
      int curFid = fileid;
      int curDid = dirid;
      
      FileInfo finfo = null;
      
      do {
            
        //  Search for the current file in the database

        finfo = dbCtx.getDBInterface().getFileInformation(curDid, curFid, DBInterface.FileIds);

        if ( finfo != null) {
          
          //  Get the filename
          
          names.add(finfo.getFileName());
          
          //  The directory id becomes the next file id to search for
          
          curFid = finfo.getDirectoryId();
          curDid = -1;
        }
        else
          throw new FileNotFoundException("" + curFid);
      
      } while ( curFid > 0);
    }
    catch ( DBException ex) {
      Debug.println( ex);
      return null;
    }

    //  Build the path string

    StringBuffer pathStr = new StringBuffer (256);
    pathStr.append(FileName.DOS_SEPERATOR_STR);
    
    for ( int i = names.size() - 1; i >= 0; i--) {
      pathStr.append(names.get(i));
      pathStr.append(FileName.DOS_SEPERATOR_STR);
    }
    
    //  Remove the trailing slash from the path
    
    if ( pathStr.length() > 0)
      pathStr.setLength(pathStr.length() - 1);
    
    //  Return the path string
    
    return pathStr.toString();
  }
  
  /**
   * Determine if symbolic links are enabled
   * 
   * @param sess SrvSession
   * @param tree TreeConnection
   * @return boolean
   */
  public boolean hasSymbolicLinksEnabled(SrvSession sess, TreeConnection tree) {

    //  Access the associated database interface to check if it supports symbolic links
      
    DBDeviceContext dbCtx = (DBDeviceContext) tree.getContext();
    if ( dbCtx.getDBInterface().supportsFeature( DBInterface.FeatureSymLinks)) {
        
      //  Database interface supports symbolic links

      return true;
    }
    
    //  Symbolic links not supported
    
    return false;
  }
  
  /**
   * Read the link data for a symbolic link
   * 
   * @param sess SrvSession
   * @param tree TreeConnection
   * @param path String
   * @return String
   * @exception AccessDeniedException
   * @exception FileNotFoundException 
   */
  public String readSymbolicLink( SrvSession sess, TreeConnection tree, String path)
    throws AccessDeniedException, FileNotFoundException {
    
    //  Access the associated database interface to check if it supports symbolic links
    
    DBDeviceContext dbCtx = (DBDeviceContext) tree.getContext();
    DBInterface dbInterface = dbCtx.getDBInterface();
    String symLink = null;
    
    if ( dbInterface.supportsFeature( DBInterface.FeatureSymLinks)) {
        
      //  Get, or create, the file state for the existing file
      
      FileState fstate = getFileState( path, dbCtx, true);
      
      //  Get the file id of the existing file
      
      int fid = fstate.getFileId();
      int dirId = -1;
      
      if ( fid == -1) {
        
        //  Split the current path string and find the file id of the existing file/directory
        
        dirId = findParentDirectoryId( dbCtx, path, true);
        if ( dirId == -1)
          throw new FileNotFoundException( path);
    
        //  Get the file/directory name
  
        String[] oldPaths = FileName.splitPath( path);
        String fname = oldPaths[1];
        
        //  Get the file id
        
        fid = getFileId( path, fname, dirId, dbCtx);
        if ( fid == -1)
          throw new FileNotFoundException( path);
          
        //  Update the file state
        
        fstate.setFileId(fid);
      }
      
      try {
        
        //  Database interface supports symbolic links, read the symbolic link
        
        symLink = dbInterface.readSymbolicLink( dirId, fid);
      }
      catch ( DBException ex) {
        throw new FileNotFoundException ( path);
      }
    }
    
    //  Return the symbolic link data
    
    return symLink;
  }
}
