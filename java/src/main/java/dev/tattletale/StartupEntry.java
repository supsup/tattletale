package dev.tattletale;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.lang.foreign.*;
import java.lang.invoke.MethodHandle;
import java.nio.ByteOrder;
import java.nio.file.*;
import java.util.*;
import static java.lang.foreign.ValueLayout.*;

/** Type-first startup reads. Native entry opens are nonblocking and bounded to a proven regular fd. */
final class StartupEntry {
    static final int MAX_BYTES=16*1024*1024, MAX_LINKS=40;
    static final int TYPE=0170000, REGULAR=0100000, DIRECTORY=0040000, LINK=0120000;
    record Meta(long dev,long ino,int mode,long size,long mtimeSec,long mtimeNsec,long ctimeSec,long ctimeNsec) {}
    interface Fs {
        Meta metadata(Path path) throws IOException;
        Path target(Path path) throws IOException;
        byte[] regular(Path path,Meta expected) throws IOException;
        boolean optionalAbsent(Path path) throws IOException;
        default List<Observed> ancestorLinks(Path path)throws IOException{return List.of();}
    }
    record Observed(Path path,Meta metadata) {}
    static final class AncestorLoop extends IOException {
        private static final long serialVersionUID=1L;
        final List<Observed> observed;
        AncestorLoop(List<Observed> observed){super("startup-read");this.observed=List.copyOf(observed);}
    }
    static final Fs REAL=new Fs() {
        public Meta metadata(Path path)throws IOException {
            // NIO on Darwin conflates ENOTDIR with ENOENT. Preserve the actual native errno.
            return Darwin.metadata(path,false);
        }
        public Path target(Path path)throws IOException{return Files.readSymbolicLink(path);}
        public byte[] regular(Path path,Meta expected)throws IOException{return Darwin.read(path,expected,()->{},()->{});}
        public boolean optionalAbsent(Path path)throws IOException {
            ancestorLinks(path); // Broken/inaccessible ancestors are not a known final absence.
            return true;
        }
        public List<Observed> ancestorLinks(Path path)throws IOException {
            List<Observed> links=new ArrayList<>();
            if(path.getParent()!=null)directoryChain(this,path.getParent(),links,new HashSet<>(),new int[]{0},true);
            return links;
        }
    };
    /** Observe every link in ancestor targets too, retaining raw symlink/.. kernel spelling. */
    static void directoryChain(Fs fs,Path directory,List<Observed> chain,Set<Path> active,int[] hops,boolean optional)throws IOException {
        Path prefix=directory.getRoot();
        for(int i=0;i<directory.getNameCount();i++) {
            prefix=prefix.resolve(directory.getName(i));Meta m;
            try{m=fs.metadata(prefix);}catch(NoSuchFileException absent){if(optional)return;throw absent;}
            int type=m.mode()&TYPE;
            if(type==LINK) {
                chain.add(new Observed(prefix,m));
                if(!active.add(prefix) || ++hops[0]>MAX_LINKS)throw new AncestorLoop(chain);
                Path target=fs.target(prefix);stable(fs,chain);
                directoryChain(fs,target.isAbsolute()?target:prefix.getParent().resolve(target),chain,active,hops,false);
                active.remove(prefix);
                // Confirm the completely observed target is still a directory with native errno fidelity.
                if((Darwin.metadata(prefix,true).mode()&TYPE)!=DIRECTORY)throw new NotDirectoryException(prefix.toString());
            }else if(type!=DIRECTORY)throw new NotDirectoryException(prefix.toString());
        }
    }
    static void stable(Fs fs,List<Observed> chain)throws IOException {
        for(Observed entry:chain)if(!entry.metadata().equals(fs.metadata(entry.path())))throw new IOException("startup-read");
    }
    static Watch.Unreadable marker(Fs fs,List<Observed> chain,String reason)throws IOException {
        stable(fs,chain);return new Watch.Unreadable(reason);
    }
    static byte[] read(String file)throws IOException{return read(file,REAL);}
    static byte[] read(String file,Fs fs)throws IOException {
        // Preserve spelling: normalizing a symlink/.. path changes the kernel's target.
        Path path=Path.of(file).toAbsolutePath();boolean followed=false;Set<Path> seen=new HashSet<>();List<Observed> chain=new ArrayList<>();
        for(int hops=0;hops<=MAX_LINKS;hops++) {
            try{chain.addAll(fs.ancestorLinks(path));}
            catch(AncestorLoop loop){chain.addAll(loop.observed);throw marker(fs,chain,"symlink-loop");}
            if(!seen.add(path))throw marker(fs,chain,"symlink-loop");
            Meta m;
            try {m=fs.metadata(path);}
            catch(NoSuchFileException e){
                if(!fs.optionalAbsent(path))throw e;
                stable(fs,chain);
                // Confirm absence again after validating links, before persisting an absence/marker.
                try{fs.metadata(path);throw new IOException("startup-read");}catch(NoSuchFileException stillAbsent){}
                if(followed)throw marker(fs,chain,"dangling-link");return null;
            }
            chain.add(new Observed(path,m));
            int type=m.mode()&TYPE;
            if(type==LINK) {
                if(hops==MAX_LINKS)throw marker(fs,chain,"symlink-loop");
                Path target=fs.target(path);stable(fs,chain);path=target.isAbsolute()?target:path.getParent().resolve(target);followed=true;continue;
            }
            if(type==DIRECTORY)throw marker(fs,chain,"directory");
            if(type!=REGULAR)throw marker(fs,chain,"not-a-regular-file");
            if(m.size()>MAX_BYTES)throw marker(fs,chain,"file-too-large");
            if(m.size()<0)throw new IOException("startup-read");
            stable(fs,chain);
            try{byte[] bytes=fs.regular(path,m);stable(fs,chain);return bytes;}
            catch(AccessDeniedException e){throw marker(fs,chain,"permission-denied");}
        }
        throw marker(fs,chain,"symlink-loop");
    }

    interface Boundary {void run()throws IOException;}
    /** Darwin LP64 stat64: installed SDK sys/stat.h + sys/_types.h; no private JDK reflection. */
    static final class Darwin {
        static final MemoryLayout TS=MemoryLayout.structLayout(JAVA_LONG,JAVA_LONG);
        static final MemoryLayout STAT=MemoryLayout.structLayout(JAVA_INT.withName("dev"),JAVA_SHORT.withName("mode"),JAVA_SHORT,
                JAVA_LONG.withName("ino"),JAVA_INT,JAVA_INT,JAVA_INT,MemoryLayout.paddingLayout(4),TS,
                TS.withName("mtime"),TS.withName("ctime"),TS,JAVA_LONG.withName("size"),JAVA_LONG,JAVA_INT,JAVA_INT,JAVA_INT,JAVA_INT,MemoryLayout.sequenceLayout(2,JAVA_LONG));
        record Calls(MethodHandle open,MethodHandle stat,MethodHandle read,MethodHandle close,MethodHandle lstat,MethodHandle pathStat) {}
        static final class Holder {static final Calls CALLS=load();}
        static boolean supported() {return System.getProperty("os.name").equals("Mac OS X") && List.of("aarch64","x86_64").contains(System.getProperty("os.arch"))
                && ADDRESS.byteSize()==8 && JAVA_LONG.byteSize()==8 && ByteOrder.nativeOrder()==ByteOrder.LITTLE_ENDIAN;}
        static long offset(String name){return STAT.byteOffset(MemoryLayout.PathElement.groupElement(name));}
        static boolean permissionErrno(int errno){return errno==1 || errno==13;} // Darwin EPERM/EACCES only.
        static Calls load() {
            if(!supported())return null;
            try {
                Linker l=Linker.nativeLinker();SymbolLookup lib=SymbolLookup.libraryLookup("/usr/lib/libSystem.B.dylib",Arena.global());
                return new Calls(l.downcallHandle(lib.find("open").orElseThrow(),FunctionDescriptor.of(JAVA_INT,ADDRESS,JAVA_INT,JAVA_INT),Linker.Option.firstVariadicArg(2),Linker.Option.captureCallState("errno")),
                        l.downcallHandle(lib.find(System.getProperty("os.arch").equals("aarch64")?"fstat":"fstat$INODE64").orElseThrow(),FunctionDescriptor.of(JAVA_INT,JAVA_INT,ADDRESS)),
                        l.downcallHandle(lib.find("read").orElseThrow(),FunctionDescriptor.of(JAVA_LONG,JAVA_INT,ADDRESS,JAVA_LONG)),
                        l.downcallHandle(lib.find("close").orElseThrow(),FunctionDescriptor.of(JAVA_INT,JAVA_INT)),
                        l.downcallHandle(lib.find(System.getProperty("os.arch").equals("aarch64")?"lstat":"lstat$INODE64").orElseThrow(),FunctionDescriptor.of(JAVA_INT,ADDRESS,ADDRESS),Linker.Option.captureCallState("errno")),
                        l.downcallHandle(lib.find(System.getProperty("os.arch").equals("aarch64")?"stat":"stat$INODE64").orElseThrow(),FunctionDescriptor.of(JAVA_INT,ADDRESS,ADDRESS),Linker.Option.captureCallState("errno")));
            }catch(RuntimeException | LinkageError e){return null;}
        }
        static Meta stat(MemorySegment s) {return new Meta(s.get(JAVA_INT,offset("dev")),s.get(JAVA_LONG,offset("ino")),Short.toUnsignedInt(s.get(JAVA_SHORT,offset("mode"))),s.get(JAVA_LONG,offset("size")),s.get(JAVA_LONG,offset("mtime")),s.get(JAVA_LONG,offset("mtime")+8),s.get(JAVA_LONG,offset("ctime")),s.get(JAVA_LONG,offset("ctime")+8));}
        static Meta metadata(Path path,boolean follow)throws IOException {
            if(!supported() || STAT.byteSize()!=144 || offset("mode")!=4 || offset("ino")!=8 || offset("size")!=96 || Holder.CALLS==null)throw new IOException("startup-read");
            try(Arena a=Arena.ofConfined()) {
                MemorySegment capture=a.allocate(Linker.Option.captureStateLayout()),name=a.allocateFrom(path.toString()),s=a.allocate(STAT);
                MethodHandle call=follow?Holder.CALLS.pathStat():Holder.CALLS.lstat();
                if((int)call.invokeExact(capture,name,s)==0)return stat(s);
                int errno=capture.get(JAVA_INT,Linker.Option.captureStateLayout().byteOffset(MemoryLayout.PathElement.groupElement("errno")));
                // Installed Darwin SDK sys/errno.h: no exception-message or existence heuristics.
                if(errno==2)throw new NoSuchFileException(path.toString());
                if(errno==20)throw new NotDirectoryException(path.toString());
                if(errno==62)throw new FileSystemLoopException(path.toString());
                if(permissionErrno(errno))throw new AccessDeniedException(path.toString());
                throw new IOException("startup-read");
            }catch(IOException e){throw e;}
            catch(Throwable e){if(e instanceof Error err)throw err;throw new IOException("startup-read",e);}
        }
        static byte[] read(Path path,Meta expected,Boundary beforeOpen,Boundary afterRead)throws IOException {
            if(!supported() || STAT.byteSize()!=144 || offset("mode")!=4 || offset("ino")!=8 || offset("size")!=96 || Holder.CALLS==null)throw new IOException("startup-read");
            Calls c=Holder.CALLS;
            beforeOpen.run();
            try(Arena a=Arena.ofConfined()) {
                MemorySegment capture=a.allocate(Linker.Option.captureStateLayout()),name=a.allocateFrom(path.toString()),s=a.allocate(STAT),end=a.allocate(STAT);
                // Installed Darwin SDK sys/fcntl.h: O_NOFOLLOW=0x100; reject a raced final symlink.
                int fd=(int)c.open().invokeExact(capture,name,0x01000104,0); // O_RDONLY|O_NONBLOCK|O_NOFOLLOW|O_CLOEXEC
                if(fd<0) {
                    int errno=capture.get(JAVA_INT,Linker.Option.captureStateLayout().byteOffset(MemoryLayout.PathElement.groupElement("errno")));
                    if(permissionErrno(errno))throw new AccessDeniedException(path.toString());
                    throw new IOException("startup-read");
                }
                Throwable primary=null;
                try {
                    if((int)c.stat().invokeExact(fd,s)!=0)throw new IOException("startup-read");Meta opened=stat(s);
                    if((opened.mode()&TYPE)!=REGULAR || !opened.equals(expected) || opened.size()>MAX_BYTES)throw new IOException("startup-read");
                    MemorySegment buf=a.allocate(8192);ByteArrayOutputStream out=new ByteArrayOutputStream();
                    while(out.size()<=opened.size()) {
                        long n=(long)c.read().invokeExact(fd,buf,Math.min(8192L,opened.size()+1-out.size()));
                        if(n<0)throw new IOException("startup-read");if(n==0)break;out.write(buf.asSlice(0,n).toArray(JAVA_BYTE));
                    }
                    afterRead.run();
                    if((int)c.stat().invokeExact(fd,end)!=0 || !opened.equals(stat(end)) || out.size()!=opened.size())throw new IOException("startup-read");
                    return out.toByteArray();
                } catch(Throwable failure){primary=failure;throw failure;}
                finally {
                    try{if((int)c.close().invokeExact(fd)!=0)throw new IOException("startup-close");}
                    catch(Throwable closeFailure){if(primary!=null)primary.addSuppressed(closeFailure);else throw closeFailure;}
                }
            } catch(IOException e){throw e;}
            catch(Throwable e){if(e instanceof Error err)throw err;throw new IOException("startup-read",e);}
        }
    }
}
