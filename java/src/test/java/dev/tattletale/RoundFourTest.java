package dev.tattletale;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.*;
import static dev.tattletale.CollectionHealthTest.*;
import static dev.tattletale.RepairHealthTest.digest;

/** Review44 regressions. All process identities are synthetic and every pid-path call is stubbed. */
final class RoundFourTest {
    static void run() {
        test("r4-stable-absolute-process-does-not-consult-kernel",()->{try(Fixture f=new Fixture()){
            f.w.sources=new Fake(){public String pidPath(long pid){throw new AssertionError("stable ps identity consulted bridge");}};
            f.w.checkProcesses();status(f.w,"processes","ok");check(f.w.knownProgs.equals(Set.of("/fixture/a")),"stable absolute identity displaced");
        }});
        test("r4-relative-and-escaped-process-bridge-controls",()->{
            for(String comm:List.of("/fixture/app^2","/fixture/plainM-","/fixture/backslash\\q","/fixture/stable"))try(Fixture f=new Fixture()){
                Fake fake=new Fake(){public String pidPath(long pid){throw new AssertionError("escape-free ps identity consulted bridge");}};fake.comm=new Proc.Result(0,"42 1 fixture "+comm+"\n","");f.w.sources=fake;f.w.checkProcesses();status(f.w,"processes","ok");check(f.w.knownProgs.equals(Set.of(comm)),"escape-free stable identity changed");
            }
            for(String comm:List.of("relative","/fixture/slM-CM-)","/fixture/escaped\\040name","/fixture/control^A"))try(Fixture f=new Fixture()){
                Fake fake=new Fake(){public String pidPath(long pid){check(pid==42,"unexpected fixture pid");return "/fixture/real";}};fake.comm=new Proc.Result(0,"42 1 fixture "+comm+"\n","");f.w.sources=fake;
                f.w.checkProcesses();status(f.w,"processes","ok");check(f.w.knownProgs.equals(Set.of("/fixture/real")),"bridge not selected for escaped/relative identity");
            }
            for(String bridge:Arrays.asList(null,"","relative","/"))for(String comm:List.of("/fixture/slM-CM-)","/fixture/escaped\\040name","/fixture/control^A"))try(Fixture f=new Fixture()){
                Fake fake=new Fake(){public String pidPath(long pid){return bridge;}};fake.comm=new Proc.Result(0,"42 1 fixture "+comm+"\n","");f.w.sources=fake;
                f.w.checkProcesses();status(f.w,"processes","degraded");check(f.w.knownProgs.isEmpty() && f.w.baseline.get("programs"),"escaped identity adopted without valid bridge");
            }
        });
        test("r4-listener-fallback-root-and-vis-controls",()->{
            for(String comm:List.of("/fixture/service","/","/fixture/escaped\\040name","/fixture/slM-CM-)"))try(Fixture f=new Fixture()){
                Fake fake=new Fake(){public String pidPath(long pid){check(pid==99,"stable ps identity consulted bridge");return "/";}};fake.lookup=new Proc.Result(0,comm+"\n","");fake.lsof=new Proc.Result(0,"p99\ncfixture\nn127.0.0.1:12345\n","");f.w.sources=fake;f.w.checkListeners();
                if(comm.equals("/fixture/service")){status(f.w,"listeners","ok");check(f.w.listeners.containsKey("/fixture/service 127.0.0.1:12345"),"invalid root bridge hid valid comm fallback");}
                else{status(f.w,"listeners","degraded");check(f.w.listeners.isEmpty() && f.w.baseline.get("listeners"),"root/vis comm fallback adopted");}
            }
        });
        test("r4-real-looping-ancestor-is-marker",()->{
            Path d=Files.createDirectory(root.resolve("r4-loop-parent")),loop=d.resolve("loop"),link=d.resolve("link");Files.createSymbolicLink(loop,loop);Files.createSymbolicLink(link,loop.resolve("child"));
            marker(link,"symlink-loop");
        });
        test("r4-real-enotdir-optional-and-link-reject",()->{
            Path d=Files.createDirectory(root.resolve("r4-notdir")),regular=d.resolve("regular"),link=d.resolve("link");Files.writeString(regular,"regular control");Files.createSymbolicLink(link,regular.resolve("child"));
            rejected(regular.resolve("child"));rejected(link);
            check(StartupEntry.read(d.resolve("absent").toString())==null,"true ENOENT optional rejected");
            Path dangling=d.resolve("dangling");Files.createSymbolicLink(dangling,d.resolve("absent-target"));marker(dangling,"dangling-link");
            check(new String(StartupEntry.read(regular.toString()),StandardCharsets.UTF_8).equals("regular control"),"readable peer rejected");
        });
        test("r4-source-list-only-positive-enoent-is-optional",()->{
            Path d=Files.createDirectory(root.resolve("r4-list-source")),file=d.resolve("file");Files.writeString(file,"A\n");Watch.Sources source=Proc::collector;
            check(source.list(d.resolve("absent").toString()).isEmpty(),"genuinely absent optional directory rejected");check(source.list(d.toString()).equals(List.of(file.toString())),"readable directory listing changed");
            boolean rejected=false;try{source.list(file.resolve("x").toString());}catch(IOException e){rejected=true;}check(rejected,"ENOTDIR listing became optional empty");check(!source.optionalMissing(file.resolve("x").toString()),"optionalMissing admitted ENOTDIR as absence");
            Path broken=d.resolve("broken"),loop=d.resolve("loop");Files.createSymbolicLink(broken,d.resolve("missing-target"));Files.createSymbolicLink(loop,loop);
            for(Path p:List.of(broken.resolve("x"),loop.resolve("x"))){rejected=false;try{source.list(p.toString());}catch(IOException e){rejected=true;}check(rejected && !source.optionalMissing(p.toString()),"uncertain ancestor became optional empty");}
        });
        test("r4-source-legacy-read-enotdir-rejects",()->{
            Path d=Files.createDirectory(root.resolve("r4-read-source")),file=d.resolve("file");Files.writeString(file,"A\n");Watch.Sources source=Proc::collector;
            check(source.read(d.resolve("absent").toString())==null && Arrays.equals(source.read(file.toString()),"A\n".getBytes(StandardCharsets.UTF_8)),"optional absent/readable read changed");
            boolean rejected=false;try{source.read(file.resolve("x").toString());}catch(IOException e){rejected=true;}check(rejected,"legacy ENOTDIR read became optional absence");
        });
        test("r4-list-enotdir-retains-files-and-adopts-cron",()->{try(Fixture f=new Fixture()){
            Path d=Files.createDirectory(root.resolve("r4-list-collector")),file=d.resolve("item");Files.writeString(file,"A\n");Path[] listed={d};String[] cron={"old cron\n"};
            f.w.sources=new Watch.Sources(){public Proc.Result run(List<String> c,long timeout){check(c.equals(List.of("crontab","-l")),"unexpected actual fixture command");return new Proc.Result(0,cron[0],"");}public List<String> dirs(){return List.of(listed[0].toString());}public List<String> files(){return List.of();}public String copyRoot(String actual){return f.fake.copyRoot(actual);}public void copy(String p,byte[] b)throws IOException{f.fake.copy(p,b);}public String textDiff(String a,String b,int limit){return f.fake.textDiff(a,b,limit);}};
            f.w.checkStartup();status(f.w,"startup","ok");String old=f.w.startup.get(file.toString());check(old.equals(digest("A\n")),"real readable listing did not seed inventory");
            listed[0]=file.resolve("x");cron[0]="new cron\n";f.w.checkStartup();status(f.w,"startup","degraded");status(f.w,"crontab","ok");
            check(f.w.startup.get(file.toString()).equals(old) && f.w.crontabText.equals("new cron\n") && count(f.w,"STARTUP-")==0 && !f.w.baseline.get("startup"),"failed listing lost accepted file/baseline or suppressed independent cron");
        }});
        test("r4-loop-marker-pins-complete-ancestor-target-chain",()->{
            Path d=Files.createDirectory(root.resolve("r4-loop-chain-race")),a=d.resolve("a"),b=d.resolve("b"),outer=d.resolve("outer"),regular=Files.createDirectory(d.resolve("regular"));
            Files.createSymbolicLink(a,b);Files.createSymbolicLink(b,a);Files.createSymbolicLink(outer,a.resolve("child"));marker(outer,"symlink-loop");
            StartupEntry.Fs raced=new RoundThreeTest.DelegatingFs(){public List<StartupEntry.Observed> ancestorLinks(Path p)throws IOException{
                try{return super.ancestorLinks(p);}catch(StartupEntry.AncestorLoop loop){Files.delete(b);Files.createSymbolicLink(b,regular);throw loop;}
            }};boolean rejected=false;try{StartupEntry.read(outer.toString(),raced);}catch(IOException e){rejected=!(e instanceof Watch.Unreadable);}check(rejected,"retargeted nested loop persisted obsolete marker");
        });
        test("r4-native-stat-lstat-layout-and-errno-controls",()->{
            Path d=Files.createDirectory(root.resolve("r4-native-stat")),file=d.resolve("file"),link=d.resolve("link");Files.writeString(file,"stat control");Files.createSymbolicLink(link,file);
            Map<String,Object> attrs=Files.readAttributes(file,"unix:dev,ino,mode,size,lastModifiedTime,ctime",LinkOption.NOFOLLOW_LINKS);
            StartupEntry.Meta m=StartupEntry.Darwin.metadata(file,false);java.time.Instant mt=((java.nio.file.attribute.FileTime)attrs.get("lastModifiedTime")).toInstant(),ct=((java.nio.file.attribute.FileTime)attrs.get("ctime")).toInstant();
            check(m.equals(new StartupEntry.Meta(((Number)attrs.get("dev")).longValue(),((Number)attrs.get("ino")).longValue(),((Number)attrs.get("mode")).intValue(),((Number)attrs.get("size")).longValue(),mt.getEpochSecond(),mt.getNano(),ct.getEpochSecond(),ct.getNano())),"native struct stat fields differ from public NIO attributes");
            check((StartupEntry.Darwin.metadata(link,false).mode()&StartupEntry.TYPE)==StartupEntry.LINK && StartupEntry.Darwin.metadata(link,true).equals(m),"lstat/stat follow flag confused");
            boolean enoent=false,enotdir=false;try{StartupEntry.Darwin.metadata(d.resolve("absent"),false);}catch(NoSuchFileException e){enoent=true;}try{StartupEntry.Darwin.metadata(file.resolve("x"),false);}catch(NotDirectoryException e){enotdir=true;}
            Path loop=d.resolve("loop");Files.createSymbolicLink(loop,loop);boolean eloop=false;try{StartupEntry.Darwin.metadata(loop,true);}catch(FileSystemLoopException e){eloop=true;}check(enoent && enotdir && eloop,"native errno classification collapsed");
        });
        test("r4-listed-child-lstat-eacces-rejects-partition",()->{try(Fixture f=new Fixture()){
            Path d=Files.createDirectory(root.resolve("r4-listed-eacces")),child=d.resolve("child");Files.writeString(child,"known existing peer");
            // Qualified metadata seam: the real directory listing and bytes exist; only lstat is injected.
            StartupEntry.Fs denied=new RoundThreeTest.DelegatingFs(){public StartupEntry.Meta metadata(Path p)throws IOException{if(p.equals(child))throw new AccessDeniedException(p.toString());return super.metadata(p);}};
            f.w.sources=new Fake(){public List<String> dirs(){return List.of(d.toString());}public List<String> list(String dir)throws IOException{List<String> paths=new ArrayList<>();try(DirectoryStream<Path> ds=Files.newDirectoryStream(Path.of(dir))){for(Path p:ds)paths.add(p.toString());}return paths;}public List<String> files(){return List.of();}public byte[] entry(String p)throws IOException{return StartupEntry.read(p,denied);}};
            f.w.checkStartup();status(f.w,"startup","degraded");status(f.w,"crontab","ok");check(!f.w.startup.containsKey(child.toString()) && f.w.baseline.get("startup"),"unknown listed metadata became persistent marker/absence");
        }});
        for(boolean baseline:List.of(true,false))test("r4-first-readable-"+(baseline?"baseline":"new-add"),()->{try(Fixture f=new Fixture()){
            class Readability extends Fake {boolean unreadable=true;public byte[] entry(String p)throws IOException{if(unreadable)throw new Watch.Unreadable("permission-denied");return super.entry(p);}}
            Readability fake=new Readability();f.w.sources=fake;String path="/fixture/first-readable";
            if(!baseline)f.w.checkStartup();fake.files.put(path,"A\n".getBytes(StandardCharsets.UTF_8));f.w.checkStartup();long added=count(f.w,"STARTUP+");
            fake.unreadable=false;f.w.checkStartup();String after=RepairHealthTest.copy(path,digest("A\n"));
            check(f.w.db.query("SELECT kind,message FROM events WHERE kind='STARTUP~' ORDER BY id;").equals(List.of(RepairHealthTest.event("STARTUP~","changed: "+path+" | before: None | after: "+after+"\n(no text diff: binary or missing copy)"))),"first readable content not delivered once with missing-before");
            check(Arrays.equals(fake.copies.get(after),"A\n".getBytes(StandardCharsets.UTF_8)),"first readable event lacks actual after-copy bytes");
            f.w.checkStartup();check(count(f.w,"STARTUP~")==1 && count(f.w,"STARTUP+")==added,"unchanged readable repeated event");
            fake.unreadable=true;f.w.checkStartup();fake.unreadable=false;f.w.checkStartup();check(count(f.w,"STARTUP~")==1,"A-unreadable-A emitted change");
            fake.unreadable=true;f.w.checkStartup();fake.unreadable=false;fake.files.put(path,"B\n".getBytes(StandardCharsets.UTF_8));f.w.checkStartup();
            List<Map<String,Object>> changed=f.w.db.query("SELECT kind,message FROM events WHERE kind='STARTUP~' ORDER BY id;");check(changed.size()==2 && Db.asStr(changed.getLast().get("message")).contains("before: "+after) && Db.asStr(changed.getLast().get("message")).endsWith("(fixture diff)"),"A-unreadable-B lost retained readable before/diff");
        }});
        test("r4-first-readable-event-published-only-after-db-commit",()->{try(Fixture f=new Fixture()){
            class Readability extends Fake {boolean unreadable=true;public byte[] entry(String p)throws IOException{if(unreadable)throw new Watch.Unreadable("permission-denied");return super.entry(p);}}
            Readability fake=new Readability();String path="/fixture/first-atomic";fake.files.put(path,"first content\n".getBytes(StandardCharsets.UTF_8));f.w.sources=fake;f.w.checkStartup();String prior=f.w.startup.get(path);long versions=Db.asLong(f.w.db.scalar("SELECT count(*) FROM startup_versions;"));
            f.w.db.exec("CREATE TRIGGER fixture_first_readable BEFORE INSERT ON startup_versions BEGIN SELECT RAISE(ABORT,'fixture first readable'); END;");fake.unreadable=false;f.w.checkStartup();
            check(f.w.startup.get(path).equals(prior) && count(f.w,"STARTUP~")==0 && Db.asLong(f.w.db.scalar("SELECT count(*) FROM startup_versions;"))==versions && health(f.w,"startup").get("error").equals("collection-db"),"failed first-readable DB sample published event or adopted mirror/history");
            f.w.db.exec("DROP TRIGGER fixture_first_readable;");f.w.checkStartup();check(count(f.w,"STARTUP~")==1 && f.w.startup.get(path).equals(digest("first content\n")),"first-readable failed DB sample did not recover exactly once");
        }});
        test("r4-nonutf8-pid-invalid-stale-not-partial",()->{try(Fixture f=new Fixture()){
            Path pid=Path.of(f.w.dataDir,"tattletale.pid");f.w.pidProbe=n->{throw new AssertionError("invalid pid reached identity probe");};
            for(byte[] bytes:List.of(new byte[]{(byte)0xff},new byte[]{0x42,(byte)0xc3})){
                Files.write(pid,bytes);f.w.claimPidFile();check(Files.readString(pid).equals(ProcessHandle.current().pid()+"\n"),"non-UTF8 pid not atomically replaced");f.w.releasePidFile();
            }check(count(f.w,"NOTE")==2,"invalid stale NOTE missing");
        }});
        test("r4-stale-pid-replacement-failure-has-no-note",()->{try(Fixture f=new Fixture()){
            Path dir=Path.of(f.w.dataDir),pid=dir.resolve("tattletale.pid");byte[] original="invalid stale".getBytes(StandardCharsets.UTF_8);Files.write(pid,original);f.w.pidProbe=n->{throw new AssertionError("invalid pid reached probe");};
            Files.setPosixFilePermissions(dir,PosixFilePermissions.fromString("r-x------"));boolean failed=false;
            try{f.w.claimPidFile();}catch(IOException e){failed=true;}finally{Files.setPosixFilePermissions(dir,PosixFilePermissions.fromString("rwx------"));}
            check(failed && Arrays.equals(Files.readAllBytes(pid),original) && f.w.pidFile==null && count(f.w,"NOTE")==0,"failed replacement published NOTE/identity or lost old bytes");
        }});
        test("r4-stale-pid-atomic-move-failure-preserves-bytes",()->{try(Fixture f=new Fixture()){
            Path pid=Path.of(f.w.dataDir,"tattletale.pid");byte[] original=new byte[]{0x42,(byte)0xc3};Files.write(pid,original);f.w.pidProbe=n->{throw new AssertionError("invalid pid reached probe");};
            f.w.pidReplace=(from,to)->{check(Files.readString(from).equals(ProcessHandle.current().pid()+"\n"),"replacement not fully written before move");throw new IOException("fixture atomic move failure");};boolean failed=false;
            try{f.w.claimPidFile();}catch(IOException e){failed=e.getMessage().equals("fixture atomic move failure");}
            check(failed && Arrays.equals(Files.readAllBytes(pid),original) && f.w.pidFile==null && count(f.w,"NOTE")==0,"failed atomic move published NOTE/identity or lost old bytes");
            try(DirectoryStream<Path> ds=Files.newDirectoryStream(pid.getParent(),".tattletale-pid-*.tmp")){check(!ds.iterator().hasNext(),"failed pid move left owned temp");}
        }});
        test("r4-publication-cache-detachment-holds-lock",()->{try(Fixture f=new Fixture()){
            f.w.save();Map<String,Object> expected=f.w.pageMap();f.w.cachedInventory=new LinkedHashMap<String,Object>(expected){
                @Override public Set<Map.Entry<String,Object>> entrySet(){check(Thread.holdsLock(Watch.LOCK),"publication cache read outside lock");return super.entrySet();}
            };f.w.projection=()->{throw new Db.DbException("fixture cache boundary");};boolean failed=false;
            try{f.w.save();}catch(Db.DbException e){failed=e.getMessage().equals("fixture cache boundary");}
            check(failed && RoundThreeTest.payload(f.w).get("map").equals(expected) && RoundThreeTest.payload(f.w).get("inventoryAsOf").equals(T),"coherent detached projection changed inventory/as-of");
        }});
    }
    static void marker(Path p,String reason)throws Exception {boolean marked=false;try{StartupEntry.read(p.toString());}catch(Watch.Unreadable e){marked=e.marker.equals("unreadable: "+reason);}check(marked,"expected actual marker "+reason);}
    static void rejected(Path p)throws Exception {boolean rejected=false;try{StartupEntry.read(p.toString());}catch(IOException e){rejected=!(e instanceof Watch.Unreadable);}check(rejected,"ENOTDIR became marker or optional absence");}
}
