package dev.tattletale;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import static dev.tattletale.CollectionHealthTest.*;

/** Contract regressions use only injected sources and explicit scratch SQLite. */
final class RepairHealthTest {
    static void run() {
        test("repair-filesystem-failure-still-attempts-cron",()->{try(Fixture f=new Fixture()) {
            f.fake.failList=true; f.fake.cron=new Proc.Result(0,"fixture cron\n","");
            f.w.checkStartup(); status(f.w,"startup","degraded"); status(f.w,"crontab","ok");
            check(f.fake.cronCalls==1 && f.w.startup.containsKey("crontab -l"),"cron suppressed by files");
        }});
        test("repair-cron-failure-still-adopts-files",()->{try(Fixture f=new Fixture()) {
            f.fake.files.put("/fixture/a","a0".getBytes(StandardCharsets.UTF_8)); f.fake.cron=new Proc.Result(7,"","");
            f.w.checkStartup();status(f.w,"startup","ok");status(f.w,"crontab","degraded");
            check(f.w.startup.containsKey("/fixture/a") && !f.w.baseline.get("startup"),"valid files discarded");
        }});
        test("repair-per-entry-unreadability-keeps-peers",()->{try(Fixture f=new Fixture()) {
            Fake fake=new Fake(){public byte[] read(String file)throws IOException {if(file.equals("/fixture/denied"))throw new AccessDeniedException(file);return super.read(file);}};
            fake.files.put("/fixture/denied",new byte[0]);fake.files.put("/fixture/a","a0".getBytes(StandardCharsets.UTF_8));f.w.sources=fake;
            f.w.checkStartup();status(f.w,"startup","degraded");status(f.w,"crontab","ok");
            check("unreadable: permission-denied".equals(f.w.startup.get("/fixture/denied")) && f.w.startup.containsKey("/fixture/a"),"unreadable entry hid peers");
            check(health(f.w,"startup").get("lastSuccess")==null && !f.w.baseline.get("startup"),"unreadable all-clear/baseline");
        }});
        test("repair-ordinary-lossy-newline-decode",()->check(Proc.text(new byte[]{'t','a','t','t','l','e','t','a','l','e','.','j','a','r',(byte)255,'\r','\n','x','\r'}).equals("tattletale.jar\ufffd\nx\n"),"ordinary decoding"));
        test("repair-ps1-failure-does-not-call-ps2",()->{try(Fixture f=new Fixture()) {
            Fake fake=new Fake(){public Proc.Result run(List<String> c,long t)throws IOException {if(c.getLast().equals("pid=,args="))throw new AssertionError("ps2 reached after invalid ps1");return super.run(c,t);}};
            fake.comm=new Proc.Result(7,"","");f.w.sources=fake;f.w.checkProcesses();status(f.w,"processes","degraded");
        }});
        test("repair-pid-upper-bound-before-bridge",()->{try(Fixture f=new Fixture()) {
            f.fake.comm=new Proc.Result(0,"2147483648 1 fixture /fixture/a\n","");f.w.checkProcesses();status(f.w,"processes","degraded");
            check(f.w.knownProgs.isEmpty(),"out-of-range pid adopted");
        }});
        test("repair-old-row-order-explicit-reload",()->{try(Fixture f=new Fixture()) {
            f.w.db.exec("INSERT INTO startup_items(path,hash) VALUES('/fixture/z','z'),('/fixture/a','a');");f.w.loadState();
            check(new ArrayList<>(f.w.startup.keySet()).equals(List.of("/fixture/a","/fixture/z")),"old physical row order leaked");
        }});
        test("repair-automatic-rollback-recovery",()->{try(Fixture f=new Fixture()) {
            f.w.db.exec("CREATE TRIGGER fatal_fixture BEFORE INSERT ON programs BEGIN SELECT RAISE(ROLLBACK,'fixture-original'); END;");
            f.w.checkProcesses();status(f.w,"processes","degraded");check(f.w.knownProgs.isEmpty(),"rolled-back sample adopted");
            f.w.db.exec("DROP TRIGGER fatal_fixture;");f.w.checkProcesses();status(f.w,"processes","ok");check(!f.w.knownProgs.isEmpty(),"same-handle recovery failed");
        }});
        test("repair-collector-locale-streams-and-strictness",()->{
            ProcessBuilder pb=new ProcessBuilder("synthetic-unused");pb.environment().put("LC_ALL","conflicting-locale");Proc.collectorEnvironment(pb);
            check(pb.environment().get("LC_ALL").equals("C"),"collector inherited locale");
            Proc.Result r=Proc.collector(List.of("/bin/sh","-c","printf 'a\\r\\nb\\r'; printf 'e\\r\\nf\\r' >&2"),2);
            check(r.out().equals("a\nb\n") && r.err().equals("e\nf\n"),"both stream newlines");
            boolean strict=false;try {Proc.collector(List.of("/bin/sh","-c","printf '\\377'"),2);}catch(IOException e){strict=CollectionHealth.ioError(e).equals("collection-parse");}
            check(strict,"collector bad bytes accepted");
            check(Proc.run(List.of("/bin/sh","-c","printf 'tattletale.jar\\377\\r'"),2).out().equals("tattletale.jar\ufffd\n"),"ordinary subprocess strict");
        });
        test("repair-pid-identity-unknown-refuses-takeover",()->{try(Fixture f=new Fixture()) {
            Path pid=Path.of(f.w.dataDir,"tattletale.pid");
            for(Proc.Result result:List.of(new Proc.Result(7,"",""),new Proc.Result(0,"",""),new Proc.Result(0,"/other\n","warning"),new Proc.Result(0,"/other\n/other\n",""),new Proc.Result(0,Proc.text(new byte[]{'t','a','t','t','l','e','t','a','l','e','.','j','a','r',(byte)255}),""))) {
                Files.writeString(pid,"42\n");f.w.pidProbe=n->result;boolean refused=false;
                try{f.w.claimPidFile();}catch(Watch.Exit e){refused=true;}
                check(refused && Files.readString(pid).equals("42\n"),"occupied/unknown identity overwritten");
            }
            f.w.pidProbe=n->{throw new IOException("synthetic identity uncertainty");};boolean refused=false;try{f.w.claimPidFile();}catch(Watch.Exit e){refused=true;}check(refused,"probe failure took over");
            for(Proc.Result result:List.of(new Proc.Result(1,"",""),new Proc.Result(0,"/other-program\n",""))) {
                Files.writeString(pid,"42\n");f.w.pidProbe=n->result;f.w.claimPidFile();check(Files.readString(pid).equals(ProcessHandle.current().pid()+"\n"),"positive absence/other refused");f.w.releasePidFile();check(!Files.exists(pid),"owned pid not released");
            }
            Files.writeString(pid,"2147483648\n");f.w.pidProbe=n->{throw new AssertionError("bad PID reached probe");};f.w.claimPidFile();check(Files.readString(pid).equals(ProcessHandle.current().pid()+"\n"),"stale malformed pid not replaced");f.w.releasePidFile();
        }});
        test("repair-fatal-owned-finally-preserves-error",()->{try(Fixture f=new Fixture()) {
            Path pid=Path.of(f.w.dataDir,"tattletale.pid");Files.writeString(pid,ProcessHandle.current().pid()+"\n");f.w.pidFile=pid.toString();
            Db.DbException original=new Db.DbException("fixture-original");Db.Fatal fatal=new Db.Fatal(original);boolean caught=false;
            Thread worker=new Thread(()->{try{Thread.sleep(10000);}catch(InterruptedException expected){}});worker.start();
            try {f.w.withOwnedCleanup(()->{throw fatal;},worker);}catch(Db.Fatal e){caught=e==fatal && e.getCause()==original;}
            check(caught && f.w.stopped() && !worker.isAlive() && !Files.exists(pid),"fatal/owned cleanup lost");
            boolean closed=false;try{f.w.db.exec("SELECT 1;");}catch(Db.Fatal e){closed=true;}check(closed,"DB retained after fatal");
        }});
        test("repair-entry-markers-transient-retention-recovery",()->{try(Fixture f=new Fixture()) {
            Fake fake=new Fake(){boolean denied=true;public byte[] entry(String path)throws IOException{if(path.equals("/fixture/denied") && denied)throw new Watch.Unreadable("permission-denied");return super.entry(path);}};
            fake.files.put("/fixture/denied","readable".getBytes(StandardCharsets.UTF_8));fake.files.put("/fixture/a","a".getBytes(StandardCharsets.UTF_8));f.w.sources=fake;f.w.checkStartup();
            check(f.w.startup.size()==3 && fake.copies.size()==2 && health(f.w,"startup").get("error").equals("startup-unreadable"),"marker/copy contract");
            fake.files.put("/fixture/b","b".getBytes(StandardCharsets.UTF_8));f.w.checkStartup();check(f.w.startup.containsKey("/fixture/b") && count(f.w,"STARTUP+")==1,"marker concealed new peer");
            Map<String,String> before=new LinkedHashMap<>(f.w.startup);fake.failRead=true;f.w.checkStartup();check(f.w.startup.equals(before) && count(f.w,"STARTUP-")==0,"transient read removed entries");status(f.w,"crontab","ok");
            fake.failRead=false;f.w.sources=new Fake(){public List<String> files(){return new ArrayList<>(fake.files.keySet());}public byte[] read(String file){return fake.files.get(file);}public String textDiff(String a,String b,int l){return "(fixture diff)";}};
            f.w.clock=()->"2000-01-01T00:01:00Z";f.w.checkStartup();status(f.w,"startup","ok");check(count(f.w,"STARTUP~")==0 && health(f.w,"startup").get("lastSuccess").equals("2000-01-01T00:01:00Z"),"marker recovery duplicated/missed");
        }});
        test("repair-final-directory-dangling-versus-disappearance",()->{
            Path d=Files.createDirectory(root.resolve("entry-markers"));Path dir=Files.createDirectory(d.resolve("bundle"));Path link=d.resolve("dangling");Files.createSymbolicLink(link,d.resolve("absent"));Watch.Sources source=Proc::collector;
            for(Map.Entry<Path,String> e:Map.of(dir,"unreadable: directory",link,"unreadable: dangling-link").entrySet()) {boolean marked=false;try{source.entry(e.getKey().toString());}catch(Watch.Unreadable x){marked=x.marker.equals(e.getValue());}check(marked,"persistent state not marked");}
            Path ancestor=d.resolve("bad-parent");Files.createSymbolicLink(ancestor,d.resolve("absent-dir"));boolean rejected=false;try{source.entry(ancestor.resolve("file").toString());}catch(IOException e){rejected=!(e instanceof Watch.Unreadable);}check(rejected,"broken ancestor accepted as final marker");
            try(Fixture f=new Fixture()){f.fake.listing=List.of("/fixture/vanished");f.w.checkStartup();check(health(f.w,"startup").get("error").equals("startup-read"),"listed disappearance accepted");status(f.w,"crontab","ok");}
        });
        test("repair-pid-ascii-bounds-and-first-stream-completeness",()->{try(Fixture f=new Fixture()) {
            for(String row:List.of("2147483648 1 fixture /fixture/a\n","42 2147483648 fixture /fixture/a\n","٤٢ 1 fixture /fixture/a\n","42 1 fixture /fixture/a\npartial\n")) {
                Fake fake=new Fake(){public Proc.Result run(List<String> c,long t)throws IOException{if(c.getLast().equals("pid=,args="))throw new AssertionError("ps2 reached malformed primary");return super.run(c,t);}};fake.comm=new Proc.Result(0,row,"");f.w.sources=fake;f.w.checkProcesses();status(f.w,"processes","degraded");
            }
            f.w.sources=f.fake;f.fake.comm=new Proc.Result(0,"2147483647 0 fixture /fixture/a\n","");f.fake.args=new Proc.Result(0,"2147483647\n","");f.w.checkProcesses();status(f.w,"processes","ok");
            f.fake.comm=new Proc.Result(0,"42 1 fixture /fixture/a\n","");f.fake.args=new Proc.Result(0,"42\n","");
            for(String out:List.of("p2147483648\ncfixture\nn127.0.0.1:5\n","p42\ncfixture\n\nn127.0.0.1:5\n")){f.fake.lsof=new Proc.Result(0,out,"");f.w.checkListeners();status(f.w,"listeners","degraded");}
        }});
        test("repair-bare-listener-and-announcement-merge",()->{try(Fixture f=new Fixture()) {
            f.seed();f.fake.comm=new Proc.Result(0,"42 1 fixture bare\n","");f.fake.lookup=new Proc.Result(0,"bare\n","");f.fake.lsof=new Proc.Result(0,"p42\ncfixture\nn127.0.0.1:12345\n","");f.w.checkListeners();status(f.w,"listeners","degraded");check(count(f.w,"UNLISTEN")==0 && f.w.listeners.get(KEY).present,"bare listener erased stable key");
            f.w.announce.put("/fixture/pending","older");f.w.baseline.put("programs",false);f.fake.comm=new Proc.Result(0,"42 1 fixture /fixture/a\n","");f.w.checkProcesses();check(f.w.announce.containsKey("/fixture/pending") && f.w.announce.containsKey("/fixture/a"),"announcement merge lost old/new");
        }});
        test("repair-independent-errors-survive-peer-db-failure",()->{try(Fixture f=new Fixture()) {
            f.fake.failList=true;f.w.db.exec("CREATE TRIGGER reject_independent BEFORE INSERT ON startup_items BEGIN SELECT RAISE(ABORT,'fixture'); END;");f.w.checkStartup();
            check(health(f.w,"startup").get("error").equals("startup-read") && health(f.w,"crontab").get("error").equals("collection-db"),"DB error erased collection error");
            check(f.w.startup.isEmpty() && f.w.baseline.get("startup") && f.w.baseline.get("crontab"),"peer failure consumed baseline/mirror");
            f.fake.failList=false;f.fake.cron=new Proc.Result(7,"","");f.fake.files.put("/fixture/a",new byte[0]);f.w.checkStartup();
            check(health(f.w,"startup").get("error").equals("collection-db") && health(f.w,"crontab").get("error").equals("crontab-command"),"reverse peer error precedence");
        }});
        test("repair-readable-marker-readable-retains-history",()->{try(Fixture f=new Fixture()) {
            f.fake.files.put("/fixture/a","good".getBytes(StandardCharsets.UTF_8));f.w.checkStartup();String good=f.w.startup.get("/fixture/a"),copy=copy("/fixture/a",good);byte[] retained=f.fake.copies.get(copy);
            Fake denied=new Fake(){public byte[] entry(String path)throws IOException{throw new Watch.Unreadable("permission-denied");}};denied.files.put("/fixture/a",new byte[0]);f.w.sources=denied;f.w.clock=()->"2000-01-01T00:01:00Z";f.w.checkStartup();
            check(health(f.w,"startup").get("lastSuccess").equals(T) && count(f.w,"STARTUP~")==0 && f.fake.copies.get(copy)==retained,"marker erased success/history");
            check(Db.asLong(f.w.db.scalar("SELECT count(*) FROM startup_versions WHERE path='/fixture/a' AND copy_path IS NULL;"))==1,"marker saved invented copy");
            f.w.checkStartup();check(count(f.w,"STARTUP~")==0,"persistent marker duplicate change");
            f.w.sources=f.fake;f.w.clock=()->"2000-01-01T00:02:00Z";f.w.checkStartup();check(count(f.w,"STARTUP~")==0 && health(f.w,"startup").get("lastSuccess").equals("2000-01-01T00:02:00Z"),"readable recovery missing/duplicated");
        }});
        test("repair-synthetic-directory-link-do-not-hide-readable-peer",()->{try(Fixture f=new Fixture()) {
            Path dir=Files.createDirectory(root.resolve("inventory-entries")),bundle=Files.createDirectory(dir.resolve("bundle")),link=dir.resolve("dangling"),file=dir.resolve("readable");Files.createSymbolicLink(link,dir.resolve("absent"));Files.writeString(file,"readable bytes");
            Watch.Sources actual=Proc::collector;Fake fake=new Fake(){public byte[] entry(String name)throws IOException{return actual.entry(name);}};
            for(Path path:List.of(bundle,link,file))fake.files.put(path.toString(),null);f.w.sources=fake;f.w.checkStartup();
            check(f.w.startup.get(bundle.toString()).equals("unreadable: directory") && f.w.startup.get(link.toString()).equals("unreadable: dangling-link") && f.w.startup.get(file.toString()).equals(digest("readable bytes")),"entry markers/readable peer");
            check(health(f.w,"startup").get("error").equals("startup-unreadable") && health(f.w,"startup").get("lastSuccess")==null && !f.w.baseline.get("startup"),"marked baseline all-clear");status(f.w,"crontab","ok");
        }});
        test("repair-command-newlines-do-not-normalize-files",()->{try(Fixture f=new Fixture()) {
            f.fake.cron=new Proc.Result(0,Proc.strictText("fixture\r\ncron\r".getBytes(StandardCharsets.UTF_8)),"");f.fake.files.put("/fixture/raw","a\r".getBytes(StandardCharsets.UTF_8));f.w.checkStartup();String raw=f.w.startup.get("/fixture/raw"),cron=f.w.startup.get("crontab -l");
            f.fake.cron=new Proc.Result(0,Proc.strictText("fixture\ncron\n".getBytes(StandardCharsets.UTF_8)),"");f.fake.files.put("/fixture/raw","a\n".getBytes(StandardCharsets.UTF_8));f.w.checkStartup();
            check(f.w.startup.get("crontab -l").equals(cron) && !f.w.startup.get("/fixture/raw").equals(raw) && count(f.w,"STARTUP~")==1,"command normalization changed file bytes/cron identity");
        }});
        test("repair-owned-finally-never-removes-replaced-pid",()->{try(Fixture f=new Fixture()) {
            Path pid=Path.of(f.w.dataDir,"tattletale.pid");Files.writeString(pid,"42\n");f.w.pidFile=pid.toString();Db.Fatal fatal=new Db.Fatal(new Db.DbException("fixture"));
            f.w.ownedWorker(()->{throw fatal;});check(f.w.workerDatabaseFailure==fatal && f.w.stopped(),"worker fatal failed to stop owner");
            boolean propagated=false;try{f.w.withOwnedCleanup(()->{});}catch(Db.Fatal e){propagated=e==fatal;}
            check(propagated && Files.readString(pid).equals("42\n"),"cleanup removed another owner/lost late worker failure");
        }});
        test("repair-lsof-warning-distinct-retains-last-known",()->{try(Fixture f=new Fixture()) {
            f.seed();f.fake.lsof=new Proc.Result(0,"p42\ncfixture\nn127.0.0.1:12345\n","");f.w.checkListeners();status(f.w,"listeners","ok");
            Map<String,Watch.Listener> retained=f.w.listeners;
            Map<String,String> retainedDirty=f.w.dirtyListeners;Map<String,Boolean> retainedBaselines=new HashMap<>(f.w.baseline);
            List<Map<String,Object>> beforeRows=f.w.db.query("SELECT * FROM listeners ORDER BY key;");
            long beforeEvents=Db.asLong(f.w.db.scalar("SELECT count(*) FROM events;"));
            f.w.clock=()->"2000-01-01T00:01:00Z";
            // Structurally valid records would replace the old key if the warning were admitted.
            f.fake.lsof=new Proc.Result(0,"p42\ncfixture\nn192.0.2.10:23456\n","lsof: WARNING: fixture coverage incomplete\n");
            f.fake.failPs=true;f.w.checkListeners();status(f.w,"listeners","degraded");
            check(health(f.w,"listeners").get("error").equals("lsof-warning"),"warning lost distinct health code");
            check(health(f.w,"listeners").get("lastSuccess").equals(T) && health(f.w,"listeners").get("lastAttempt").equals("2000-01-01T00:01:00Z"),"warning advanced lastSuccess or hid attempt");
            check(f.w.listeners==retained && retained.get(KEY).present && f.w.db.query("SELECT * FROM listeners ORDER BY key;").equals(beforeRows),"warning adopted inventory/false removal");
            check(f.w.dirtyListeners==retainedDirty && f.w.baseline.equals(retainedBaselines),"warning changed dirty mirror/baseline");
            check(Db.asLong(f.w.db.scalar("SELECT count(*) FROM events;"))==beforeEvents+1 && count(f.w,"UNLISTEN")==0,"warning NOTE missing or unexpected event");
            check(f.w.db.query("SELECT kind,message FROM events WHERE kind='NOTE' ORDER BY id;").equals(List.of(event("NOTE","listeners collection degraded: lsof-warning"))),"fixed warning NOTE");
            f.w.checkListeners();check(Db.asLong(f.w.db.scalar("SELECT count(*) FROM events;"))==beforeEvents+1,"repeated warning NOTE not deduplicated");
            f.fake.failPs=false;f.fake.lsof=new Proc.Result(0,"p42\ncfixture\nn127.0.0.1:12345\n","");f.w.clock=()->"2000-01-01T00:02:00Z";f.w.checkListeners();status(f.w,"listeners","ok");
            f.fake.lsof=new Proc.Result(0,"p42\ncfixture\nn192.0.2.10:23456\n","lsof: WARNING: fixture coverage incomplete\n");f.w.clock=()->"2000-01-01T00:03:00Z";f.w.checkListeners();
            check(count(f.w,"NOTE")==2 && count(f.w,"UNLISTEN")==0 && health(f.w,"listeners").get("lastSuccess").equals("2000-01-01T00:02:00Z"),"warning after recovery did not emit exactly once");
            String log=Files.readString(Path.of(f.w.logPath));check(log.contains("listeners collection degraded: lsof-warning") && !log.contains("coverage incomplete"),"warning log missing/raw stderr leaked");
            check(!Json.write(f.w.collectionHealth.snapshot()).contains("coverage incomplete"),"raw warning leaked into health");
            for(String diagnostic:List.of(" ","arbitrary fixture diagnostic")) {
                boolean rejected=false;try{CollectionHealth.command("lsof",new Proc.Result(0,"",diagnostic));}catch(CollectionHealth.Rejected e){rejected=e.code.equals("lsof-warning");}
                check(rejected,"exit0 stderr did not use warning code");
            }
            boolean failure=false;try{CollectionHealth.command("lsof",new Proc.Result(7,"","WARNING"));}catch(CollectionHealth.Rejected e){failure=e.code.equals("lsof-command");}check(failure,"nonzero status reclassified as warning");
        }});
        test("repair-dangling-pid-link-refuses-unknown-target",()->{try(Fixture f=new Fixture()) {
            Path pid=Path.of(f.w.dataDir,"tattletale.pid"),target=Path.of(f.w.dataDir,"missing-pid-target");Files.createSymbolicLink(pid,target);
            f.w.pidProbe=n->{throw new AssertionError("dangling PID reached process probe");};boolean refused=false;
            try{f.w.claimPidFile();}catch(Watch.Exit e){refused=true;}
            check(refused && Files.isSymbolicLink(pid) && !Files.exists(target),"dangling PID identity was replaced/followed");
        }try(Fixture f=new Fixture()) {
            f.w.pidProbe=n->{throw new AssertionError("absent PID reached process probe");};f.w.claimPidFile();Path pid=Path.of(f.w.dataDir,"tattletale.pid");
            check(Files.readString(pid).equals(ProcessHandle.current().pid()+"\n"),"true first-start absence refused");f.w.releasePidFile();check(!Files.exists(pid),"own first-start PID not released");
        }});
        test("repair-unreadable-marker-removal-has-no-invented-copy",()->{try(Fixture f=new Fixture()) {
            Fake fake=new Fake(){public byte[] entry(String path)throws IOException{throw new Watch.Unreadable("permission-denied");}};fake.files.put("/fixture/denied",new byte[0]);f.w.sources=fake;f.w.checkStartup();
            f.w.clock=()->"2000-01-01T00:01:00Z";fake.files.clear();f.w.checkStartup();
            List<Map<String,Object>> events=f.w.db.query("SELECT kind,message FROM events WHERE kind='STARTUP-' ORDER BY id;");
            check(events.equals(List.of(event("STARTUP-","removed: /fixture/denied | last copy: None"))),"marker removal invented a last-copy path: "+events);
            check(!f.w.startup.containsKey("/fixture/denied") && Db.asLong(f.w.db.scalar("SELECT count(*) FROM startup_versions WHERE path='/fixture/denied' AND copy_path IS NOT NULL;"))==0,"marker removal created copy/version");status(f.w,"startup","ok");
        }});
        test("repair-filesystem-copy-failure-keeps-files-adopts-cron",()->{try(Fixture f=new Fixture()) {
            class CopyFake extends Fake {boolean reject;public void copy(String path,byte[] value)throws IOException{if(reject && path.contains("/fixture_a/"))throw new IOException("fixture file copy failed");super.copy(path,value);}}
            CopyFake fake=new CopyFake();fake.files.put("/fixture/a","old file".getBytes(StandardCharsets.UTF_8));fake.cron=new Proc.Result(0,"old cron","");f.w.sources=fake;f.w.checkStartup();String old=f.w.startup.get("/fixture/a");
            fake.reject=true;fake.files.put("/fixture/a","new file".getBytes(StandardCharsets.UTF_8));fake.cron=new Proc.Result(0,"new cron","");f.w.clock=()->"2000-01-01T00:01:00Z";f.w.checkStartup();
            check(health(f.w,"startup").get("error").equals("collection-io") && health(f.w,"startup").get("lastSuccess").equals(T),"file copy failure health");status(f.w,"crontab","ok");
            check(f.w.startup.get("/fixture/a").equals(old) && f.w.startup.get("crontab -l").equals(digest("new cron")) && f.w.crontabText.equals("new cron"),"file copy failure discarded valid cron/adopted files");
            check(f.w.db.query("SELECT kind,message FROM events WHERE kind='STARTUP~' ORDER BY id;").equals(List.of(event("STARTUP~","changed: crontab -l | before: "+copy("crontab -l",digest("old cron"))+" | after: "+copy("crontab -l",digest("new cron"))+"\n(fixture diff)"))),"file copy failure event isolation");
        }});
        test("repair-cron-copy-failure-keeps-cron-adopts-files",()->{try(Fixture f=new Fixture()) {
            class CopyFake extends Fake {boolean reject;public void copy(String path,byte[] value)throws IOException{if(reject && path.contains("/crontab_-l/"))throw new IOException("fixture cron copy failed");super.copy(path,value);}}
            CopyFake fake=new CopyFake();fake.files.put("/fixture/a","old file".getBytes(StandardCharsets.UTF_8));fake.cron=new Proc.Result(0,"old cron","");f.w.sources=fake;f.w.checkStartup();String old=f.w.startup.get("crontab -l");
            fake.reject=true;fake.files.put("/fixture/a","new file".getBytes(StandardCharsets.UTF_8));fake.cron=new Proc.Result(0,"new cron","");f.w.clock=()->"2000-01-01T00:01:00Z";f.w.checkStartup();
            check(health(f.w,"crontab").get("error").equals("collection-io") && health(f.w,"crontab").get("lastSuccess").equals(T),"cron copy failure health");status(f.w,"startup","ok");
            check(f.w.startup.get("crontab -l").equals(old) && f.w.crontabText.equals("old cron") && f.w.startup.get("/fixture/a").equals(digest("new file")),"cron copy failure discarded valid files/adopted cron");
            check(f.w.db.query("SELECT kind,message FROM events WHERE kind='STARTUP~' ORDER BY id;").equals(List.of(event("STARTUP~","changed: /fixture/a | before: "+copy("/fixture/a",digest("old file"))+" | after: "+copy("/fixture/a",digest("new file"))+"\n(fixture diff)"))),"cron copy failure event isolation");
        }});
        test("repair-partition-copy-decode-causes-are-parse",()->{try(Fixture f=new Fixture()) {
            class CopyFake extends Fake {boolean failFile=true;public void copy(String path,byte[] value)throws IOException{if(path.contains(failFile?"/fixture_a/":"/crontab_-l/"))throw new IOException("fixture decode failure",new java.nio.charset.MalformedInputException(1));super.copy(path,value);}}
            CopyFake fake=new CopyFake();fake.files.put("/fixture/a",new byte[0]);f.w.sources=fake;f.w.checkStartup();
            check(health(f.w,"startup").get("error").equals("collection-parse") && !f.w.startup.containsKey("/fixture/a"),"file copy decode classification/adoption");status(f.w,"crontab","ok");
            fake.failFile=false;fake.cron=new Proc.Result(0,"changed cron","");f.w.checkStartup();
            status(f.w,"startup","ok");check(health(f.w,"crontab").get("error").equals("collection-parse") && f.w.crontabText.isEmpty(),"cron copy decode classification/adoption");
        }});
        startupTransitions();
    }
    static String digest(String value) {return HexFormat.of().formatHex(Watch.sha256().digest(value.getBytes(StandardCharsets.UTF_8)));}
    static String copy(String path,String hash) {return "/fixture/copies/"+Watch.safeName(path)+"/"+hash.substring(0,Math.min(16,hash.length()));}
    static Map<String,Object> event(String kind,String message) {return Map.of("kind",kind,"message",message);}
    static Map<String,Object> transition(Watch w,String name) throws Exception {
        Map<String,Object> row=new LinkedHashMap<>();row.put("name",name);row.putAll(snapshot(w));
        row.put("startupKeys",new ArrayList<>(((Map<?,?>)w.pageMap().get("startup")).keySet()));
        row.put("baselines",Map.of("startup",w.baseline.get("startup"),"crontab",w.baseline.get("crontab")));return row;
    }
    static void startupTransitions() {
        test("repair-shared-eight-startup-transitions-ledger-reload",()->{try(Fixture f=new Fixture()) {
            List<Object> rows=new ArrayList<>();List<Map<String,Object>> expected=new ArrayList<>();
            f.fake.cron=new Proc.Result(1,"","crontab: no crontab for fixture\n");
            f.fake.files.put("/fixture/c","c0".getBytes(StandardCharsets.UTF_8));f.fake.files.put("/fixture/a","a0".getBytes(StandardCharsets.UTF_8));
            f.w.checkStartup();rows.add(transition(f.w,"startupBaseline"));
            expected.add(event("BASELINE","startup items: 2 recorded, copies in /fixture/copies"));expected.add(event("BASELINE","crontab: 1 recorded, copies in /fixture/copies"));
            check(f.w.db.query("SELECT kind,message FROM events ORDER BY id;").equals(expected),"T0 independent baseline ledger");
            f.w.clock=()->"2000-01-01T00:01:00Z";f.fake.files.clear();f.fake.files.put("/fixture/c","c1".getBytes(StandardCharsets.UTF_8));f.fake.files.put("/fixture/b","b0".getBytes(StandardCharsets.UTF_8));f.w.checkStartup();rows.add(transition(f.w,"startupTransition"));
            expected.add(event("STARTUP-","removed: /fixture/a | last copy: "+copy("/fixture/a",digest("a0"))));
            expected.add(event("STARTUP+","added: /fixture/b | copy: "+copy("/fixture/b",digest("b0"))));
            expected.add(event("STARTUP~","changed: /fixture/c | before: "+copy("/fixture/c",digest("c0"))+" | after: "+copy("/fixture/c",digest("c1"))+"\n(fixture diff)"));
            check(f.w.db.query("SELECT kind,message FROM events ORDER BY id;").equals(expected),"T1 union ledger must remove a, add b, change c");
            long versions=Db.asLong(f.w.db.scalar("SELECT count(*) FROM startup_versions;"));
            f.w.clock=()->"2000-01-01T00:02:00Z";f.w.checkStartup();rows.add(transition(f.w,"startupRepeated"));check(f.w.db.query("SELECT kind,message FROM events ORDER BY id;").equals(expected) && Db.asLong(f.w.db.scalar("SELECT count(*) FROM startup_versions;"))==versions,"T2 duplicate events/versions");
            f.w.clock=()->"2000-01-01T00:03:00Z";f.fake.files.put("/fixture/b","b1".getBytes(StandardCharsets.UTF_8));f.fake.cron=new Proc.Result(7,"","");f.w.checkStartup();rows.add(transition(f.w,"startupCronFailure"));
            expected.add(event("STARTUP~","changed: /fixture/b | before: "+copy("/fixture/b",digest("b0"))+" | after: "+copy("/fixture/b",digest("b1"))+"\n(fixture diff)"));
            check(health(f.w,"crontab").get("lastSuccess").equals("2000-01-01T00:02:00Z") && f.w.db.query("SELECT kind,message FROM events ORDER BY id;").equals(expected),"T3 independent filesystem/cron");
            f.w.clock=()->"2000-01-01T00:04:00Z";f.fake.failRead=true;String cron="* * * * * fixture\n";f.fake.cron=new Proc.Result(0,cron,"");f.w.checkStartup();rows.add(transition(f.w,"startupFilesystemFailure"));
            expected.add(event("STARTUP~","changed: crontab -l | before: "+copy("crontab -l","none")+" | after: "+copy("crontab -l",digest(cron))+"\n(fixture diff)"));
            check(health(f.w,"startup").get("lastSuccess").equals("2000-01-01T00:03:00Z") && f.w.db.query("SELECT kind,message FROM events ORDER BY id;").equals(expected),"T4 cron suppressed/files changed");
            f.w.clock=()->"2000-01-01T00:05:00Z";f.fake.failRead=false;f.fake.files.put("/fixture/z","z0".getBytes(StandardCharsets.UTF_8));Map<String,String> before=f.w.startup;
            f.w.db.exec("CREATE TRIGGER shared_transition_abort BEFORE INSERT ON startup_items BEGIN SELECT RAISE(ABORT,'fixture'); END;");f.w.checkStartup();rows.add(transition(f.w,"startupDbFailure"));
            check(f.w.startup==before && f.w.db.query("SELECT kind,message FROM events ORDER BY id;").equals(expected),"T5 DB failure adopted mirrors/events");
            f.w.db.exec("DROP TRIGGER shared_transition_abort;");f.w.clock=()->"2000-01-01T00:06:00Z";f.w.checkStartup();rows.add(transition(f.w,"startupRecovered"));
            expected.add(event("STARTUP+","added: /fixture/z | copy: "+copy("/fixture/z",digest("z0"))));
            check(f.w.db.query("SELECT kind,message FROM events ORDER BY id;").equals(expected),"T6 incorrect recovery ledger");
            check(new ArrayList<>(f.w.startup.keySet()).equals(List.of("/fixture/b","/fixture/c","/fixture/z","crontab -l")),"T6 key order");
            f.w.db.close();
            Watch reload=new Watch(f.w.logPath,f.w.dbPath,30,300,List.of(),false,100000,1,3,f.w.mapPath,0,0,f.w.dashboard);
            try {reload.sources=f.fake;reload.clock=()->"2000-01-01T00:07:00Z";reload.loadState();rows.add(transition(reload,"startupReloaded"));
                check(new ArrayList<>(reload.startup.keySet()).equals(List.of("/fixture/b","/fixture/c","/fixture/z","crontab -l")) && reload.db.query("SELECT kind,message FROM events ORDER BY id;").equals(expected),"T7 reload inventory/event order");
                for(String k:CollectionHealth.KEYS)status(reload,k,"unknown");check(!reload.baseline.get("startup") && !reload.baseline.get("crontab"),"reload partition baseline");
            } finally {reload.db.close();}
            check(rows.size()==8,"required transition denominator");parity.put("startupTransitions",rows);
        }});
    }

}
