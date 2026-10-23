package dev.tattletale;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.time.Instant;
import java.util.*;

/** Synthetic sources and explicit temporary SQLite only. Never Watch.run/Main/FFI. */
public final class CollectionHealthTest {
    static final String T="2000-01-01T00:00:00Z", KEY="/fixture/a 127.0.0.1:12345";
    static Path root;
    static int serial;
    static final List<Map<String,Object>> results=new ArrayList<>();
    static final Map<String,Object> parity=new LinkedHashMap<>();
    interface Test { void run() throws Exception; }
    static void check(boolean condition,String message) { if(!condition) throw new AssertionError(message); }
    static void test(String name,Test body) {
        long begin=System.nanoTime(); String stamp=Instant.now().toString();
        Map<String,Object> row=new LinkedHashMap<>();row.put("name",name);row.put("timestamp",stamp);
        try { body.run();row.put("status","pass");System.out.println("PASS "+name); }
        catch(Throwable e) {row.put("status",e instanceof AssertionError?"failure":"error");row.put("detail",e.toString());System.out.println("FAIL "+name+" "+e);}
        row.put("seconds",(System.nanoTime()-begin)/1e9);results.add(row);
    }
    static class Fake implements Watch.Sources {
        Proc.Result comm=new Proc.Result(0,"42 1 fixture /fixture/a\n","");
        Proc.Result args=new Proc.Result(0,"42 /fixture/a --synthetic\n","");
        Proc.Result lsof=new Proc.Result(0,"","");
        Proc.Result cron=new Proc.Result(0,"","");
        IOException failure;
        boolean failRead,failList,failCopy,realCopies,failPs;
        List<String> listing=List.of();
        Proc.Result lookup=new Proc.Result(0,"/fixture/a\n","");
        int cronCalls;
        Map<String,byte[]> files=new LinkedHashMap<>();
        public Proc.Result run(List<String> c,long timeout) throws IOException {
            if(failure!=null) throw failure;
            if(failPs && c.getFirst().equals("ps")) throw new AssertionError("empty lsof must not call ps");
            return switch(c.getFirst()) {
                case "ps" -> c.contains("-p")?lookup:c.getLast().equals("pid=,args=")?args:comm;
                case "lsof" -> lsof;
                case "crontab" -> {cronCalls++;yield cron;}
                default -> throw new AssertionError("unoffered command");
            };
        }
        public String copyRoot(String actual) { return realCopies?actual:"/fixture/copies"; }
        final Map<String,byte[]> copies=new HashMap<>();
        public void copy(String dest,byte[] value) throws IOException { if(failCopy)throw new IOException("synthetic copy failure");if(realCopies)Watch.Sources.super.copy(dest,value);else copies.put(dest,value.clone()); }
        public byte[] copyBytes(String path) throws IOException { if(realCopies)return Watch.Sources.super.copyBytes(path);byte[] b=copies.get(path);if(b==null)throw new IOException("synthetic missing copy");return b; }
        public String textDiff(String before,String after,int limit) {return before==null || after==null?"(no text diff: binary or missing copy)":"(fixture diff)";}
        public String pidPath(long pid) { return null; }
        public List<String> dirs() {return failList || !listing.isEmpty()?List.of("/fixture/dir"):List.of();}
        public List<String> files() {return new ArrayList<>(files.keySet());}
        public List<String> list(String d) throws IOException {if(failList)throw new IOException("synthetic list failure");return listing;}
        public byte[] read(String f) throws IOException {if(failRead) throw new IOException("PRIVATE_SENTINEL /private/fixture");return files.get(f);}
        public byte[] entry(String f) throws IOException {try{return read(f);}catch(AccessDeniedException e){throw new Watch.Unreadable("permission-denied");}}
    }
    static final class Fixture implements AutoCloseable {
        final Watch w; final Fake fake=new Fake();
        Fixture() throws Exception {
            Path d=Files.createDirectory(root.resolve("case-"+(++serial)));
            w=new Watch(d.resolve("log").toString(),d.resolve("db").toString(),30,300,List.of(),false,100000,1,3,d.resolve("absent-map").toString(),0,0,d.resolve("absent-page").toString());
            w.clock=()->T; w.sources=fake; w.loadState();
        }
        public void close() {w.db.close();}
        void seed() throws Exception {
            w.db.exec(Db.bind("INSERT INTO listeners(key,exe,address,port,command,pid,user,args,chain,present,exposed,first_seen,last_seen) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",KEY,"/fixture/a","127.0.0.1",12345,"fixture",42,"fixture","","?",1,0,T,T));
            w.loadState();
        }
    }
    static Map<?,?> health(Watch w,String key) {return (Map<?,?>)w.collectionHealth.snapshot().get(key);}
    static void status(Watch w,String key,String value) {check(health(w,key).get("status").equals(value),key+" status "+health(w,key));}
    static long count(Watch w,String kind) throws Exception {return Db.asLong(w.db.scalar(Db.bind("SELECT count(*) FROM events WHERE kind=?;",kind)));}
    static Map<String,Object> snapshot(Watch w) throws Exception {
        w.writePageData(w.dataDir,w.pageMap());
        String text=Files.readString(Path.of(w.dataDir,"tattletale-data.js"));
        Map<?,?> payload=(Map<?,?>)Json.parse(text.substring("window.TATTLETALE = ".length(),text.length()-2));
        Map<String,Object> r=new LinkedHashMap<>();r.put("formatVersion",payload.get("formatVersion"));r.put("schemaVersion",w.db.scalar("SELECT max(version) FROM schema_version;"));
        r.put("collectionHealth",payload.get("collectionHealth"));r.put("map",payload.get("map"));r.put("events",w.db.query("SELECT kind,message FROM events ORDER BY id;"));return r;
    }
    @SuppressWarnings("unchecked") public static void main(String[] a) throws Exception {
        Thread.ofPlatform().daemon().start(()->{try {Thread.sleep(60000);System.err.println("fixture deadline exceeded");System.exit(124);}catch(InterruptedException ignored){}});
        Path xml=null, fixture=null, parityPath=null;
        for(int i=0;i<a.length;i+=2) {
            switch(a[i]) {case "--xml" -> xml=Path.of(a[i+1]);case "--fixtures" -> fixture=Path.of(a[i+1]);case "--scratch" -> root=Path.of(a[i+1]);case "--parity-output" -> parityPath=Path.of(a[i+1]);default -> throw new IllegalArgumentException("unknown test flag");}
        }
        if(xml==null || fixture==null || root==null) throw new IllegalArgumentException("--xml --fixtures --scratch required");
        Files.createDirectory(root);
        Map<String,Object> shared=(Map<String,Object>)Json.parse(Files.readString(fixture));
        List<Object> scopes=new ArrayList<>(),commands=new ArrayList<>();
        for(Object o:(List<?>)shared.get("scopeCases")) {
            Map<String,Object> c=(Map<String,Object>)o; String host=(String)c.get("host");
            test("bind-scope-"+scopes.size(),()->check(CollectionHealth.bindScope(host).equals(c.get("expected")),"scope fixture "+host));
            scopes.add(Map.of("host",host,"actual",CollectionHealth.bindScope(host)));
        }
        for(Object o:(List<?>)shared.get("commandCases")) {
            Map<String,Object> c=(Map<String,Object>)o;String tool=(String)c.get("tool");
            Proc.Result r=new Proc.Result(((Number)c.get("code")).intValue(),(String)c.get("out"),(String)c.get("err"));
            String result;try {result=CollectionHealth.command(tool,r);} catch(CollectionHealth.Rejected e) {result="degraded";}
            final String actual=result;
            test("command-policy-"+commands.size(),()->check(actual.equals(c.get("expected")),"command policy "+actual));
            commands.add(Map.of("tool",tool,"code",r.code(),"out",r.out(),"err",r.err(),"actual",actual));
        }
        parity.put("fixtureVersion",1);parity.put("scopes",scopes);parity.put("commands",commands);
        test("initial-epoch-health",()->{try(Fixture f=new Fixture()) {for(String k:CollectionHealth.KEYS) {status(f.w,k,"unknown");check(health(f.w,k).get("lastAttempt")==null,"initial attempt");}}});
        test("listener-failure-partial-recovery",()->{try(Fixture f=new Fixture()) {
            f.seed();f.fake.lsof=new Proc.Result(0,"p42\ncfixture\nn127.0.0.1:12345\n","");f.w.checkListeners();status(f.w,"listeners","ok");

            f.fake.lsof=new Proc.Result(7,"","");f.w.checkListeners();status(f.w,"listeners","degraded");
            check(f.w.listeners.get(KEY).present && count(f.w,"UNLISTEN")==0,"failed lsof erased last-good");check(T.equals(health(f.w,"listeners").get("lastSuccess")),"success retained");
            f.fake.lsof=new Proc.Result(0,"p42\ncfixture\nn127.0.0.1:12345\np43\ncpartial\n","");f.w.checkListeners();status(f.w,"listeners","degraded");check(f.w.listeners.size()==1 && f.w.listeners.get(KEY).present,"partial adoption");
            f.fake.lsof=new Proc.Result(1,"","");f.w.checkListeners();status(f.w,"listeners","ok");check(!f.w.listeners.get(KEY).present && count(f.w,"UNLISTEN")==1,"complete recovery removal");
        }});
        test("listener-db-rollback",()->{try(Fixture f=new Fixture()) {f.seed();f.w.db.exec("CREATE TRIGGER reject_listener BEFORE UPDATE ON listeners BEGIN SELECT RAISE(ABORT,'fixture'); END;");f.w.checkListeners();status(f.w,"listeners","degraded");check(f.w.listeners.get(KEY).present && count(f.w,"UNLISTEN")==0,"rollback mirror/event");check(Db.asLong(f.w.db.scalar("SELECT present FROM listeners;"))==1,"DB rollback");}});
        test("listener-metadata-race",()->{try(Fixture f=new Fixture()) {f.fake.lsof=new Proc.Result(0,"p99\ncfixture\nn192.0.2.10:12345\n","");f.w.checkListeners();status(f.w,"listeners","ok");check(f.w.listeners.containsKey("/fixture/a 192.0.2.10:12345"),"checked lookup stable executable");}});
        test("process-two-samples-churn-failure-recovery",()->{try(Fixture f=new Fixture()) {
            f.fake.args=new Proc.Result(0,"99 /fixture/vanished\n","");f.w.checkProcesses();status(f.w,"processes","ok");check(f.w.knownProgs.contains("/fixture/a"),"normal PID churn");
            Map<Long,String> old=f.w.prevPids;
            f.fake.args=new Proc.Result(7,"","");f.w.checkProcesses();status(f.w,"processes","degraded");check(f.w.prevPids==old,"failed argv adopted");
            f.fake.args=new Proc.Result(0,"42 /fixture/a --synthetic\n","");f.w.checkProcesses();status(f.w,"processes","ok");
        }});
        test("process-empty-and-partial",()->{try(Fixture f=new Fixture()) {f.fake.comm=new Proc.Result(0,"","");f.w.checkProcesses();status(f.w,"processes","degraded");check(f.w.baseline.get("programs") && f.w.knownProgs.isEmpty(),"empty consumed baseline");f.fake.comm=new Proc.Result(0,"42 1 fixture /fixture/a\nmalformed\n","");f.w.checkProcesses();check(f.w.knownProgs.isEmpty() && f.w.identQ.isEmpty(),"partial mirror/queue");}});
        test("process-db-rollback",()->{try(Fixture f=new Fixture()) {f.w.db.exec("CREATE TRIGGER reject_program BEFORE INSERT ON programs BEGIN SELECT RAISE(ABORT,'fixture'); END;");f.w.checkProcesses();status(f.w,"processes","degraded");check(f.w.knownProgs.isEmpty() && f.w.prevPids==null && f.w.identQ.isEmpty() && f.w.baseline.get("programs"),"process rollback");check(count(f.w,"BASELINE")==0,"rollback event");}});
        test("startup-cron-staging-recovery",()->{try(Fixture f=new Fixture()) {
            f.fake.files.put("/fixture/startup", "first\n".getBytes(StandardCharsets.UTF_8));f.w.checkStartup();status(f.w,"startup","ok");status(f.w,"crontab","ok");
            Map<String,String> old=f.w.startup;String text=f.w.crontabText;long events=count(f.w,"STARTUP-");
            f.fake.files.clear();f.fake.cron=new Proc.Result(7,"partial","PRIVATE_SENTINEL");f.w.checkStartup();status(f.w,"startup","ok");status(f.w,"crontab","degraded");check(!f.w.startup.containsKey("/fixture/startup") && f.w.crontabText.equals(text) && count(f.w,"STARTUP-")==events+1,"independent files not adopted");
            f.fake.cron=new Proc.Result(1,"","crontab: no crontab for fixture\n");f.w.checkStartup();status(f.w,"startup","ok");check(!f.w.startup.containsKey("/fixture/startup") && count(f.w,"STARTUP-")==events+1,"startup recovery");
        }});
        test("startup-before-crontab-failure",()->{try(Fixture f=new Fixture()) {f.fake.files.put("/fixture/startup",new byte[0]);f.fake.failRead=true;f.w.checkStartup();status(f.w,"startup","degraded");status(f.w,"crontab","ok");check(f.fake.cronCalls==1 && f.w.startup.size()==1 && f.w.baseline.get("startup"),"independent cron staging");check(!Json.write(f.w.collectionHealth.snapshot()).contains("PRIVATE_SENTINEL"),"private diagnostic leak");}});
        test("startup-db-rollback",()->{try(Fixture f=new Fixture()) {f.w.db.exec("CREATE TRIGGER reject_startup BEFORE INSERT ON startup_items BEGIN SELECT RAISE(ABORT,'fixture'); END;");f.w.checkStartup();status(f.w,"startup","degraded");status(f.w,"crontab","degraded");check(f.w.startup.isEmpty() && f.w.crontabText.isEmpty() && f.w.baseline.get("startup") && count(f.w,"BASELINE")==0,"startup DB rollback");}});
        test("collector-stream-and-decode-failure",()->{try(Fixture f=new Fixture()) {f.fake.failure=new IOException("PRIVATE_SENTINEL");f.w.checkProcesses();status(f.w,"processes","degraded");check(!Json.write(f.w.collectionHealth.snapshot()).contains("PRIVATE_SENTINEL"),"io leak");}boolean rejected=false;try {Proc.strictText(new byte[]{(byte)0xff});}catch(java.nio.charset.CharacterCodingException e){rejected=true;}check(rejected,"lossy decode accepted");});
        test("format-page-and-persisted-epoch",()->{try(Fixture f=new Fixture()) {f.seed();for(String k:CollectionHealth.KEYS)status(f.w,k,"unknown");f.w.save();String page=Files.readString(Path.of(f.w.dataDir,"tattletale-data.js"));Map<?,?> payload=(Map<?,?>)Json.parse(page.substring("window.TATTLETALE = ".length(),page.length()-2));check(((Number)payload.get("formatVersion")).intValue()==2,"format version");check(((Map<?,?>)payload.get("collectionHealth")).size()==4,"health keys");Map<?,?> ls=(Map<?,?>)((Map<?,?>)payload.get("map")).get("listeners");check(((Map<?,?>)ls.get(KEY)).get("bindScope").equals("loopback"),"scope projection");check(Db.asLong(f.w.db.scalar("SELECT max(version) FROM schema_version;"))==1,"DB schema changed");}});
        test("listener-key-enrichment-failure",()->{try(Fixture f=new Fixture()) {f.seed();f.fake.lsof=new Proc.Result(0,"p99\ncfixture\nn127.0.0.1:12345\n","");f.fake.lookup=new Proc.Result(7,"/fixture/a\n","");f.w.checkListeners();status(f.w,"listeners","degraded");check(f.w.listeners.size()==1 && f.w.listeners.get(KEY).present && count(f.w,"UNLISTEN")==0,"unstable lookup erased key");}});
        test("health-attempt-success-recovery-times",()->{try(Fixture f=new Fixture()) {f.w.checkListeners();f.w.clock=()->"2000-01-01T00:00:01Z";f.fake.lsof=new Proc.Result(7,"","");f.w.checkListeners();check(health(f.w,"listeners").get("lastAttempt").equals("2000-01-01T00:00:01Z") && health(f.w,"listeners").get("lastSuccess").equals(T),"failure timestamp retention");f.w.clock=()->"2000-01-01T00:00:02Z";f.fake.lsof=new Proc.Result(0,"","");f.w.checkListeners();check(health(f.w,"listeners").get("lastSuccess").equals("2000-01-01T00:00:02Z") && health(f.w,"listeners").get("error")==null,"recovery timestamp/error");}});
        test("startup-nonempty-partial-and-copy-rejection",()->{try(Fixture f=new Fixture()) {f.fake.files.put("/fixture/startup","old".getBytes(StandardCharsets.UTF_8));f.w.checkStartup();Map<String,String> old=f.w.startup;long count=count(f.w,"BASELINE");int cron=f.fake.cronCalls;f.fake.failList=true;f.w.checkStartup();check(f.w.startup.get("/fixture/startup").equals(old.get("/fixture/startup")) && f.fake.cronCalls==cron+1,"failed list lost files or suppressed cron");f.fake.failList=false;f.fake.files.put("/fixture/startup","new".getBytes(StandardCharsets.UTF_8));f.fake.failCopy=true;f.w.checkStartup();status(f.w,"startup","degraded");status(f.w,"crontab","ok");check(f.w.startup.get("/fixture/startup").equals(old.get("/fixture/startup")) && count(f.w,"BASELINE")==count && count(f.w,"STARTUP~")==0,"failed copy mutated state/events");}});
        test("startup-optional-empty-and-real-synthetic-copy",()->{try(Fixture f=new Fixture()) {f.fake.files.put("/fixture/absent",null);f.w.checkStartup();status(f.w,"startup","ok");check(f.w.startup.size()==1,"optional absence not empty");f.fake.realCopies=true;f.fake.files.put("/fixture/file","fixture bytes".getBytes(StandardCharsets.UTF_8));f.w.checkStartup();String digest=f.w.startup.get("/fixture/file");String path=Paths.join(f.w.snapDir,Watch.safeName("/fixture/file"),Py.cut(digest,16));check(Arrays.equals(Files.readAllBytes(Path.of(path)),"fixture bytes".getBytes(StandardCharsets.UTF_8)),"actual synthetic copy bytes");}});
        test("empty-lsof-without-enrichment",()->{try(Fixture f=new Fixture()){f.fake.failPs=true;f.w.checkListeners();status(f.w,"listeners","ok");f.fake.lsof=new Proc.Result(1,"","");f.w.checkListeners();status(f.w,"listeners","ok");}});
        test("expanded-bind-literals",()->{check(CollectionHealth.bindScope("::ffff:0.0.0.0").equals("wildcard"),"mapped wildcard");check(CollectionHealth.bindScope("[::ffff:0.0.0.0]").equals("wildcard"),"bracket mapped wildcard");for(String host:List.of("[127.0.0.1]"," 127.0.0.1","127.0.0.1 ","::ffff:127.000.0.1"))check(CollectionHealth.bindScope(host).equals("unknown"),"invalid literal "+host);});
        test("ps-blank-and-empty-args",()->{try(Fixture f=new Fixture()){f.fake.args=new Proc.Result(0,"\n42\n \n","");f.fake.comm=new Proc.Result(0,"\n42 1 fixture /fixture/a\n \n","");f.w.checkProcesses();status(f.w,"processes","ok");check(f.w.prevPids.containsKey(42L),"empty args lost process");}});
        test("invalid-pids-and-listener-address",()->{try(Fixture f=new Fixture()){f.fake.comm=new Proc.Result(0,"0 1 fixture /fixture/a\n","");f.w.checkProcesses();status(f.w,"processes","degraded");f.fake.comm=new Proc.Result(0,"42 1 fixture /fixture/a\n","");for(String out:List.of("p0\ncfixture\nn127.0.0.1:5\n","p42\ncfixture\nn127.0.0.1:0\n","p42\ncfixture\nn127.0.0.1 :5\n")){f.fake.lsof=new Proc.Result(0,out,"");f.w.checkListeners();status(f.w,"listeners","degraded");check(f.w.listeners.isEmpty(),"invalid listener adopted");}}});
        test("optional-missing-versus-dangling-links",()->{Path dir=Files.createDirectory(root.resolve("link-fixture"));Watch.Sources source=Proc::run;check(source.read(dir.resolve("absent").toString())==null,"optional absent");Path link=dir.resolve("broken");Files.createSymbolicLink(link,dir.resolve("not-there"));boolean readFailed=false,listFailed=false;try{source.read(link.toString());}catch(IOException e){readFailed=true;}try{source.list(link.toString());}catch(IOException e){listFailed=true;}check(readFailed && listFailed,"dangling link hidden as absence");});
        test("startup-nonempty-late-db-rollback",()->{try(Fixture f=new Fixture()){f.fake.files.put("/fixture/startup","old".getBytes(StandardCharsets.UTF_8));f.w.checkStartup();Map<String,String> old=f.w.startup;String cron=f.w.crontabText;f.fake.files.clear();f.fake.cron=new Proc.Result(0,"updated","");f.w.db.exec("CREATE TRIGGER reject_late BEFORE INSERT ON startup_items WHEN NEW.path='crontab -l' BEGIN SELECT RAISE(ABORT,'fixture'); END;");f.w.checkStartup();status(f.w,"startup","degraded");status(f.w,"crontab","degraded");check(f.w.startup==old && f.w.crontabText.equals(cron) && count(f.w,"STARTUP-")==0,"late rejection changed inventory/event/text");check(Db.asLong(f.w.db.scalar("SELECT count(*) FROM startup_items;"))==2,"prior delete not rolled back");}});
        test("retained-startup-copy-policy",()->{try(Fixture f=new Fixture()){byte[] value=new byte[4*1024*1024+1];Arrays.fill(value,(byte)'x');f.fake.files.put("/fixture/large",value);f.fake.cron=new Proc.Result(0,new String(value,StandardCharsets.UTF_8),"");f.w.checkStartup();status(f.w,"startup","ok");String hash=HexFormat.of().formatHex(Watch.sha256().digest(value));check(f.w.startup.get("/fixture/large").equals(hash),"hash truncated");check(f.fake.copies.get("/fixture/copies/fixture_large/"+hash.substring(0,16)).length==4*1024*1024,"file copy not capped");check(f.fake.copies.get("/fixture/copies/crontab_-l/"+hash.substring(0,16)).length==value.length,"cron copy truncated");}});
        test("lsof-optional-file-boundaries",()->{try(Fixture f=new Fixture()){f.fake.lsof=new Proc.Result(0,"p42\ncfixture\nf10\nn127.0.0.1:12345\nf11\nn192.0.2.10:12346\n","");f.w.checkListeners();status(f.w,"listeners","ok");check(f.w.listeners.size()==2,"f boundaries lost rows");Map<String,Watch.Listener> old=f.w.listeners;f.fake.lsof=new Proc.Result(0,"p42\ncfixture\nf10\nn127.0.0.1:12345\nf11\n","");f.w.checkListeners();status(f.w,"listeners","degraded");check(f.w.listeners==old && count(f.w,"UNLISTEN")==0,"trailing f partial adopted");}});
        test("atomic-copy-compares-existing",()->{Path dir=Files.createDirectory(root.resolve("atomic-copy"));Watch.Sources source=Proc::run;Path dest=dir.resolve("copy");byte[] value="complete".getBytes(StandardCharsets.UTF_8);source.copy(dest.toString(),value);source.copy(dest.toString(),value);check(Arrays.equals(Files.readAllBytes(dest),value),"atomic publish bytes");Files.writeString(dest,"partial");boolean rejected=false;try{source.copy(dest.toString(),value);}catch(IOException e){rejected=true;}check(rejected && Files.readString(dest).equals("partial"),"bad existing copy accepted/overwritten");});
        test("deferred-commit-failure-rolls-back",()->{try(Fixture f=new Fixture()){f.w.db.exec("PRAGMA foreign_keys=ON;\nCREATE TABLE fixture_parent(id INTEGER PRIMARY KEY);\nCREATE TABLE fixture_child(id INTEGER REFERENCES fixture_parent(id) DEFERRABLE INITIALLY DEFERRED);\nCREATE TRIGGER fail_commit AFTER INSERT ON programs BEGIN INSERT INTO fixture_child VALUES(42); END;");f.w.checkProcesses();status(f.w,"processes","degraded");check(f.w.knownProgs.isEmpty() && f.w.identQ.isEmpty() && f.w.prevPids==null && count(f.w,"BASELINE")==0,"commit failure adopted state");check(Db.asLong(f.w.db.scalar("SELECT count(*) FROM programs;"))==0 && Db.asLong(f.w.db.scalar("SELECT count(*) FROM fixture_child;"))==0,"failed COMMIT not rolled back");f.w.db.exec("DROP TRIGGER fail_commit;");f.w.checkProcesses();status(f.w,"processes","ok");}});
        test("stable-comm-path-with-spaces",()->{try(Fixture f=new Fixture()){String exe="/fixture/Example App.app/service",key=exe+" 127.0.0.1:12345";f.w.db.exec(Db.bind("INSERT INTO listeners(key,exe,address,port,command,pid,present,exposed) VALUES (?,?,?,?,?,?,?,?)",key,exe,"127.0.0.1",12345,"fixture",99,1,0));f.w.loadState();f.fake.lookup=new Proc.Result(0,exe+"\n","");f.fake.lsof=new Proc.Result(0,"p99\ncfixture\nn127.0.0.1:12345\n","");f.w.checkListeners();status(f.w,"listeners","ok");check(f.w.listeners.size()==1 && f.w.listeners.get(key).present && count(f.w,"UNLISTEN")==0,"space-containing executable key changed");}});
        test("rollback-failure-closes-preserves-original",()->{try(Fixture f=new Fixture()) {
            f.w.db.exec("CREATE TABLE fixture_abort(id INTEGER);\nCREATE TRIGGER rollback_fixture BEFORE INSERT ON fixture_abort BEGIN SELECT RAISE(ROLLBACK,'original-fixture-error'); END;");
            Db.DbException original=null;
            try {f.w.db.transaction(List.of("INSERT INTO fixture_abort VALUES(1);"));}
            catch(Db.Fatal e) {original=(Db.DbException)e.getCause();}
            check(original!=null && original.getMessage().contains("original-fixture-error"),"original transaction exception lost");
            boolean closed=false;
            try {f.w.db.exec("SELECT 1;");} catch(Db.Fatal e) {closed=e.getCause().getMessage().equals("Cannot operate on a closed database.");}
            check(closed,"connection remained usable after failed ROLLBACK");
            boolean fatal=false;try{f.w.checkProcesses();}catch(Db.Fatal e){fatal=true;}check(fatal,"closed DB continued");
            check(f.w.knownProgs.isEmpty() && f.w.identQ.isEmpty() && f.w.prevPids==null,"closed connection adopted later sample");
        }});
        test("cross-language-result-policy-edges",()->{try(Fixture f=new Fixture()) {
            f.fake.lsof=new Proc.Result(0,"p42\ncfixture\nfbad\nn127.0.0.1:12345\n","");f.w.checkListeners();status(f.w,"listeners","degraded");check(f.w.listeners.isEmpty(),"nonnumeric descriptor adopted");
            f.fake.lsof=new Proc.Result(0,"p42\ncfixture\nn[::ffff:0.0.0.0]:12345\n","");f.w.checkListeners();status(f.w,"listeners","ok");Map<?,?> row=(Map<?,?>)((Map<?,?>)f.w.pageMap().get("listeners")).values().iterator().next();check(row.get("bindScope").equals("wildcard") && row.get("exposed").equals(false),"legacy exposed semantics changed");
            f.fake.comm=new Proc.Result(0,"","");f.w.checkProcesses();check(health(f.w,"processes").get("error").equals("ps-parse"),"empty primary error policy");
            f.fake.comm=new Proc.Result(0,"42 1 fixture /fixture/a\n","");f.fake.args=new Proc.Result(0,"","");f.w.checkProcesses();check(health(f.w,"processes").get("error").equals("ps-parse"),"empty args inventory accepted");
            f.fake.failure=new IOException("synthetic decode",new java.nio.charset.MalformedInputException(1));f.w.checkProcesses();check(health(f.w,"processes").get("error").equals("collection-parse"),"decode error classified as io");
        }});
        test("actual-stream-read-failure",()->{
            Proc.Reader reader=new Proc.Reader(new InputStream(){public int read() throws IOException{throw new IOException("fixture read failure");}});
            reader.start();reader.join();check(reader.failure!=null,"stream error swallowed");
        });
        test("shared-feature-parity-sequence",()->{try(Fixture f=new Fixture()) {
            List<Object> snapshots=new ArrayList<>(); f.seed(); f.w.baseline.replaceAll((k,v)->false);
            java.util.function.Consumer<String> capture=name->{try {Map<String,Object> row=new LinkedHashMap<>();row.put("name",name);row.putAll(snapshot(f.w));snapshots.add(row);}catch(Exception e){throw new IllegalStateException(e);}};
            capture.accept("initial");
            f.fake.args=new Proc.Result(0,"99 /fixture/vanished\n","");
            f.fake.lsof=new Proc.Result(0,"p42\ncfixture\nn127.0.0.1:12345\n","");f.w.checkListeners();capture.accept("listenerHealthy");
            f.fake.lsof=new Proc.Result(7,"","");f.w.checkListeners();capture.accept("listenerFailed7");
            f.fake.lsof=new Proc.Result(0,"p42\ncfixture\nn127.0.0.1:12345\np43\ncpartial\n","");f.w.checkListeners();capture.accept("listenerPartial");
            f.fake.lsof=new Proc.Result(1,"","");f.w.checkListeners();capture.accept("listenerRecovered");
            f.w.checkProcesses();capture.accept("processHealthy");
            f.fake.args=new Proc.Result(7,"","");f.w.checkProcesses();capture.accept("processFailed");
            f.fake.args=new Proc.Result(0,"99 /fixture/vanished\n","");f.w.checkProcesses();capture.accept("processRecovered");
            f.fake.files.put("/fixture/startup",new byte[0]);f.fake.failRead=true;f.w.checkStartup();capture.accept("startupBeforeCronFailure");
            f.fake.files.clear();f.fake.failRead=false;f.fake.cron=new Proc.Result(1,"","crontab: no crontab for fixture\n");
            f.w.db.exec("CREATE TRIGGER shared_reject_startup BEFORE INSERT ON startup_items BEGIN SELECT RAISE(ABORT,'fixture'); END;");f.w.checkStartup();capture.accept("startupDbFailure");
            parity.put("snapshots",snapshots);
        }});
        RepairHealthTest.run();
        if(parityPath!=null) Files.writeString(parityPath,Json.write(parity)+"\n");
        StringBuilder x=new StringBuilder("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<testsuite name=\"CollectionHealthTest\" timestamp=\"").append(Instant.now()).append("\" tests=\"").append(results.size()).append("\" failures=\"").append(results.stream().filter(r->r.get("status").equals("failure")).count()).append("\" errors=\"").append(results.stream().filter(r->r.get("status").equals("error")).count()).append("\" skipped=\"0\">\n");
        for(Map<String,Object> r:results) {x.append("<testcase classname=\"dev.tattletale.CollectionHealthTest\" name=\"").append(escape(r.get("name"))).append("\" timestamp=\"").append(r.get("timestamp")).append("\" time=\"").append(r.get("seconds")).append("\">");if(!r.get("status").equals("pass"))x.append('<').append(r.get("status")).append('>').append(escape(r.get("detail"))).append("</").append(r.get("status")).append('>');x.append("</testcase>\n");}x.append("</testsuite>\n");Files.writeString(xml,x);
        System.out.println("RESULT cases="+results.size()+" failed="+results.stream().filter(r->!r.get("status").equals("pass")).count());
        if(results.stream().anyMatch(r->!r.get("status").equals("pass"))) System.exit(1);
    }
    static String escape(Object s) {return String.valueOf(s).replace("&","&amp;").replace("<","&lt;").replace(">","&gt;").replace("\"","&quot;");}
}
