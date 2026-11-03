package dev.tattletale;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import static dev.tattletale.CollectionHealthTest.check;
import static dev.tattletale.CollectionHealthTest.test;

/** Explicit synthetic DBs/fake stream children only; never Main watcher/real collectors. */
public final class CoverageTest {
    private CoverageTest() {}
    static Map<?,?> shared;
    static final List<Map<String,Object>> parity=new ArrayList<>();
    static String stamp(int second){return "2000-01-01T00:00:%02dZ".formatted(second);}
    static String field(String key){return (String)shared.get(key);}
    static Path next(String name)throws Exception{return CollectionHealthTest.root.resolve(name+"-"+(++CollectionHealthTest.serial));}
    static void seed(Db db)throws Exception {
        db.exec(Watch.SCHEMA);db.exec("INSERT INTO schema_version VALUES (1); INSERT INTO heartbeat_schema VALUES (1);");
        for(String key:Coverage.COLLECTORS)for(int second=0;second<=30;second+=5)
            db.exec(Db.bind("INSERT INTO collector_heartbeats VALUES (NULL,1,?,?,0,'ok',NULL,3)",key,stamp(second)));
    }
    static void mutate(Db db,Map<?,?> c)throws Exception {
        String op=(String)c.get("op");
        switch(op) {
            case "none" -> {}
            case "events" -> {for(String at:List.of("1999-12-31T23:59:59Z",stamp(0),stamp(15),stamp(30),stamp(31)))db.exec(Db.bind("INSERT INTO events VALUES (NULL,?,'FIXTURE','synthetic')",at));}
            case "empty" -> db.exec("DELETE FROM collector_heartbeats;");
            case "missing" -> db.exec(Db.bind("DELETE FROM collector_heartbeats WHERE collector=?",c.get("target")));
            case "failure","partial","recovery","anchor" -> {
                String key,error;int at;
                switch(op) {
                    case "failure" -> {key="listeners";error="lsof-command";at=10;}
                    case "partial" -> {key="startup";error="startup-unreadable";at=10;}
                    case "recovery" -> {key="keychain";error="keychain-ended";at=5;}
                    default -> {key="keychain";error="keychain-ended";at=0;}
                }
                db.exec(Db.bind("UPDATE collector_heartbeats SET status='degraded',error=?,observed_count=NULL WHERE collector=? AND time=?",error,key,stamp(at)));
            }
            case "early" -> db.exec(Db.bind("DELETE FROM collector_heartbeats WHERE collector='keychain' AND time>?",stamp(0)));
            case "gap" -> db.exec(Db.bind("DELETE FROM collector_heartbeats WHERE collector='processes' AND time IN (?,?,?)",stamp(10),stamp(15),stamp(20)));
            case "end" -> db.exec(Db.bind("DELETE FROM collector_heartbeats WHERE collector='keychain' AND time>=?",stamp(25)));
            case "start" -> db.exec(Db.bind("DELETE FROM collector_heartbeats WHERE collector='startup' AND time=?",stamp(0)));
            case "legacy" -> db.exec("DROP TABLE collector_heartbeats;");
            case "schema" -> db.exec(Db.bind("UPDATE schema_version SET version=?",c.get("value")));
            case "duplicate-schema" -> db.exec("INSERT INTO schema_version VALUES (1);");
            case "extension" -> db.exec("UPDATE heartbeat_schema SET version=2;");
            case "mutate" -> {
                String column=(String)c.get("field");
                check(List.of("version","collector","observed_count","status","error","time","cadence_seconds").contains(column),"fixture column");
                db.exec(Db.bind("UPDATE collector_heartbeats SET "+column+"=? WHERE collector='keychain' AND time=?",c.get("value"),stamp(0)));
            }
            case "floor" -> db.exec(Db.bind("INSERT INTO coverage_metadata VALUES ('event_floor',?)",c.get("value")));
            case "bad-event" -> db.exec(Db.bind("INSERT INTO events VALUES (NULL,?,'FIXTURE','synthetic')",c.get("value")));
            default -> throw new AssertionError("unhandled fixture operation "+op);
        }
    }
    static List<String> issues(Map<String,Object> result) {
        List<String> out=new ArrayList<>();for(Object item:(List<?>)result.get("issues")) {
            Map<?,?> issue=(Map<?,?>)item;out.add((issue.get("collector")==null?"-":issue.get("collector"))+"/"+issue.get("reason"));
        }return out;
    }
    static void caseTest(Map<?,?> c)throws Exception {
        try(Db db=Db.open(next("fixture").toString(),false)) {
            seed(db);mutate(db,c);db.exec("PRAGMA query_only=ON; BEGIN;");
            Object before=db.scalar("SELECT total_changes();");
            String since=c.containsKey("since")?(String)c.get("since"):field("since");
            String until=c.containsKey("until")?(String)c.get("until"):field("until");
            Map<String,Object> result=Coverage.guard(db,since,until,field("now"));
            check(result.get("outcome").equals(c.get("outcome")),"outcome "+Json.write(result));
            check(issues(result).equals(c.get("issues")),"issues "+Json.write(result));
            Object expected=c.get("outcome").equals("REFUSED")?null:c.containsKey("eventCount")?c.get("eventCount"):0L;
            check(java.util.Objects.equals(result.get("eventCount"),expected),"event count "+Json.write(result));
            check(before.equals(db.scalar("SELECT total_changes();")),"guard wrote logical state");
            parity.add(Map.of("name",c.get("name"),"result",result));
        }
    }
    static void streamCase(Map<?,?> c)throws Exception {
        KeychainProgress progress=new KeychainProgress();
        for(Object line:(List<?>)c.get("lines"))progress.line(((String)line).getBytes(StandardCharsets.UTF_8));
        if(c.containsKey("hex"))progress.line(HexFormat.of().parseHex((String)c.get("hex")));
        KeychainProgress.Cycle cycle=progress.cycle((Boolean)c.get("alive"),(Boolean)c.get("partial"));
        check(java.util.Objects.equals(cycle.count(),c.get("count")) && java.util.Objects.equals(cycle.error(),c.get("error")),"stream cycle "+c.get("name"));
        check(progress.cycle(true,false).equals(new KeychainProgress.Cycle(0L,null)),"fresh fully serviced interval recovery");
        Map<String,Object> row=new LinkedHashMap<>();row.put("name","stream-"+c.get("name"));row.put("count",cycle.count());row.put("error",cycle.error());parity.add(row);
    }
    static Map<String,Object> last(Watch w,String key)throws Exception {
        List<Map<String,Object>> rows=w.db.query(Db.bind("SELECT observed_count,status,error FROM collector_heartbeats WHERE collector=? ORDER BY id DESC LIMIT 1",key));
        check(rows.size()==1,"missing producer heartbeat "+key);return rows.getFirst();
    }
    static Map<String,Object> snapshotGuard(Db db,String since)throws Exception {
        db.exec("PRAGMA query_only=ON; BEGIN;");
        try {return Coverage.guard(db,since,field("until"),field("now"));}
        finally {db.exec("ROLLBACK; PRAGMA query_only=OFF;");}
    }
    static void historyTests() {
        test("coverage-old-history-signed-rowids-and-out-of-window-faults",()->{
            try(Db db=Db.open(next("old-history").toString(),false)) {
                seed(db);mutate(db,Map.of("op","events"));
                String old="1999-12-31T23:00:00Z",message="x".repeat(4096);
                List<String> history=new ArrayList<>();
                List<Long> ids=new ArrayList<>();ids.add(Long.MIN_VALUE);for(long id=-1537;id<0;id++)ids.add(id);ids.add(Long.MAX_VALUE);
                for(long id:ids) {
                    history.add(Db.bind("INSERT INTO collector_heartbeats VALUES (?,1,'keychain',?,0,'ok',NULL,3)",id,old));
                    history.add(Db.bind("INSERT INTO events VALUES (?,?,'FIXTURE',?)",id,old,message));
                }
                db.transaction(history);
                Map<String,Object> result=snapshotGuard(db,stamp(2));
                check(result.get("outcome").equals("EVENTS") && result.get("eventCount").equals(2L) && issues(result).isEmpty(),"old history changed the requested window "+Json.write(result));
                // Exercise real bounded pages across signed rowid extremes, not OFFSET.
                db.exec("PRAGMA query_only=ON; BEGIN;");
                for(String table:List.of("collector_heartbeats","events")) {
                    Coverage.Rows rows=new Coverage.Rows(db,table,table.equals("events")?"time,kind,message":"time,collector");
                    long count=0,first=0,last=0;
                    for(Map<String,Object> row;(row=rows.next())!=null;) {
                        long id=(Long)row.get("evidence_rowid");if(count==0)first=id;last=id;count++;
                    }
                    check(count==(table.equals("events")?1544:1574),"keyset pager skipped/duplicated evidence");
                    check(first==Long.MIN_VALUE && last==Long.MAX_VALUE,"signed rowid boundary lost");
                    check(rows.peakPageRows==512 && rows.pagesRead==4,"unbounded or incomplete page traversal");
                }
                db.exec("ROLLBACK; PRAGMA query_only=OFF;");
                db.exec(Db.bind("UPDATE collector_heartbeats SET version=2 WHERE rowid=?",Long.MAX_VALUE));
                check(issues(snapshotGuard(db,stamp(2))).equals(List.of("-/unsupported-heartbeat-version")),"final old heartbeat page escaped validation");
                db.exec(Db.bind("UPDATE collector_heartbeats SET version=1 WHERE rowid=?",Long.MAX_VALUE));
                db.exec(Db.bind("UPDATE events SET message=NULL WHERE rowid=?",Long.MAX_VALUE));
                check(issues(snapshotGuard(db,stamp(2))).equals(List.of("-/malformed-event")),"final old event page escaped validation");
            }
        });
        test("coverage-anchor-time-rowid-and-reverse-insert-order",()->{
            try(Db db=Db.open(next("late-anchor").toString(),false)) {
                seed(db);
                db.exec("INSERT INTO collector_heartbeats VALUES (NULL,1,'keychain','1999-12-31T23:59:59Z',NULL,'degraded','keychain-ended',3);");
                check(snapshotGuard(db,stamp(2)).get("outcome").equals("QUIET"),"late older failure replaced true anchor");
                db.exec(Db.bind("UPDATE collector_heartbeats SET observed_count=NULL,status='degraded',error='keychain-ended' WHERE collector='keychain' AND time=?",stamp(0)));
                db.exec("INSERT INTO collector_heartbeats VALUES (NULL,1,'keychain','1999-12-31T23:59:59Z',0,'ok',NULL,3);");
                check(issues(snapshotGuard(db,stamp(2))).equals(List.of("keychain/start-silence")),"late older success concealed failed anchor");
                db.exec(Db.bind("INSERT INTO collector_heartbeats VALUES (NULL,1,'keychain',?,0,'ok',NULL,3)",stamp(0)));
                check(snapshotGuard(db,stamp(2)).get("outcome").equals("QUIET"),"same-time later rowid did not recover anchor");
                db.exec("DELETE FROM collector_heartbeats WHERE collector='keychain';");
                for(int second=30;second>=0;second-=5)db.exec(Db.bind("INSERT INTO collector_heartbeats VALUES (NULL,1,'keychain',?,0,'ok',NULL,3)",stamp(second)));
                check(snapshotGuard(db,stamp(0)).get("outcome").equals("QUIET"),"in-window rows were not sorted chronologically");
            }
        });
    }
    static void producerTests() {
        test("coverage-producer-counts-failure-partial-recovery",()->{try(var f=new CollectionHealthTest.Fixture()) {
            f.seed();f.fake.lsof=new Proc.Result(1,"","");f.w.checkListeners();
            check(last(f.w,"listeners").get("observed_count").equals(0L),"healthy zero listener count");
            f.w.checkProcesses();check(last(f.w,"processes").get("observed_count").equals(1L),"process observed count");
            for(Proc.Result rejected:List.of(new Proc.Result(7,"",""),new Proc.Result(0,"p42\ncpartial\n",""))) {
                String before=Json.write(f.w.db.query("SELECT * FROM listeners;"));f.fake.lsof=rejected;f.w.checkListeners();
                check(before.equals(Json.write(f.w.db.query("SELECT * FROM listeners;"))),"failed sample changed inventory");
                check(last(f.w,"listeners").get("observed_count")==null && last(f.w,"listeners").get("status").equals("degraded"),"failure became zero");
            }
            f.fake.lsof=new Proc.Result(1,"","");f.w.checkListeners();check(last(f.w,"listeners").get("status").equals("ok"),"listener recovery");
            f.fake.cron=new Proc.Result(1,"","crontab: no crontab for fixture\n");f.w.checkStartup();
            check(last(f.w,"startup").get("observed_count").equals(0L),"empty startup count");
            check(last(f.w,"crontab").get("observed_count").equals(0L),"absent crontab count");
        }});
        test("coverage-success-heartbeat-and-inventory-share-rollback",()->{try(var f=new CollectionHealthTest.Fixture()) {
            f.w.db.exec("CREATE TRIGGER reject_pulse BEFORE INSERT ON collector_heartbeats WHEN NEW.status='ok' BEGIN SELECT RAISE(ABORT,'fixture'); END;");
            f.w.checkProcesses();check(f.w.db.scalar("SELECT count(*) FROM programs;").equals(0L),"inventory escaped rejected heartbeat");
            check(last(f.w,"processes").get("error").equals("collection-db"),"rollback lacks failure heartbeat");
        }});
        test("coverage-configured-cadence",()->{try(var f=new CollectionHealthTest.Fixture()) {
            check(f.w.cadence("processes")==3 && f.w.cadence("listeners")==33 && f.w.cadence("startup")==303 && f.w.cadence("crontab")==303 && f.w.cadence("keychain")==3,"configured scheduling cadence");
        }});
        test("coverage-startup-partial-crontab-failure-independent-controls",()->{try(var f=new CollectionHealthTest.Fixture()) {
            var blocked=new CollectionHealthTest.Fake(){public byte[] entry(String file)throws java.io.IOException{throw new Watch.Unreadable("permission-denied");}};
            blocked.files.put("/fixture/blocked",new byte[0]);blocked.cron=new Proc.Result(7,"","");f.w.sources=blocked;f.w.checkStartup();
            check(last(f.w,"startup").get("observed_count")==null && last(f.w,"startup").get("error").equals("startup-unreadable"),"partial became healthy zero");
            check(last(f.w,"crontab").get("error").equals("crontab-command"),"cron failed control missing");
            f.w.sources=f.fake;f.fake.cron=new Proc.Result(1,"","no crontab for fixture\n");f.w.checkStartup();
            check(last(f.w,"startup").get("observed_count").equals(0L) && last(f.w,"crontab").get("observed_count").equals(0L),"partition recovery counts");
        }});
    }
    static class Child extends Process {
        final InputStream input;boolean alive;boolean destroyed;int code;
        Child(byte[] bytes,boolean alive){this(new ByteArrayInputStream(bytes),alive);}
        Child(InputStream input,boolean alive){this.input=input;this.alive=alive;}
        public OutputStream getOutputStream(){return new ByteArrayOutputStream();}
        public InputStream getInputStream(){return input;}
        public InputStream getErrorStream(){return InputStream.nullInputStream();}
        public int waitFor(){alive=false;return code;}
        public boolean waitFor(long timeout,TimeUnit unit){alive=false;return true;}
        public int exitValue(){if(alive)throw new IllegalThreadStateException();return code;}
        public void destroy(){destroyed=true;alive=false;}
        public Process destroyForcibly(){destroy();return this;}
        public boolean isAlive(){return alive;}
    }
    static final class IdleInput extends InputStream {
        final java.util.concurrent.CountDownLatch reading=new java.util.concurrent.CountDownLatch(1);
        boolean closed;
        public synchronized int read(byte[] bytes,int offset,int length)throws java.io.IOException {
            reading.countDown();
            while(!closed)try {wait();}catch(InterruptedException e){Thread.currentThread().interrupt();throw new java.io.IOException("fixture-interrupted");}
            return -1;
        }
        public int read()throws java.io.IOException{return read(new byte[1],0,1);}
        public synchronized void close(){closed=true;notifyAll();}
    }
    static void awaitReader(Watch w)throws InterruptedException {
        check(w.streamReader!=null && w.streamReader.ended.await(1,TimeUnit.SECONDS),"owned reader did not observe terminal input");
    }
    static void workerTests() {
        test("coverage-strict-raw-controls-and-escaped-positive-legacy-compatibility",()->{
            for(int control=0;control<32;control++) {
                String prefix="{\"processID\":42,\"processImagePath\":\"/fixture/SecurityAgent\",\"eventMessage\":\"";
                KeychainProgress bad=new KeychainProgress();
                check(bad.line((prefix+(char)control+"\"}").getBytes(StandardCharsets.UTF_8))==null,"raw JSON control accepted");
                check(bad.cycle(true,false).error().equals("keychain-malformed"),"raw control became quiet");
                KeychainProgress good=new KeychainProgress();
                check(good.line((prefix+"\\u%04x".formatted(control)+"\"}").getBytes(StandardCharsets.UTF_8))!=null,"valid escaped control rejected");
                check(good.cycle(true,false).count().equals(1L),"escaped positive missing");
            }
            check(Json.parse("\"\\u+001\"").equals(Character.toString((char)1)),"permissive parser compatibility changed");
            try {Json.parseStrict("\"\\u+001\"");throw new AssertionError("signed Unicode escape accepted in strict mode");}
            catch(Json.ParseError expected){}
        });
        test("coverage-initial-no-output-nonzero-stream-keeps-fallback-uncovered",()->{try(var f=new CollectionHealthTest.Fixture()) {
            Child child=new Child(new byte[0],false);child.code=2;int[] starts={0};
            f.w.streamFactory=command->{starts[0]++;return child;};
            f.w.streamPause=millis->{if(millis==250){awaitReader(f.w);return false;}throw new AssertionError("unsupported stream retry forbidden");};
            f.w.logStream();check(starts[0]==1,"unsupported stream restarted");
            check(last(f.w,"keychain").get("observed_count")==null && last(f.w,"keychain").get("error").equals("keychain-ended"),"fallback became keychain coverage");
        }});
        test("coverage-stdout-eof-with-live-child-never-becomes-healthy-idle",()->{try(var f=new CollectionHealthTest.Fixture()) {
            Child child=new Child(new byte[0],true);f.w.streamFactory=command->child;
            f.w.streamPause=millis->{awaitReader(f.w);return false;};
            check(!f.w.logStreamOnce(),"closed live-child pipe authorized restart");
            var rows=f.w.db.query("SELECT observed_count,status,error FROM collector_heartbeats WHERE collector='keychain';");
            check(rows.size()==1 && rows.getFirst().get("observed_count")==null && rows.getFirst().get("error").equals("keychain-closed"),"EOF was credited as live idle "+Json.write(rows));
            check(child.destroyed && !child.isAlive() && f.w.streamProc==null && f.w.streamReader==null,"closed-pipe child/reader cleanup incomplete");
        }});
        test("coverage-reader-failure-with-live-child-is-degraded",()->{try(var f=new CollectionHealthTest.Fixture()) {
            Child child=new Child(new InputStream(){public int read()throws java.io.IOException{throw new java.io.IOException("fixture-read");}},true);
            f.w.streamFactory=command->child;f.w.streamPause=millis->{awaitReader(f.w);return false;};
            check(!f.w.logStreamOnce() && last(f.w,"keychain").get("error").equals("keychain-io"),"reader failure became idle");
            check(!child.isAlive() && f.w.streamReader==null,"failed reader remains owned/live");
        }});
        test("coverage-unexpected-worker-interrupt-degrades-and-stops",()->{try(var f=new CollectionHealthTest.Fixture()) {
            IdleInput input=new IdleInput();Child child=new Child(input,true);f.w.streamFactory=command->child;
            f.w.streamPause=millis->{check(input.reading.await(1,TimeUnit.SECONDS),"reader never blocked on fake idle pipe");throw new InterruptedException("fixture-unexpected");};
            try {
                check(!f.w.logStreamOnce() && f.w.stopped(),"unexpected interrupt left watcher healthy/running");
                check(last(f.w,"keychain").get("error").equals("keychain-interrupted"),"interrupt lost degraded evidence");
                check(f.w.streamProc==null && f.w.streamReader==null && !child.isAlive(),"interrupted worker left owned liveness");
                check(Thread.currentThread().isInterrupted(),"interrupt disposition lost");
            }finally {Thread.interrupted();}
        }});
        test("coverage-unexpected-reader-interrupt-degrades-and-stops",()->{try(var f=new CollectionHealthTest.Fixture()) {
            IdleInput input=new IdleInput();Child child=new Child(input,true);f.w.streamFactory=command->child;
            f.w.streamPause=millis->{check(input.reading.await(1,TimeUnit.SECONDS),"fake reader never observed idle input");f.w.streamReader.thread.interrupt();return false;};
            check(!f.w.logStreamOnce() && f.w.stopped(),"interrupted reader retained healthy coverage");
            check(last(f.w,"keychain").get("error").equals("keychain-interrupted"),"reader interrupt lost degraded evidence");
            check(f.w.streamProc==null && f.w.streamReader==null && !child.isAlive(),"reader interruption left live ownership");
        }});
        test("coverage-unconfirmed-child-cleanup-keeps-ownership-and-blocks-restart",()->{try(var f=new CollectionHealthTest.Fixture()) {
            Child child=new Child(new byte[0],true){
                public void destroy(){destroyed=true;}
                public Process destroyForcibly(){destroyed=true;return this;}
                public boolean waitFor(long timeout,TimeUnit unit){return false;}
            };
            int[] starts={0};f.w.streamFactory=command->{starts[0]++;return child;};f.w.streamPause=millis->{awaitReader(f.w);return false;};
            check(!f.w.logStreamOnce() && f.w.stopped(),"unknown child liveness authorized restart");
            check(f.w.streamProc==child && f.w.streamReader!=null,"live child ownership was cleared");
            check(!f.w.logStreamOnce() && starts[0]==1,"second child started before cleanup proof");
            check(last(f.w,"keychain").get("error").equals("keychain-cleanup"),"unknown cleanup was healthy");
            child.alive=false;check(f.w.cleanupStream(child,f.w.streamReader).complete(),"fake child final release failed");
        }});
        test("coverage-owned-reader-backpressure-is-bounded-and-cancellable",()->{
            var ninth=new java.util.concurrent.CountDownLatch(1);var reads=new java.util.concurrent.atomic.AtomicInteger();
            InputStream input=new InputStream(){
                volatile boolean closed;
                public int read(byte[] bytes,int offset,int length)throws java.io.IOException {
                    if(closed)throw new java.io.IOException("fixture-closed");Arrays.fill(bytes,offset,offset+length,(byte)'x');
                    if(reads.incrementAndGet()==9)ninth.countDown();return length;
                }
                public int read(){return 'x';}
                public void close(){closed=true;}
            };
            Watch.OwnedStreamReader reader=new Watch.OwnedStreamReader(input);reader.start();
            try {
                check(ninth.await(1,TimeUnit.SECONDS),"reader did not exercise backpressure");
                check(reader.chunks.size()==8 && reads.get()==9,"reader buffers grew without a bound");
            }finally {reader.cancel();Watch.joinOwned(reader.thread,1000);}
            check(!reader.thread.isAlive(),"queue-blocked reader did not stop");
        });
        test("coverage-idle-worker-pulses-then-observes-owned-exit",()->{try(var f=new CollectionHealthTest.Fixture()) {
            IdleInput input=new IdleInput();Child child=new Child(input,true);double[] tick={0};
            f.w.streamFactory=command->child;f.w.streamClock=()->tick[0];
            f.w.streamPause=millis->{
                check(input.reading.await(1,TimeUnit.SECONDS),"idle reader never observed pipe");tick[0]+=3;
                if(tick[0]>=6){child.alive=false;input.close();awaitReader(f.w);}return false;
            };
            check(f.w.logStreamOnce(),"normal confirmed terminal exit should allow bounded restart");
            var rows=f.w.db.query("SELECT observed_count,status,error FROM collector_heartbeats WHERE collector='keychain' ORDER BY id;");
            check(rows.size()==2 && rows.getFirst().get("observed_count").equals(0L) && rows.getLast().get("error").equals("keychain-ended"),"idle/exit controls "+Json.write(rows));
            check(!child.isAlive() && f.w.streamProc==null && f.w.streamReader==null,"child/reader cleanup");
        }});
        test("coverage-final-buffer-drained-before-terminal-row",()->{try(var f=new CollectionHealthTest.Fixture()) {
            Child child=new Child("{\"processID\":42,\"processImagePath\":\"/fixture/SecurityAgent\"}\n".getBytes(StandardCharsets.UTF_8),false);
            int[] events={0};f.w.streamFactory=command->child;f.w.streamEvents=event->events[0]++;
            check(f.w.logStreamOnce() && events[0]==1,"buffered final event lost");
            check(last(f.w,"keychain").get("error").equals("keychain-ended"),"exit was healthy");
        }});
        test("coverage-restart-cleans-child-before-next-owned-child",()->{try(var f=new CollectionHealthTest.Fixture()) {
            List<Child> children=new ArrayList<>();int[] delays={0};
            f.w.streamFactory=command->{if(!children.isEmpty())check(!children.getLast().isAlive() && f.w.streamProc==null && f.w.streamReader==null,"overlapping stream child/reader");Child child=new Child(new byte[0],false);children.add(child);return child;};
            f.w.streamPause=millis->{if(millis==250){awaitReader(f.w);return false;}check(millis==10000,"restart delay changed");delays[0]++;if(delays[0]==2){f.w.requestStop();return true;}return false;};
            f.w.logStream();check(children.size()==2 && delays[0]==2,"confirmed-terminal retry missing");
        }});
    }
    static void readonlyTests() {
        test("coverage-writer-refuses-future-header-or-rows-before-extension",()->{
            for(String sql:List.of("UPDATE schema_version SET version=2;","UPDATE heartbeat_schema SET version=2;","UPDATE collector_heartbeats SET version=2;")) {
                Path path=next("future-writer");try(Db db=Db.open(path.toString(),false)){seed(db);db.exec(sql);}
                byte[] before=Files.readAllBytes(path);
                try(Db ignored=Watch.openDb(path.toString())){throw new AssertionError("unsupported writer data accepted");}
                catch(Watch.Exit expected){check(expected.getMessage().contains("unsupported"),"wrong writer refusal");}
                check(Arrays.equals(before,Files.readAllBytes(path)),"unsupported writer data modified");
                check(!Files.exists(Path.of(path+"-wal")),"future preflight switched WAL");
            }
        });
        test("coverage-legacy-extension-keeps-inventory-with-no-invented-history",()->{
            Path path=next("legacy-writer");try(Db db=Db.open(path.toString(),false)) {
                seed(db);db.exec("DROP TABLE collector_heartbeats; DROP TABLE heartbeat_schema; DROP TABLE coverage_metadata; INSERT INTO programs(exe) VALUES ('/fixture/retained');");
            }
            try(Db writer=Watch.openDb(path.toString())) {
                check(writer.scalar("SELECT count(*) FROM programs;").equals(1L),"legacy inventory lost");
                check(writer.scalar("SELECT count(*) FROM collector_heartbeats;").equals(0L),"invented historical controls");
                check(issues(Coverage.review(path.toString(),field("since"),field("until"),field("now"))).size()==5,"legacy extension certified quiet");
            }
        });
        test("coverage-no-db-no-file-creation",()->{
            Path path=next("missing").resolve("db");
            check(issues(Coverage.review(path.toString(),field("since"),field("until"),field("now"))).equals(List.of("-/no-database")),"missing db accepted");
            check(!Files.exists(path.getParent()),"review created parent");
        });
        test("coverage-static-file-nonmutation",()->{
            Path path=next("static");try(Db db=Db.open(path.toString(),false)){seed(db);}
            byte[] before=Files.readAllBytes(path);long entries;try(var files=Files.list(path.getParent())){entries=files.count();}
            check(Coverage.review(path.toString(),field("since"),field("until"),field("now")).get("outcome").equals("QUIET"),"static quiet refused");
            check(Arrays.equals(before,Files.readAllBytes(path)),"review mutated database bytes");
            try(var files=Files.list(path.getParent())){check(entries==files.count(),"review published a file");}
        });
        test("coverage-live-wal-visible-and-snapshot-consistent",()->{
            Path path=next("wal");try(Db writer=Db.open(path.toString(),false)) {
                writer.exec("PRAGMA journal_mode=WAL;");seed(writer);
                check(Files.size(Path.of(path+"-wal"))>0,"no live WAL fixture");
                check(Coverage.review(path.toString(),field("since"),field("until"),field("now")).get("outcome").equals("QUIET"),"WAL controls invisible");
                try(Db reader=Db.open(path.toString(),true)) {
                    reader.exec("PRAGMA query_only=ON; BEGIN;");reader.scalar("SELECT count(*) FROM events;");
                    writer.exec(Db.bind("INSERT INTO events VALUES (NULL,?,'CREDENTIAL','synthetic')",stamp(15)));
                    Object changes=writer.scalar("SELECT total_changes();");
                    check(Coverage.guard(reader,field("since"),field("until"),field("now")).get("outcome").equals("QUIET"),"split read snapshot");
                    reader.exec("ROLLBACK;");
                    check(Coverage.review(path.toString(),field("since"),field("until"),field("now")).get("eventCount").equals(1L),"committed WAL event invisible");
                    check(changes.equals(writer.scalar("SELECT total_changes();")),"review altered writer logical state");
                }
            }
        });
        test("coverage-malformed-db-refused",()->{
            Path path=next("corrupt");Files.writeString(path,"synthetic non-SQLite bytes");
            check(issues(Coverage.review(path.toString(),field("since"),field("until"),field("now"))).equals(List.of("-/database-read")),"unreadable DB became quiet");
        });
        test("coverage-cli-conflicts-before-watcher-setup",()->{
            for(String[] flags:List.of(new String[]{"--since",field("since")},new String[]{"--until",field("until")},new String[]{"--review"},
                    new String[]{"--review","--since",field("since")},new String[]{"--review","--report","--since",field("since"),"--until",field("until")},
                    new String[]{"--review","--query","SELECT 1","--since",field("since"),"--until",field("until")},
                    new String[]{"--review","--show-settings","--since",field("since"),"--until",field("until")})) {
                try {Main.parseArgs(flags);throw new AssertionError("conflicting read request accepted");}
                catch(Watch.Exit e){check(e.code==2,"wrong conflict status");}
            }
            Path path=next("cli-missing").resolve("db");
            Path config=next("fixture-config");Files.writeString(config,"");
            check(Main.run(new String[]{"--review","--config",config.toString(),"--db",path.toString(),"--since",field("since"),"--until",field("until")})==2,"review missing DB exit");
            check(!Files.exists(path.getParent()),"CLI review constructed watcher");
        });
    }
    public static void main(String[] args)throws Exception {
        Path fixtures=null,scratch=null,output=null,xml=null;
        for(int i=0;i<args.length;i+=2)switch(args[i]) {
            case "--fixtures" -> fixtures=Path.of(args[i+1]);case "--scratch" -> scratch=Path.of(args[i+1]);case "--parity-output" -> output=Path.of(args[i+1]);case "--xml" -> xml=Path.of(args[i+1]);default -> throw new IllegalArgumentException("unknown fixture flag");
        }
        if(fixtures==null || scratch==null || xml==null)throw new IllegalArgumentException("--fixtures, --xml and fresh --scratch required");
        if(output!=null && Files.exists(output))throw new IllegalArgumentException("refusing existing parity output");
        if(Files.exists(xml))throw new IllegalArgumentException("refusing existing XML output");
        CollectionHealthTest.root=Files.createDirectory(scratch);shared=(Map<?,?>)Json.parse(Files.readString(fixtures));
        check(shared.get("fixtureVersion").equals(1L),"unsupported fixture version");
        for(Object item:(List<?>)shared.get("cases")){Map<?,?> c=(Map<?,?>)item;test("coverage-"+c.get("name"),()->caseTest(c));}
        for(Object item:(List<?>)shared.get("streamCases")){Map<?,?> c=(Map<?,?>)item;test("stream-"+c.get("name"),()->streamCase(c));}
        producerTests();workerTests();readonlyTests();historyTests();
        long failed=CollectionHealthTest.results.stream().filter(r->!r.get("status").equals("pass")).count();
        writeXml(xml);
        System.out.println("COVERAGE RESULT cases="+CollectionHealthTest.results.size()+" failed="+failed);
        if(failed>0)throw new AssertionError("coverage controls failed: "+failed);
        parity.sort(java.util.Comparator.comparing(row->(String)row.get("name")));
        if(output!=null)Files.writeString(output,Json.write(Map.of("fixtureVersion",1L,"results",parity))+"\n");
    }
    static void writeXml(Path path)throws Exception {
        var results=CollectionHealthTest.results;
        StringBuilder out=new StringBuilder("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<testsuite name=\"CoverageTest\" timestamp=\"").append(java.time.Instant.now())
                .append("\" tests=\"").append(results.size()).append("\" failures=\"").append(results.stream().filter(r->r.get("status").equals("failure")).count())
                .append("\" errors=\"").append(results.stream().filter(r->r.get("status").equals("error")).count()).append("\" skipped=\"0\">\n");
        for(var row:results) {
            out.append("<testcase classname=\"dev.tattletale.CoverageTest\" name=\"").append(CollectionHealthTest.escape(row.get("name"))).append("\" timestamp=\"")
                    .append(row.get("timestamp")).append("\" time=\"").append(row.get("seconds")).append("\">");
            if(!row.get("status").equals("pass"))out.append('<').append(row.get("status")).append('>').append(CollectionHealthTest.escape(row.get("detail"))).append("</").append(row.get("status")).append('>');
            out.append("</testcase>\n");
        }
        out.append("</testsuite>\n");Files.writeString(path,out);
    }
}
