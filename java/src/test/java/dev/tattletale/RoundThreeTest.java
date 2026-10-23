package dev.tattletale;
import java.io.*;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.TimeUnit;
import static dev.tattletale.CollectionHealthTest.*;

final class RoundThreeTest {
 static Map<String,Object> payload(Watch w)throws Exception {String s=Files.readString(Path.of(w.dataDir,"tattletale-data.js"));@SuppressWarnings("unchecked")Map<String,Object> m=(Map<String,Object>)Json.parse(s.substring("window.TATTLETALE = ".length(),s.length()-2));return m;}
 static void seedProgram(Watch w)throws Exception {w.db.exec(Db.bind("INSERT INTO programs(exe,first_seen,last_seen,user,first_pid,first_args,parent) VALUES(?,?,?,?,?,?,?)","/fixture/program",T,T,"fixture",42,"","?"));}
 static void run() {
  test("r3-exact-rollback-response-and-negative-shapes",()->{
   check(Db.noActiveTransaction(new Db.DbException(List.of("Runtime error near line 4: cannot rollback - no transaction is active (1)"))),"known response not recognized");
   check(Db.noActiveTransaction(new Db.DbException(List.of("Error near line 10: cannot rollback - no transaction is active"))),"installed shell response without optional code not recognized");
   for(Db.DbException e:List.of(new Db.DbException("cannot rollback - no transaction is active"),new Db.DbException(List.of("Runtime error near line 4: cannot rollback - no transaction is active (1)","extra error")),new Db.DbException(List.of("Runtime error near line 4: cannot rollback - no transaction is active (19)")),new Db.DbException(List.of("Runtime error near line 4: prefix cannot rollback - no transaction is active (1)"))))check(!Db.noActiveTransaction(e),"unknown rollback response accepted");
  });
  test("r3-nested-begin-preserves-caller-transaction",()->{try(Fixture f=new Fixture()){
   f.w.db.exec("CREATE TABLE fixture_nested(id INTEGER);\nBEGIN;\nINSERT INTO fixture_nested VALUES(1);");boolean rejected=false;
   try{f.w.db.transaction(List.of("INSERT INTO fixture_nested VALUES(2);"));}catch(Db.DbException e){rejected=true;}
   check(rejected && Db.asLong(f.w.db.scalar("SELECT count(*) FROM fixture_nested;"))==1,"nested body ran/caller state lost");
   f.w.db.exec("ROLLBACK;");f.w.db.transaction(List.of("INSERT INTO fixture_nested VALUES(3);"));check(Db.asLong(f.w.db.scalar("SELECT sum(id) FROM fixture_nested;"))==3,"caller rollback/reuse failed");
  }});
  test("r3-unknown-rollback-fatal-retains-original",()->{try(Fixture f=new Fixture()){
   f.w.db.exec("CREATE TABLE fixture_fail(id INTEGER);\nCREATE TRIGGER fixture_unknown BEFORE INSERT ON fixture_fail BEGIN SELECT RAISE(ABORT,'fixture-original'); END;");
   f.w.db.rollback=()->{throw new Db.DbException("injected-unknown-rollback");};boolean fatal=false;
   try{f.w.db.transaction(List.of("INSERT INTO fixture_fail VALUES(1);"));}catch(Db.Fatal e){fatal=e.getCause().getMessage().equals("fixture-original") && e.getCause().getSuppressed().length==1;}
   check(fatal,"unknown disposition reused/lost primary");boolean closed=false;try{f.w.db.exec("SELECT 1;");}catch(Db.Fatal e){closed=true;}check(closed,"unknown connection not disposed");
  }});
  test("r3-retention-failed-commit-rolls-back-and-recovers",()->{
   Path d=Files.createDirectory(root.resolve("retain-r3"));Watch w=new Watch(d.resolve("log").toString(),d.resolve("db").toString(),30,300,List.of(),false,100000,1,3,d.resolve("absent-map").toString(),1,1,d.resolve("absent-page").toString());
   try{w.clock=()->T;w.sources=new Fake();w.db.exec("PRAGMA foreign_keys=ON;\nCREATE TABLE fixture_parent(id INTEGER PRIMARY KEY);\nCREATE TABLE fixture_child(id INTEGER REFERENCES fixture_parent(id) DEFERRABLE INITIALLY DEFERRED);\nINSERT INTO events(time,kind,message)VALUES('1970-01-01T00:00:00Z','fixture','old');\nCREATE TRIGGER fixture_retain AFTER DELETE ON events BEGIN INSERT INTO fixture_child VALUES(42); END;");
    boolean rejected=false;try{w.retain();}catch(Db.DbException e){rejected=true;}check(rejected && Db.asLong(w.db.scalar("SELECT count(*) FROM events;"))==1,"retention failed commit left pending deletion");w.db.exec("DROP TRIGGER fixture_retain;");w.retain();check(Db.asLong(w.db.scalar("SELECT count(*) FROM events WHERE kind='fixture';"))==0,"retention same-handle recovery failed");
   }finally{w.db.close();}
  });
  test("r3-lf-only-pid-and-atomic-stale-replacement",()->{try(Fixture f=new Fixture()){
   for(char c:new char[]{0x85,0x2028,0x2029,0xb,0xc,0x1c,0x1d,0x1e})check(Watch.pidIdentity(new Proc.Result(0,"/fixture/other "+c+"argument\n","")).equals(Watch.PidIdentity.OTHER),"unicode split changed PID identity");
   Path p=Path.of(f.w.dataDir,"tattletale.pid");f.w.pidProbe=n->{throw new AssertionError("stale content reached probe");};
   for(String text:List.of("","garbage","2147483648")){Files.writeString(p,text);f.w.claimPidFile();check(Files.readString(p).equals(ProcessHandle.current().pid()+"\n"),"stale pid not atomically replaced");f.w.releasePidFile();}
   check(count(f.w,"NOTE")==3,"stale pid diagnostic missing");
  }});
  test("r3-bridge-preferred-over-absolute-c-escaped-display",()->{try(Fixture f=new Fixture()){
   Fake fake=new Fake(){public String pidPath(long pid){return "/fixture/slé";}};fake.comm=new Proc.Result(0,"42 1 fixture /fixture/slM-CM-)\n","");f.w.sources=fake;f.w.checkProcesses();check(f.w.knownProgs.contains("/fixture/slé") && !f.w.knownProgs.contains("/fixture/slM-CM-)"),"escaped display used as identity");
  }});
  test("r5-effective-executable-root-rejected-after-bridge-preference",()->{
   try(Fixture f=new Fixture()) {
    f.w.checkProcesses();status(f.w,"processes","ok");Map<String,Object> before=f.w.pageMap();
    Set<String> known=new HashSet<>(f.w.knownProgs);Map<Long,String> previous=f.w.prevPids;Map<String,Boolean> baselines=new HashMap<>(f.w.baseline);Map<String,String> dirty=new LinkedHashMap<>(f.w.dirtyProgs);
    List<Map<String,Object>> events=f.w.db.query("SELECT time,kind,message FROM events ORDER BY id;");List<String> queue=new ArrayList<>(f.w.identQ);
    f.w.clock=()->"2000-01-01T00:01:00Z";f.fake.comm=new Proc.Result(0,"42 1 fixture /\n","");f.w.checkProcesses();
    check(health(f.w,"processes").get("status").equals("degraded") && health(f.w,"processes").get("error").equals("ps-parse"),"effective slash executable was accepted");
    check(f.w.pageMap().equals(before) && f.w.knownProgs.equals(known) && f.w.prevPids==previous && f.w.baseline.equals(baselines) && f.w.dirtyProgs.equals(dirty) && new ArrayList<>(f.w.identQ).equals(queue) && f.w.db.query("SELECT time,kind,message FROM events ORDER BY id;").equals(events),"rejected slash changed accepted inventory/baselines/events/queue");
    check(Db.asLong(f.w.db.scalar("SELECT count(*) FROM programs WHERE exe='/';"))==0,"invented root program");
   }
   try(Fixture f=new Fixture()) {
    Fake bridge=new Fake(){public String pidPath(long pid){return "/fixture/actual";}};bridge.comm=new Proc.Result(0,"42 1 fixture /\n","");f.w.sources=bridge;f.w.checkProcesses();status(f.w,"processes","ok");
    check(f.w.knownProgs.equals(Set.of("/fixture/actual")) && !f.w.knownProgs.contains("/"),"valid bridge did not replace slash display");
   }
   try(Fixture f=new Fixture()) {
    f.w.sources=new Fake(){public String pidPath(long pid){return "/";}};f.w.checkProcesses();status(f.w,"processes","ok");
    check(f.w.knownProgs.equals(Set.of("/fixture/a")),"invalid root bridge displaced valid comm");
   }
  });
  test("r3-invalid-path-degrades-and-cron-continues",()->{try(Fixture f=new Fixture()){
   Fake fake=new Fake(){public byte[] entry(String file)throws IOException {Path.of(file);return super.entry(file);}};fake.files.put("\0",new byte[0]);f.w.sources=fake;f.w.checkStartup();check(health(f.w,"startup").get("error").equals("startup-read") && fake.cronCalls==1,"invalid path killed/suppressed cron");status(f.w,"crontab","ok");
  }});
  test("r3-actual-default-source-strictness-and-conflicting-locale",()->{
   Path d=root.resolve("default-source-r3");String java=System.getProperty("java.home")+"/bin/java";
   ProcessBuilder pb=new ProcessBuilder(java,"--enable-native-access=ALL-UNNAMED","-Duser.home="+System.getProperty("user.home"),"-cp",System.getProperty("java.class.path"),"dev.tattletale.DefaultSourcesProbe",d.toString());pb.environment().put("LC_ALL","fixture-conflicting-parent");pb.redirectErrorStream(true);Process p=pb.start();
   try{if(!p.waitFor(5,TimeUnit.SECONDS))throw new AssertionError("owned default source deadline");String text=new String(p.getInputStream().readAllBytes(),StandardCharsets.UTF_8);check(p.exitValue()==0 && text.contains("DEFAULT_SOURCE_STRICT_AND_C"),"default source wiring: "+text);}finally{if(p.isAlive()){p.destroyForcibly();p.waitFor();}}
  });
  test("r3-actual-entry-types-limit-and-races",()->{
   check(StartupEntry.Darwin.permissionErrno(1) && StartupEntry.Darwin.permissionErrno(13) && !StartupEntry.Darwin.permissionErrno(2) && !StartupEntry.Darwin.permissionErrno(5),"Darwin permission errno classification");
   Path d=Files.createDirectory(root.resolve("native-entry-r3")),file=d.resolve("file");Files.writeString(file,"regular");Watch.Sources actual=Proc::collector;
   check(Arrays.equals(actual.entry(file.toString()),"regular".getBytes(StandardCharsets.UTF_8)),"regular control");Path link=d.resolve("link");Files.createSymbolicLink(link,file);check(Arrays.equals(actual.entry(link.toString()),"regular".getBytes(StandardCharsets.UTF_8)),"resolved regular link");
   Path dir=Files.createDirectory(d.resolve("mode0"));Files.setPosixFilePermissions(dir,Set.of());try{marker(actual,dir,"directory");}finally{Files.setPosixFilePermissions(dir,java.nio.file.attribute.PosixFilePermissions.fromString("rwx------"));}
   Files.setPosixFilePermissions(file,Set.of());try{marker(actual,file,"permission-denied");}finally{Files.setPosixFilePermissions(file,java.nio.file.attribute.PosixFilePermissions.fromString("rw-------"));}
   Path cycle=d.resolve("cycle");Files.createSymbolicLink(cycle,cycle);marker(actual,cycle,"symlink-loop");Path missing=d.resolve("dangling");Files.createSymbolicLink(missing,d.resolve("not-there"));marker(actual,missing,"dangling-link");
   Path fifo=d.resolve("fifo");mkfifo(fifo);marker(actual,fifo,"not-a-regular-file");
   Path inaccessible=Files.createDirectory(d.resolve("ancestor")),inside=inaccessible.resolve("file");Files.writeString(inside,"x");Files.setPosixFilePermissions(inaccessible,Set.of());boolean rejected=false;
   try{actual.entry(inside.toString());}catch(IOException e){rejected=!(e instanceof Watch.Unreadable);}finally{Files.setPosixFilePermissions(inaccessible,java.nio.file.attribute.PosixFilePermissions.fromString("rwx------"));}check(rejected,"ancestor uncertainty became marker");
   byte[] max=new byte[StartupEntry.MAX_BYTES];Files.write(file,max);check(actual.entry(file.toString()).length==max.length,"exact16MiB control");Files.write(file,new byte[]{1},StandardOpenOption.APPEND);marker(actual,file,"file-too-large");
   Files.writeString(file,"small");StartupEntry.Meta before=StartupEntry.REAL.metadata(file);rejected=false;
   try{StartupEntry.Darwin.read(file,before,()->{Files.delete(file);mkfifo(file);},()->{});}catch(IOException e){rejected=true;}check(rejected,"regular-to-FIFO race accepted/blocked");
   Files.delete(file);Files.writeString(file,"small");before=StartupEntry.REAL.metadata(file);rejected=false;
   try{StartupEntry.Darwin.read(file,before,()->{},()->Files.writeString(file,"growth",StandardOpenOption.APPEND));}catch(IOException e){rejected=true;}check(rejected,"growth race accepted");
  });
  test("r3-symlink-spelling-target-ancestors-and-retarget-races",()->{
   Path d=Files.createDirectory(root.resolve("native-links-r3")),target=Files.createDirectories(d.resolve("target/nested"));
   Files.writeString(d.resolve("item"),"wrong");Files.writeString(target.getParent().resolve("item"),"right");Path alias=d.resolve("alias");Files.createSymbolicLink(alias,target);
   check(new String(StartupEntry.read(alias+"/../item"),StandardCharsets.UTF_8).equals("right"),"symlink/.. kernel semantics changed");
   Path broken=d.resolve("broken"),outer=d.resolve("outer");Files.createSymbolicLink(broken,d.resolve("missing"));Files.createSymbolicLink(outer,broken.resolve("file"));boolean rejected=false;
   try{StartupEntry.read(outer.toString());}catch(IOException e){rejected=!(e instanceof Watch.Unreadable);}check(rejected,"broken target ancestor became dangling marker");
   Path a=d.resolve("a"),b=d.resolve("b"),link=d.resolve("link");Files.writeString(a,"A");Files.writeString(b,"B");Files.createSymbolicLink(link,a);
   StartupEntry.Fs retarget=new DelegatingFs(){public byte[] regular(Path p,StartupEntry.Meta m)throws IOException{byte[] bytes=super.regular(p,m);Files.delete(link);Files.createSymbolicLink(link,b);return bytes;}};
   rejected=false;try{StartupEntry.read(link.toString(),retarget);}catch(IOException e){rejected=!(e instanceof Watch.Unreadable);}check(rejected,"link retarget adopted wrong source association");
   Files.delete(link);Files.createSymbolicLink(link,a);StartupEntry.Fs markerRace=new DelegatingFs(){boolean changed;public StartupEntry.Meta metadata(Path p)throws IOException{StartupEntry.Meta m=super.metadata(p);if(p.equals(d.resolve("dir"))&&!changed){changed=true;Files.delete(link);Files.createSymbolicLink(link,b);}return m;}};
   Files.createDirectory(d.resolve("dir"));Files.delete(link);Files.createSymbolicLink(link,d.resolve("dir"));rejected=false;
   try{StartupEntry.read(link.toString(),markerRace);}catch(IOException e){rejected=!(e instanceof Watch.Unreadable);}check(rejected,"retarget during marker persisted old association");
   Path original=d.resolve("original"),kept=d.resolve("kept");Files.writeString(original,"same inode");StartupEntry.Meta m=StartupEntry.REAL.metadata(original);rejected=false;
   try{StartupEntry.Darwin.read(original,m,()->{Files.move(original,kept);Files.createSymbolicLink(original,kept);},()->{});}catch(IOException e){rejected=true;}check(rejected,"final symlink to original inode followed after precheck");
  });
  publication();
 }
 static class DelegatingFs implements StartupEntry.Fs {
  public StartupEntry.Meta metadata(Path p)throws IOException{return StartupEntry.REAL.metadata(p);}
  public Path target(Path p)throws IOException{return StartupEntry.REAL.target(p);}
  public byte[] regular(Path p,StartupEntry.Meta m)throws IOException{return StartupEntry.REAL.regular(p,m);}
  public boolean optionalAbsent(Path p)throws IOException{return StartupEntry.REAL.optionalAbsent(p);}
  public List<StartupEntry.Observed> ancestorLinks(Path p)throws IOException{return StartupEntry.REAL.ancestorLinks(p);}
 }
 static void marker(Watch.Sources s,Path p,String reason)throws Exception {boolean marked=false;try{s.entry(p.toString());}catch(Watch.Unreadable e){marked=e.marker.equals("unreadable: "+reason);}check(marked,"marker "+reason);}
 static void mkfifo(Path p)throws IOException {try{Process child=new ProcessBuilder("/usr/bin/mkfifo",p.toString()).start();if(!child.waitFor(2,TimeUnit.SECONDS)){child.destroyForcibly();child.waitFor();throw new IOException("fixture mkfifo deadline");}if(child.exitValue()!=0)throw new IOException("fixture mkfifo failure");}catch(InterruptedException e){Thread.currentThread().interrupt();throw new IOException(e);}}
 static void publication() {
  publicationCurrentHealth();
  publicationCacheIsolation();
  publicationNoCacheExistingPage();
  test("r3-publication-fallback-primary-error-dirty-recovery",()->{try(Fixture f=new Fixture()){
   seedProgram(f.w);f.w.loadState();f.w.save();Map<String,Object> initial=payload(f.w);check(((Map<?,?>)initial.get("publicationHealth")).get("status").equals("ok"),"healthy publication");
   f.w.clock=()->"2000-01-01T00:01:00Z";f.w.dirtyProgs.put("/fixture/program","2000-01-01T02:00:00Z");f.w.db.exec("CREATE TRIGGER fixture_flush BEFORE UPDATE ON programs BEGIN SELECT RAISE(ABORT,'fixture-original'); END;");
   boolean rejected=false;try{f.w.save();}catch(Db.DbException e){rejected=e.getMessage().equals("fixture-original");}check(rejected && !f.w.dirtyProgs.isEmpty(),"rollback cleared dirties/lost primary");Map<String,Object> fallback=payload(f.w);check(((Map<?,?>)fallback.get("publicationHealth")).get("error").equals("collection-db") && fallback.get("inventoryAsOf").equals(T),"fallback published false success");
   byte[] prior=Files.readAllBytes(Path.of(f.w.dataDir,"tattletale-data.js"));f.w.pageReplace=(a,b)->{throw new IOException("fixture-write");};rejected=false;
   try{f.w.save();}catch(Db.DbException e){rejected=e.getMessage().equals("fixture-original") && e.getSuppressed().length==1;}check(rejected && f.w.publicationHealth.snapshot().get("error").equals("collection-io") && Arrays.equals(prior,Files.readAllBytes(Path.of(f.w.dataDir,"tattletale-data.js"))),"fallback write lost DB primary/old bytes");
   f.w.pageReplace=(a,b)->Files.move(a,b,StandardCopyOption.ATOMIC_MOVE,StandardCopyOption.REPLACE_EXISTING);f.w.db.exec("DROP TRIGGER fixture_flush;");f.w.clock=()->"2000-01-01T00:02:00Z";f.w.save();check(f.w.dirtyProgs.isEmpty() && f.w.publicationHealth.snapshot().get("lastSuccess").equals("2000-01-01T00:02:00Z"),"full recovery");
  }});
  test("r3-publication-detach-projection-and-write-boundaries",()->{try(Fixture f=new Fixture()){
   seedProgram(f.w);f.w.loadState();f.w.save();Map<String,Object> old=payload(f.w);f.w.clock=()->"2000-01-01T00:01:00Z";f.w.dirtyProgs.put("/fixture/program","2000-01-01T02:00:00Z");
   f.w.projection=()->{f.w.pageMap();throw new Db.DbException("fixture projection");};try{f.w.save();}catch(Db.DbException expected){}check(f.w.dirtyProgs.isEmpty(),"committed dirty resurrected");
   Map<String,Object> actual=f.w.pageMap();((Map<?,?>)actual.get("programs")).clear();check(payload(f.w).get("map").equals(old.get("map")),"detached cache corrupted");
   f.w.projection=f.w::pageMap;f.w.pageReplace=(a,b)->{throw new IOException("fixture write");};byte[] prior=Files.readAllBytes(Path.of(f.w.dataDir,"tattletale-data.js"));boolean failed=false;try{f.w.save();}catch(IOException e){failed=true;}check(failed && Arrays.equals(prior,Files.readAllBytes(Path.of(f.w.dataDir,"tattletale-data.js"))) && f.w.publicationHealth.snapshot().get("lastSuccess").equals(T),"failed write adopted tentative success");
   f.w.projection=()->{throw new Db.Fatal(new Db.DbException("fixture fatal"));};failed=false;try{f.w.save();}catch(Db.Fatal e){failed=true;}check(failed,"fatal disguised as recoverable fallback");
  }});
  test("r3-publication-requires-idle-recovered-connection",()->{
   for(boolean seed:List.of(false,true))try(Fixture f=new Fixture()){
    f.w.save();byte[] prior=Files.readAllBytes(Path.of(f.w.dataDir,"tattletale-data.js"));Db.DbException original=new Db.DbException("fixture projection active");
    f.w.projection=()->{f.w.db.exec("BEGIN;");throw original;};boolean fatal=false;
    try{if(seed)f.w.loadState();else f.w.save();}catch(Db.Fatal e){fatal=e.getCause()==original && original.getSuppressed().length==1;}
    check(fatal && Arrays.equals(prior,Files.readAllBytes(Path.of(f.w.dataDir,"tattletale-data.js"))),"active projection error became recoverable/cache write");
   }
   try(Fixture f=new Fixture()){
    f.w.save();byte[] prior=Files.readAllBytes(Path.of(f.w.dataDir,"tattletale-data.js"));Db.DbException original=new Db.DbException("fixture projection closed");
    f.w.projection=()->{f.w.db.close();throw original;};boolean fatal=false;try{f.w.save();}catch(Db.Fatal e){fatal=e.getCause()==original && original.getSuppressed().length==1;}
    check(fatal && Arrays.equals(prior,Files.readAllBytes(Path.of(f.w.dataDir,"tattletale-data.js"))),"closed projection error became recoverable");
   }
   try(Fixture f=new Fixture()){
    f.w.projection=()->{throw new Db.DbException("fixture optional seed");};f.w.loadState();check(f.w.cachedInventory==null && f.w.inventoryAsOf==null,"failed optional seed fabricated cache");f.w.db.transaction(List.of("SELECT 1;"));
   }
  });
 }
 static void publicationCurrentHealth() {
  test("r4-publication-fallback-current-collector-health",()->{try(Fixture f=new Fixture()){
   seedProgram(f.w);f.w.loadState();f.fake.lsof=new Proc.Result(0,"","");f.w.checkListeners();status(f.w,"listeners","ok");f.w.save();
   Map<String,Object> initial=payload(f.w);Map<?,?> initialHealth=(Map<?,?>)initial.get("collectionHealth");
   check(((Map<?,?>)initialHealth.get("listeners")).get("status").equals("ok"),"initial published listener health not ok");
   Files.copy(Path.of(f.w.dataDir,"tattletale-data.js"),Path.of(f.w.dataDir,"current-health-initial.js"));
   String failedAt="2000-01-01T00:01:00Z",recoveredAt="2000-01-01T00:02:00Z";
   f.w.clock=()->failedAt;f.fake.lsof=new Proc.Result(7,"","");f.w.checkListeners();status(f.w,"listeners","degraded");
   Map<String,Object> current=f.w.collectionHealth.snapshot();check(!current.equals(initialHealth) && health(f.w,"listeners").get("error").equals("lsof-command"),"fixture did not change actual collector health");
   f.w.dirtyProgs.put("/fixture/program",failedAt);f.w.db.exec("CREATE TRIGGER fixture_current_health BEFORE UPDATE ON programs BEGIN SELECT RAISE(ABORT,'fixture-current-health'); END;");
   boolean rejected=false;try{f.w.save();}catch(Db.DbException e){rejected=e.getMessage().equals("fixture-current-health");}check(rejected,"expected program flush abort not reported");
   Map<String,Object> fallback=payload(f.w);check(fallback.get("map").equals(initial.get("map")) && fallback.get("inventoryAsOf").equals(initial.get("inventoryAsOf")),"fallback changed cached inventory/as-of");
   Files.copy(Path.of(f.w.dataDir,"tattletale-data.js"),Path.of(f.w.dataDir,"current-health-fallback.js"));
   check(fallback.get("collectionHealth").equals(current) && !fallback.get("collectionHealth").equals(initialHealth),"fallback serialized stale collector health");
   Map<?,?> publication=(Map<?,?>)fallback.get("publicationHealth");check(publication.get("status").equals("degraded") && publication.get("error").equals("collection-db") && publication.get("lastSuccess").equals(T) && publication.get("lastAttempt").equals(failedAt),"fallback publication advanced success/lost failure");
   check(f.w.dirtyProgs.equals(Map.of("/fixture/program",failedAt)),"failed flush lost dirty program");
   f.w.db.exec("DROP TRIGGER fixture_current_health;");f.w.clock=()->recoveredAt;f.w.save();Map<String,Object> recovered=payload(f.w);
   check(((Map<?,?>)recovered.get("publicationHealth")).get("status").equals("ok") && ((Map<?,?>)recovered.get("publicationHealth")).get("lastSuccess").equals(recoveredAt) && f.w.dirtyProgs.isEmpty(),"publication recovery failed");
   check(recovered.get("collectionHealth").equals(current) && health(f.w,"listeners").get("status").equals("degraded"),"publication recovery healed failed collector");
   Files.copy(Path.of(f.w.dataDir,"tattletale-data.js"),Path.of(f.w.dataDir,"current-health-recovered.js"));
  }});
 }
 @SuppressWarnings("unchecked") static void publicationCacheIsolation() {
  test("r6-publication-cache-detaches-exact-supplied-projection",()->{try(Fixture f=new Fixture()){
   seedProgram(f.w);f.w.db.exec(Db.bind("INSERT INTO credential_events(time,pid,user,exe,args,chain,source) VALUES(?,?,?,?,?,?,?)",T,42,"fixture","/fixture/program","","?","fixture"));
   Map<String,Object> supplied=f.w.pageMap(),pristine=(Map<String,Object>)Json.parse(Json.write(supplied));f.w.projection=()->supplied;f.w.loadState();
   ((Map<String,Object>)((Map<String,Object>)supplied.get("programs")).get("/fixture/program")).put("user","changed-after-cache");
   List<Object> credentials=(List<Object>)supplied.get("credentials");((Map<String,Object>)credentials.getFirst()).put("exe","/fixture/changed");credentials.add(Map.of("source","extra-after-cache"));
   check(!supplied.equals(pristine),"fixture did not mutate exact nested supplied projection");
   Files.writeString(Path.of(f.w.dataDir,"cache-pristine.json"),Json.write(pristine));Files.writeString(Path.of(f.w.dataDir,"cache-mutated-supplied.json"),Json.write(supplied));
   f.w.clock=()->"2000-01-01T00:01:00Z";f.w.dirtyProgs.put("/fixture/program","2000-01-01T00:01:00Z");f.w.db.exec("CREATE TRIGGER fixture_cache_alias BEFORE UPDATE ON programs BEGIN SELECT RAISE(ABORT,'fixture-cache-alias'); END;");
   boolean failed=false;try{f.w.save();}catch(Db.DbException e){failed=e.getMessage().equals("fixture-cache-alias");}check(failed,"cache isolation flush fault did not fire");
   Map<String,Object> fallback=payload(f.w);Files.copy(Path.of(f.w.dataDir,"tattletale-data.js"),Path.of(f.w.dataDir,"cache-isolation-fallback.js"));
   check(fallback.get("map").equals(pristine),"fallback map changed through cache alias");check(fallback.get("inventoryAsOf").equals(T) && !f.w.dirtyProgs.isEmpty(),"cache isolation lost as-of/dirty retention");
  }});
 }
 static void publicationNoCacheExistingPage() {
  test("r6-publication-no-cache-preserves-existing-bytes-and-recovers",()->{
   Path d=Files.createDirectory(root.resolve("no-cache-existing-r6"));Watch w=RepairParityTest.fresh(d,T);w.sources=new Fake();
   try {
    seedProgram(w);byte[] prior="window.TATTLETALE = {\"fixturePrior\":true};\n".getBytes(StandardCharsets.UTF_8);Path page=Path.of(w.dataDir,"tattletale-data.js");Files.write(page,prior);
    check(w.cachedInventory==null && w.inventoryAsOf==null,"no-load fixture unexpectedly cached");w.dirtyProgs.put("/fixture/program","2000-01-01T00:01:00Z");w.db.exec("CREATE TRIGGER fixture_no_cache BEFORE UPDATE ON programs BEGIN SELECT RAISE(ABORT,'fixture-no-cache'); END;");
    boolean failed=false;try{w.save();}catch(Db.DbException e){failed=e.getMessage().equals("fixture-no-cache");}check(failed,"no-cache actual flush fault did not fire");
    check(Arrays.equals(Files.readAllBytes(page),prior),"no-cache failure replaced existing bytes");Files.copy(page,d.resolve("no-cache-prior-retained.js"));
    Map<String,Object> health=w.publicationHealth.snapshot();check(w.cachedInventory==null && w.inventoryAsOf==null && health.get("status").equals("degraded") && health.get("error").equals("collection-db") && health.get("lastSuccess")==null && w.dirtyProgs.equals(Map.of("/fixture/program","2000-01-01T00:01:00Z")),"no-cache failure fabricated inventory/success or lost dirty update");
    w.db.exec("DROP TRIGGER fixture_no_cache;");w.clock=()->"2000-01-01T00:02:00Z";w.save();Map<String,Object> recovered=payload(w);
    check(((Map<?,?>)recovered.get("map")).equals(w.pageMap()) && ((Map<?,?>)((Map<?,?>)recovered.get("map")).get("programs")).containsKey("/fixture/program") && recovered.get("inventoryAsOf").equals("2000-01-01T00:02:00Z") && ((Map<?,?>)recovered.get("publicationHealth")).get("status").equals("ok") && w.dirtyProgs.isEmpty(),"no-cache real inventory recovery failed");Files.copy(page,d.resolve("no-cache-recovered.js"));
   } finally {w.db.close();}
  });
 }
}
