package dev.tattletale;
import java.io.*;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import static dev.tattletale.CollectionHealthTest.*;

/** Frozen v2 inputs drive production classification, collectors, transactions and page replacement. */
final class RepairParityTest {
 static final class Logical extends Fake implements StartupEntry.Fs {
  Map<String,Map<String,Object>> entries=new LinkedHashMap<>();String sourceFailure;
  public List<String> dirs(){return List.of("/fixture/source");}
  public List<String> files(){return List.of();}
  public List<String> list(String dir)throws IOException {
   if(sourceFailure!=null){if(sourceFailure.equals("listed-disappeared"))return List.of("/fixture/absent");throw new IOException("fixture rejected source");}
   return new ArrayList<>(entries.keySet());
  }
  public byte[] entry(String file)throws IOException{return StartupEntry.read(file,this);}
  public StartupEntry.Meta metadata(Path path)throws IOException {
   Map<String,Object> e=entries.get(path.toString());if(e==null)throw new NoSuchFileException(path.toString());String state=(String)e.get("state");
   int mode=switch(state){case "regular","permission-denied","file-too-large"->StartupEntry.REGULAR;case "directory"->StartupEntry.DIRECTORY;case "symlink-loop","dangling-link"->StartupEntry.LINK;case "fifo"->0010000;case "socket"->0140000;case "device"->0020000;default->throw new IOException("unknown fixture state");};
   long size=state.equals("file-too-large")?StartupEntry.MAX_BYTES+1L:e.get("text")==null?0:((String)e.get("text")).getBytes(StandardCharsets.UTF_8).length;
   return new StartupEntry.Meta(1,path.toString().hashCode(),mode,size,0,0,0,0);
  }
  public Path target(Path path){return entries.get(path.toString()).get("state").equals("symlink-loop")?path:Path.of("/fixture/missing-target");}
  public boolean optionalAbsent(Path path){return true;}
  public byte[] regular(Path path,StartupEntry.Meta meta)throws IOException {Map<String,Object> e=entries.get(path.toString());if(e.get("state").equals("permission-denied"))throw new AccessDeniedException(path.toString());return ((String)e.get("text")).getBytes(StandardCharsets.UTF_8);}
  public String textDiff(String before,String after,int limit){return null;}
  public void copy(String path,byte[] value)throws IOException {byte[] old=copies.get(path);if(old!=null&&!Arrays.equals(old,value))throw new IOException("fixture immutable copy mismatch");copies.putIfAbsent(path,value.clone());}
 }
 static Watch fresh(Path dir,String time)throws Exception {
  Watch w=new Watch(dir.resolve("log").toString(),dir.resolve("db").toString(),30,300,List.of(),false,100000,1,3,dir.resolve("absent-map").toString(),0,0,dir.resolve("absent-page").toString());w.clock=()->time;return w;
 }
 static Proc.Result command(Map<?,?> m){return new Proc.Result(((Number)m.get("code")).intValue(),(String)m.get("out"),(String)m.get("err"));}
 @SuppressWarnings("unchecked") static void run(Map<String,Object> shared)throws Exception {
  check(((Number)shared.get("fixtureVersion")).intValue()==2,"repair producer requires frozen fixtureVersion2");
  List<Object> results=new ArrayList<>();List<?> cases=(List<?>)shared.get("repairCases");check(cases!=null && cases.size()==9,"required repair families");
  for(Object object:cases){Map<String,Object> spec=(Map<String,Object>)object;String name=(String)spec.get("name"),kind=(String)spec.get("kind");List<Object> states=new ArrayList<>();
   test("v2-repair-family-"+name,()->{
    if(kind.equals("pid")) {
     for(Object so:(List<?>)spec.get("steps")){Map<String,Object> step=(Map<String,Object>)so;Proc.Result input=command((Map<?,?>)step.get("command"));Proc.Result normalized=new Proc.Result(input.code(),Proc.text(input.out().getBytes(StandardCharsets.UTF_8)),Proc.text(input.err().getBytes(StandardCharsets.UTF_8)));states.add(Map.of("name",step.get("name"),"classification",Watch.pidIdentity(normalized).name().toLowerCase(Locale.ROOT)));}
    } else {
     Path dir=Files.createDirectory(root.resolve("repair-family-"+name));Logical source=new Logical();Watch w=fresh(dir,T);w.sources=source;
     try {
      if(kind.startsWith("publication"))RoundThreeTest.seedProgram(w);else w.loadState();
      for(Object so:(List<?>)spec.get("steps")){
       Map<String,Object> step=(Map<String,Object>)so;String time=(String)step.get("at"),op=(String)step.get("op");w.clock=()->time;
       if(op.startsWith("startup")) {
        source.entries.clear();for(Object eo:(List<?>)step.get("entries")){Map<String,Object> entry=(Map<String,Object>)eo;source.entries.put((String)entry.get("path"),entry);}
        source.sourceFailure=(String)step.get("sourceFailure");source.cron=command((Map<?,?>)step.get("cron"));
        if(step.get("sql")!=null)w.db.exec((String)step.get("sql")+";");w.checkStartup();
       } else if(op.equals("listeners")) {source.lsof=command((Map<?,?>)step.get("command"));w.checkListeners();}
       else if(op.equals("load"))w.loadState();
       else if(op.equals("restart-load")){w.db.close();w=fresh(dir,time);w.sources=source;w.loadState();}
       else if(op.equals("save")||op.equals("save-without-load")) {
        if(step.get("dirtyTime")!=null)w.dirtyProgs.put("/fixture/program",(String)step.get("dirtyTime"));String fault=(String)step.get("fault");
        if("flush-abort".equals(fault))w.db.exec("CREATE TRIGGER fixture_flush_abort BEFORE UPDATE ON programs BEGIN SELECT RAISE(ABORT,'fixture-original'); END;");
        if("projection-db".equals(fault))w.projection=()->{throw new Db.DbException("fixture projection");};
        if("atomic-write-io".equals(fault))w.pageReplace=(a,b)->{throw new IOException("fixture replacement");};
        try{w.save();check(fault==null,"injected fault did not fire");}catch(Db.DbException|IOException e){check(fault!=null,"unexpected producer save failure: "+e);}
        finally {if("flush-abort".equals(fault))w.db.exec("DROP TRIGGER fixture_flush_abort;");w.projection=w::pageMap;w.pageReplace=(a,b)->Files.move(a,b,StandardCopyOption.REPLACE_EXISTING,StandardCopyOption.ATOMIC_MOVE);}
       } else throw new AssertionError("unknown frozen operation "+op);
       states.add(capture(w,source,(String)step.get("name")));
      }
     } finally {w.db.close();}
    }
    check(states.size()==((List<?>)spec.get("steps")).size(),"repair step denominator");
   });
   Map<String,Object> row=new LinkedHashMap<>();row.put("name",name);row.put("kind",kind);row.put("states",states);results.add(row);
  }
  parity.put("repairResults",results);
 }
 static Map<String,Object> capture(Watch w,Logical source,String name)throws Exception {
  Map<String,Object> row=new LinkedHashMap<>();row.put("name",name);row.put("collectionHealth",w.collectionHealth.snapshot());row.put("publicationHealth",w.publicationHealth.snapshot());row.put("inventoryAsOf",w.inventoryAsOf);row.put("map",w.pageMap());row.put("events",w.db.query("SELECT time,kind,message FROM events ORDER BY id;"));row.put("startupMirror",new LinkedHashMap<>(w.startup));row.put("baselines",new LinkedHashMap<>(w.baseline));row.put("dirtyPrograms",new LinkedHashMap<>(w.dirtyProgs));row.put("dirtyListeners",new LinkedHashMap<>(w.dirtyListeners));
  List<Object> versions=new ArrayList<>();for(Map<String,Object> v:w.db.query("SELECT path,hash,copy_path,seen_at FROM startup_versions ORDER BY id;")){Map<String,Object> p=new LinkedHashMap<>();p.put("path",v.get("path"));p.put("hash",v.get("hash"));p.put("copyPath",v.get("copy_path"));p.put("seenAt",v.get("seen_at"));versions.add(p);}row.put("startupVersions",versions);
  List<Object> copies=new ArrayList<>();source.copies.keySet().stream().sorted(Watch::codepointCompare).forEach(path->copies.add(Map.of("path",path,"hex",HexFormat.of().formatHex(source.copies.get(path)))));row.put("copies",copies);
  Object published=null;if(Files.exists(Path.of(w.dataDir,"tattletale-data.js"))){Map<String,Object> payload=RoundThreeTest.payload(w),selected=new LinkedHashMap<>();for(String k:List.of("formatVersion","generatedAt","version","collectionHealth","publicationHealth","inventoryAsOf","map"))selected.put(k,payload.get(k));published=selected;}row.put("published",published);return row;
 }
}
