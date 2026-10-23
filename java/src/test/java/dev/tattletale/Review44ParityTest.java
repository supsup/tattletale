package dev.tattletale;

import java.io.IOException;
import java.net.StandardProtocolFamily;
import java.net.UnixDomainSocketAddress;
import java.nio.channels.ServerSocketChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import static dev.tattletale.CollectionHealthTest.*;

/** Root-owned v3 input, actual production calls and independently checked observations. */
final class Review44ParityTest {
    @SuppressWarnings("unchecked") static void run(Map<String,Object> shared) throws Exception {
        check(((Number)shared.get("fixtureVersion")).intValue()==3,"review44 fixture version");
        Map<String,Object> specs=(Map<String,Object>)shared.get("review44Cases"),observed=new LinkedHashMap<>();
        List<Object> processes=new ArrayList<>(),entries=new ArrayList<>(),listeners=new ArrayList<>(),pids=new ArrayList<>();
        for(Object object:(List<?>)specs.get("processIdentities")) {
            Map<String,Object> spec=(Map<String,Object>)object;
            test("review44-process-"+spec.get("name"),()->{try(Fixture f=new Fixture()){
                int[] calls={0};Fake source=new Fake(){public String pidPath(long pid){check(pid==42,"unexpected bridge pid");calls[0]++;return (String)spec.get("bridge");}};
                source.comm=new Proc.Result(0,"42 1 fixture "+spec.get("psComm")+"\n","");f.w.sources=source;
                boolean accepted=false;String exe=null;
                try{Map<Long,Watch.P> actual=f.w.processes();exe=actual.get(42L).exe();accepted=true;}catch(CollectionHealth.Rejected rejected){check(rejected.code.equals("ps-parse"),"unexpected process rejection");}
                Map<String,Object> row=row((String)spec.get("name"));row.put("accepted",accepted);row.put("exe",exe);row.put("bridgeCalls",calls[0]);processes.add(row);assertExpected(row,(Map<?,?>)spec.get("expected"));
            }});
        }
        for(Object object:(List<?>)specs.get("entryDispositions")) {
            Map<String,Object> spec=(Map<String,Object>)object;
            test("review44-entry-"+spec.get("name"),()->{
                Path d=Files.createDirectory(root.resolve("review44-entry-"+spec.get("name"))),entry=d.resolve("entry"),regular=d.resolve("regular");Files.writeString(regular,"A\n");
                String state=(String)spec.get("state");StartupEntry.Fs fs=StartupEntry.REAL;ServerSocketChannel socket=null;
                switch(state) {
                    case "regular" -> entry=regular;
                    case "optional-missing" -> {}
                    case "dangling-link" -> Files.createSymbolicLink(entry,d.resolve("missing"));
                    case "target-directory-loop" -> {Path loop=d.resolve("loop");Files.createSymbolicLink(loop,loop);Files.createSymbolicLink(entry,loop.resolve("child"));}
                    case "link-enotdir" -> Files.createSymbolicLink(entry,regular.resolve("child"));
                    case "extra-enotdir" -> entry=regular.resolve("child");
                    case "fifo" -> RoundThreeTest.mkfifo(entry);
                    case "socket" -> {
                        // A relative owned build path stays below Darwin's short sockaddr_un limit.
                        entry=Path.of("java/build/review44-"+ProcessHandle.current().pid()+".sock");socket=ServerSocketChannel.open(StandardProtocolFamily.UNIX);socket.bind(UnixDomainSocketAddress.of(entry));
                    }
                    case "listed-lstat-eacces" -> {
                        Files.writeString(entry,"listed child\n");try(DirectoryStream<Path> ds=Files.newDirectoryStream(d)){boolean listed=false;for(Path p:ds)if(p.equals(entry))listed=true;check(listed,"EACCES seam child was not actually listed");}
                        Path denied=entry;fs=new RoundThreeTest.DelegatingFs(){public StartupEntry.Meta metadata(Path p)throws IOException{if(p.equals(denied))throw new AccessDeniedException(p.toString());return super.metadata(p);}};
                    }
                    default -> throw new AssertionError("unknown entry fixture");
                }
                Object result;
                try{byte[] actual=StartupEntry.read(entry.toString(),fs);result=actual==null?null:"readable:"+HexFormat.of().formatHex(Watch.sha256().digest(actual));}
                catch(Watch.Unreadable unreadable){result=unreadable.marker;}
                catch(IOException rejected){result="rejected";}
                finally{if(socket!=null)socket.close();}
                Map<String,Object> row=row((String)spec.get("name"));row.put("result",result);entries.add(row);check(Objects.equals(result,spec.get("expectedResult")),"entry disposition "+row);
            });
        }
        for(Object object:(List<?>)specs.get("listenerIdentities")) {
            Map<String,Object> spec=(Map<String,Object>)object;
            test("review44-listener-"+spec.get("name"),()->{try(Fixture f=new Fixture()){
                int[] calls={0};Fake source=new Fake(){
                    public String pidPath(long pid){check(pid==42,"unexpected listener bridge pid");return (String)spec.get("bridge");}
                    public Proc.Result run(List<String> c,long timeout)throws IOException{
                        if(c.equals(List.of("ps","-o","comm=","-p","42"))){calls[0]++;check(spec.get("comm")!=null,"unexpected fallback command");return new Proc.Result(0,spec.get("comm")+"\n","");}
                        return super.run(c,timeout);
                    }
                };
                source.comm=new Proc.Result(0,"99 1 fixture /fixture/snapshot-peer\n","");source.args=new Proc.Result(0,"99 /fixture/snapshot-peer\n","");source.lsof=new Proc.Result(0,"p42\ncfixture\nn127.0.0.1:12345\n","");f.w.sources=source;f.w.checkListeners();
                boolean accepted=health(f.w,"listeners").get("status").equals("ok");List<Map<String,Object>> actual=f.w.db.query("SELECT exe FROM listeners ORDER BY key;");String exe=actual.isEmpty()?null:Db.asStr(actual.getFirst().get("exe"));
                check(actual.size()==(accepted?1:0),"listener mirror/DB acceptance differs");Map<String,Object> row=row((String)spec.get("name"));row.put("accepted",accepted);row.put("exe",exe);row.put("commCalls",calls[0]);listeners.add(row);assertExpected(row,(Map<?,?>)spec.get("expected"));
            }});
        }
        List<Object> rawPidDiagnostics=new ArrayList<>();
        for(Object object:(List<?>)specs.get("pidFiles")) {
            Map<String,Object> spec=(Map<String,Object>)object;
            test("review44-pid-"+spec.get("name"),()->{try(Fixture f=new Fixture()){
                Path pid=Path.of(f.w.dataDir,"tattletale.pid");byte[] before=HexFormat.of().parseHex((String)spec.get("initialHex"));Files.write(pid,before);
                f.w.pidProbe=n->{check(n==42,"unexpected synthetic pid");return switch((String)spec.get("probe")){
                    case "must-not-call" -> throw new AssertionError("invalid stale PID reached probe");
                    case "absent" -> new Proc.Result(1,"","");case "unknown" -> new Proc.Result(7,"","");case "watcher" -> new Proc.Result(0,"python tattletale.py --fixture\n","");default -> throw new AssertionError("unknown probe fixture");};};
                if(Boolean.TRUE.equals(spec.get("replaceFailure")))f.w.pidReplace=(from,to)->{check(Files.readString(from).equals(ProcessHandle.current().pid()+"\n"),"atomic move boundary before full temp bytes");throw new IOException("fixture pid atomic replacement failure");};
                boolean accepted=false,error=false;String failure=null;
                try{f.w.claimPidFile();accepted=true;}catch(IOException|Watch.Exit e){error=true;failure=e.toString();}
                byte[] after=Files.readAllBytes(pid);Map<String,Object> row=row((String)spec.get("name"));row.put("accepted",accepted);row.put("pidFileSet",f.w.pidFile!=null);row.put("pidFileMatchesCurrentProcess",Arrays.equals(after,(ProcessHandle.current().pid()+"\n").getBytes(StandardCharsets.UTF_8)));row.put("noteCount",count(f.w,"NOTE"));row.put("originalBytesPreserved",Arrays.equals(after,before));row.put("errorObserved",error);pids.add(row);
                Map<String,Object> raw=row((String)spec.get("name"));raw.put("currentPid",ProcessHandle.current().pid());raw.put("beforeHex",HexFormat.of().formatHex(before));raw.put("afterHex",HexFormat.of().formatHex(after));raw.put("error",failure);rawPidDiagnostics.add(raw);
                assertExpected(row,(Map<?,?>)spec.get("expected"));
            }});
        }
        Files.writeString(root.resolve("review44-pid-raw.json"),Json.write(rawPidDiagnostics)+"\n");
        check(processes.size()==16 && entries.size()==9 && listeners.size()==6 && pids.size()==6,"review44 row denominator");
        observed.put("processIdentities",processes);observed.put("entryDispositions",entries);observed.put("listenerIdentities",listeners);observed.put("pidFiles",pids);parity.put("review44",observed);
    }
    static Map<String,Object> row(String name){Map<String,Object> row=new LinkedHashMap<>();row.put("name",name);return row;}
    static void assertExpected(Map<String,Object> actual,Map<?,?> expected){for(Map.Entry<?,?> e:expected.entrySet())check(Objects.equals(actual.get(e.getKey()),e.getValue()) || actual.get(e.getKey()) instanceof Number a && e.getValue() instanceof Number b && a.longValue()==b.longValue(),"review44 observation "+actual+" expected "+expected);}
}
