package dev.tattletale;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;

/** Read-only sampled-coverage prerequisite. Filtering consumers must preserve refusal. */
final class Coverage {
    static final long VERSION=1;
    static final double KEYCHAIN_CADENCE=3;
    static final int PAGE_SIZE=512;
    static final List<String> COLLECTORS=List.of("processes","listeners","startup","crontab","keychain");
    private Coverage() {}

    static double time(Object raw) {
        if(!(raw instanceof String text) || text.startsWith("0000") || !text.matches("[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z"))
            throw new IllegalArgumentException("invalid-time");
        Instant value=Instant.parse(text);
        // Instant.parse normalizes leap seconds; those are ambiguous evidence here.
        if(!value.toString().equals(text)) throw new IllegalArgumentException("invalid-time");
        return value.getEpochSecond();
    }
    static Map<String,Object> issue(String collector,String reason) {
        Map<String,Object> result=new LinkedHashMap<>();result.put("collector",collector);result.put("reason",reason);return result;
    }
    static Map<String,Object> result(String since,String until,List<Map<String,Object>> issues,Long count) {
        Map<String,Object> result=new LinkedHashMap<>();result.put("resultVersion",VERSION);result.put("since",since);result.put("until",until);
        result.put("outcome",!issues.isEmpty()?"REFUSED":count!=null && count==0?"QUIET":"EVENTS");
        result.put("eventCount",count);result.put("issues",issues);return result;
    }
    static Map<String,Object> refused(String since,String until,String collector,String why) {
        return result(since,until,List.of(issue(collector,why)),null);
    }
    static boolean versions(Db db,String table,long version) throws Db.DbException {
        List<Map<String,Object>> rows=db.query("SELECT version FROM "+table+" LIMIT 2;");
        return rows.size()==1 && rows.getFirst().get("version") instanceof Long value && value==version;
    }
    record Pulse(long rowid,double at,String status,String error,double grace) {}
    static final Comparator<Pulse> CHRONOLOGICAL=Comparator.comparingDouble(Pulse::at).thenComparingLong(Pulse::rowid);

    /** One bounded JSON result at a time, including SQLite's full signed rowid range.
     * No OFFSET or rowid arithmetic: MIN_VALUE is included in the first page and
     * MAX_VALUE cannot wrap the next cursor. Caller holds the same read snapshot.
     */
    static final class Rows {
        private final Db db;
        private final String table,columns;
        private List<Map<String,Object>> page=List.of();
        private int index;
        private Long after;
        private boolean ended;
        int peakPageRows;
        int pagesRead;
        Rows(Db db,String table,String columns) {this.db=db;this.table=table;this.columns=columns;}
        Map<String,Object> next()throws Db.DbException {
            if(index==page.size()) {
                if(ended)return null;
                page=db.query("SELECT rowid AS evidence_rowid,"+columns+" FROM "+table
                        +(after==null?"":" WHERE rowid>"+Db.lit(after))+" ORDER BY rowid LIMIT "+PAGE_SIZE+";");
                index=0;pagesRead++;peakPageRows=Math.max(peakPageRows,page.size());
                if(page.size()>PAGE_SIZE)throw new IllegalArgumentException("unbounded-evidence-page");
                if(page.isEmpty()){ended=true;return null;}
                ended=page.size()<PAGE_SIZE;
            }
            Map<String,Object> row=page.get(index++);
            if(!(row.get("evidence_rowid") instanceof Long id) || (after!=null && id<=after))
                throw new IllegalArgumentException("invalid-evidence-rowid");
            after=id;
            return row;
        }
    }

    /** Caller owns a single read transaction spanning this and subsequent review reads. */
    static Map<String,Object> guard(Db db,String since,String until,String currentTime) {
        double start,end,present;
        try {
            start=time(since);end=time(until);present=time(currentTime);
            if(start>=end || end>present) return refused(since,until,null,"invalid-window");
        } catch(RuntimeException e) {return refused(since,until,null,"invalid-window");}
        try {
            if(!versions(db,"schema_version",Watch.SCHEMA_VERSION)) return refused(since,until,null,"unsupported-schema");
            List<String> tables=new ArrayList<>();for(var row:db.query("SELECT name FROM sqlite_master WHERE type='table';"))tables.add(Db.asStr(row.get("name")));
            if(!tables.containsAll(List.of("heartbeat_schema","collector_heartbeats","coverage_metadata")))
                return refused(since,until,null,"missing-heartbeat-schema");
            if(!versions(db,"heartbeat_schema",VERSION))return refused(since,until,null,"unsupported-heartbeat-schema");
            var metadata=db.query("SELECT key,value FROM coverage_metadata LIMIT 2;");
            if(metadata.size()>1)return refused(since,until,null,"malformed-metadata");
            for(var row:metadata) {
                double floor;
                try {floor=time(row.get("value"));}
                catch(RuntimeException e) {return refused(since,until,null,"malformed-metadata");}
                if(!"event_floor".equals(row.get("key")) || floor>present)return refused(since,until,null,"malformed-metadata");
                if(start<floor)return refused(since,until,null,"events-expired");
            }
            Map<String,List<Pulse>> grouped=new LinkedHashMap<>();for(String key:COLLECTORS)grouped.put(key,new ArrayList<>());
            Map<String,Pulse> anchors=new LinkedHashMap<>();
            Rows heartbeats=new Rows(db,"collector_heartbeats","version,collector,time,observed_count,status,error,cadence_seconds");
            for(Map<String,Object> row;(row=heartbeats.next())!=null;) {
                if(!(row.get("version") instanceof Long version) || version!=VERSION)return refused(since,until,null,"unsupported-heartbeat-version");
                Object rawKey=row.get("collector");if(!(rawKey instanceof String key) || !grouped.containsKey(key))return refused(since,until,null,"unknown-collector");
                double at;
                try {at=time(row.get("time"));}catch(RuntimeException e){return refused(since,until,key,"malformed-heartbeat");}
                Object count=row.get("observed_count"),rawCadence=row.get("cadence_seconds"),error=row.get("error"),status=row.get("status");
                if(!(rawCadence instanceof Number number))return refused(since,until,key,"malformed-heartbeat");
                double cadence=number.doubleValue();
                boolean ok="ok".equals(status),degraded="degraded".equals(status);
                if(at>present || !Double.isFinite(cadence) || cadence<0.5 || cadence>3600 || (!ok && !degraded)
                        || (ok && (!(count instanceof Long n) || n<0 || error!=null))
                        || (degraded && (count!=null || !(error instanceof String s) || !s.matches("[a-z][a-z0-9-]{0,63}"))))
                    return refused(since,until,key,"malformed-heartbeat");
                Pulse pulse=new Pulse((Long)row.get("evidence_rowid"),at,(String)status,(String)error,Math.max(5,2*cadence+2));
                if(at<start) {
                    Pulse prior=anchors.get(key);
                    if(prior==null || CHRONOLOGICAL.compare(prior,pulse)<0)anchors.put(key,pulse);
                } else if(at<=end)grouped.get(key).add(pulse);
            }
            List<Map<String,Object>> issues=new ArrayList<>();
            for(String key:COLLECTORS) {
                List<Pulse> inside=grouped.get(key);inside.sort(CHRONOLOGICAL);
                Pulse anchor=anchors.get(key);
                if(inside.isEmpty()){issues.add(issue(key,"missing-heartbeat"));continue;}
                Pulse first=inside.getFirst();
                if(first.at()==start)anchor=null;
                if(anchor==null) {if(first.at()!=start)issues.add(issue(key,"start-silence"));}
                else if(!anchor.status().equals("ok") || start-anchor.at()>anchor.grace())issues.add(issue(key,"start-silence"));
                TreeSet<String> errors=new TreeSet<>();for(Pulse row:inside)if(!row.status().equals("ok"))errors.add(row.error());
                for(String error:errors)issues.add(issue(key,error));
                List<Pulse> chain=new ArrayList<>();if(anchor!=null)chain.add(anchor);chain.addAll(inside);
                boolean gap=false;for(int i=1;i<chain.size();i++)if(chain.get(i).at()-chain.get(i-1).at()>Math.min(chain.get(i).grace(),chain.get(i-1).grace()))gap=true;
                if(gap)issues.add(issue(key,"heartbeat-gap"));
                if(end-inside.getLast().at()>inside.getLast().grace())issues.add(issue(key,"end-silence"));
            }
            long count=0;
            Rows events=new Rows(db,"events","time,kind,message");
            for(Map<String,Object> row;(row=events.next())!=null;) {
                double at;
                try {at=time(row.get("time"));}catch(RuntimeException e){return refused(since,until,null,"malformed-event");}
                if(at>present || !(row.get("kind") instanceof String kind) || kind.isEmpty() || !(row.get("message") instanceof String))
                    return refused(since,until,null,"malformed-event");
                if(start<=at && at<=end)count++;
            }
            return result(since,until,issues,issues.isEmpty()?count:null);
        } catch(Db.DbException | Db.Fatal | IllegalArgumentException e) {return refused(since,until,null,"database-read");}
    }
    static Map<String,Object> review(String path,String since,String until,String currentTime) {
        // A readonly open never creates a missing DB. No Watch constructor or migration.
        try {
            Path file=Path.of(path);
            if(!Files.exists(file))return refused(since,until,null,"no-database");
            Object before=Files.readAttributes(file,java.nio.file.attribute.BasicFileAttributes.class).fileKey();
            if(before==null)return refused(since,until,null,"database-read");
            try(Db db=Db.open(path,true)) {
                db.exec("PRAGMA query_only=ON;\nBEGIN;");
                Map<String,Object> result=guard(db,since,until,currentTime);
                Object after=Files.readAttributes(file,java.nio.file.attribute.BasicFileAttributes.class).fileKey();
                if(!before.equals(after))return refused(since,until,null,"database-replaced");
                return result;
            }
        } catch(java.io.IOException | Db.DbException | Db.Fatal | IllegalArgumentException e) {return refused(since,until,null,"database-read");}
    }
}
