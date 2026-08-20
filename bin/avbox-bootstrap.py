#!/usr/bin/env python3
import argparse, datetime, hashlib, json, os, shutil, socket, ssl, subprocess, sys, urllib.error, urllib.parse, urllib.request
from pathlib import Path

ROOT = Path(os.environ.get("AVBOX_BOOTSTRAP_ROOT", "/srv/avbox-bootstrap"))
DEFAULT_MANIFEST = Path("/etc/avbox-bootstrap/acquisition.yaml")
TYPES = {"installer", "removal-tool", "definitions", "scanner-engine", "documentation", "update-package", "service-pack", "patch", "rescue-media", "other"}
TYPE_ALIASES = {"installers":"installer", "tools":"removal-tool"}
TYPE_DIRS = {"installer":"installers", "removal-tool":"tools", "definitions":"definitions", "documentation":"documentation"}
RISKS = {"stable", "legacy", "mutable", "fragile", "dead"}

def utcnow(): return datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")
def append(path, obj):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(obj, sort_keys=True) + "\n"); f.flush(); os.fsync(f.fileno())
def read_jsonl(path):
    if not path.exists(): return []
    return [json.loads(x) for x in path.read_text(encoding="utf-8").splitlines() if x.strip()]
def events(): return read_jsonl(ROOT / "logs/acquisitions.jsonl")
def integrity_events(): return read_jsonl(ROOT / "logs/integrity.jsonl")
def failure_events(): return read_jsonl(ROOT / "logs/failures.jsonl")
def load_manifest(path):
    with open(path, encoding="utf-8") as f: data = json.load(f)
    if data.get("schema") not in (1, 2) or not isinstance(data.get("artifacts"), list): raise ValueError("unsupported manifest")
    return data
def normalize(a):
    a = dict(a); old_type = a.get("artifact_type", a.get("type"))
    a["artifact_type"] = TYPE_ALIASES.get(old_type, old_type)
    a["product_version"] = a.get("product_version", a.get("version"))
    for k in ("scanner_engine_version", "definition_version", "definition_date", "platform", "architecture", "compatibility_status", "source_type", "rights_provenance_status", "source_risk"): a.setdefault(k, None)
    a.setdefault("relationships", [])
    a.setdefault("redistribution_rights", "unknown")
    return a
def manifest_index(path=DEFAULT_MANIFEST):
    try: return {a["id"]: normalize(a) for a in load_manifest(path)["artifacts"]}
    except FileNotFoundError: return {}
def latest_integrity():
    out = {}
    for e in integrity_events(): out[e["sha256"]] = e
    return out
def hashes(path):
    hs = {n: hashlib.new(n) for n in ("sha256", "sha1", "md5")}
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            for h in hs.values(): h.update(chunk)
    out = {n: h.hexdigest() for n, h in hs.items()}; b3sum = shutil.which("b3sum")
    if b3sum:
        out["blake3"] = subprocess.run([b3sum, "--no-names", str(path)], check=True, capture_output=True, text=True).stdout.strip().split()[0]
    else:
        try:
            import blake3
            b3 = blake3.blake3()
            with path.open("rb") as f:
                for chunk in iter(lambda: f.read(1024 * 1024), b""): b3.update(chunk)
            out["blake3"] = b3.hexdigest()
        except ImportError: out["blake3"] = None
    return out
def dns_evidence(url):
    host = urllib.parse.urlparse(url).hostname; result = {"hostname":host,"addresses":[],"error":None}
    if not host: return result
    try: result["addresses"] = sorted({x[4][0] for x in socket.getaddrinfo(host, None)})
    except OSError as e: result["error"] = repr(e)
    return result
def failure_record(a, started, exc, redirects, incoming=None, response=None):
    reason = getattr(exc, "reason", None); tls_error = repr(reason or exc) if isinstance(exc, ssl.SSLError) or isinstance(reason, ssl.SSLError) else None
    is_https = urllib.parse.urlparse(a.get("url", "")).scheme.casefold() == "https"
    tls_result = "failed" if tls_error else ("validated-before-http-response" if is_https and isinstance(exc,urllib.error.HTTPError) else "not-observed" if is_https else "not-applicable")
    return {"schema":2,"artifact_id":a.get("id"),"requested_url":a.get("url"),"source_url":a.get("url"),"timestamp_utc":utcnow(),"attempt_started_utc":started,"dns":dns_evidence(a.get("url", "")),"tls":{"applicable":is_https,"certificate_validation_enforced":True if is_https else None,"result":tls_result,"error":tls_error},"http_status":(response or {}).get("status", exc.code if isinstance(exc,urllib.error.HTTPError) else None),"http":response,"redirect_chain":(response or {}).get("redirect_chain", redirects),"error":repr(exc),"partial_bytes":incoming.stat().st_size if incoming and incoming.exists() else 0,"source_risk":a.get("source_risk")}
class Redirects(urllib.request.HTTPRedirectHandler):
    def __init__(self): self.chain = []
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        self.chain.append({"status":code,"from":req.full_url,"to":newurl,"headers":dict(headers.items())})
        return super().redirect_request(req,fp,code,msg,headers,newurl)
def artifact_dir(kind): return TYPE_DIRS.get(kind, kind)
def acquire_one(raw):
    a=normalize(raw); kind=a["artifact_type"]
    if kind not in TYPES: raise ValueError(f"invalid artifact type: {kind}")
    if a.get("source_risk") not in RISKS: raise ValueError("invalid source_risk")
    name=Path(a["filename"]).name
    if name != a["filename"]: raise ValueError("filename must be a basename")
    incoming=ROOT/"incoming"/(a["id"]+".part"); incoming.parent.mkdir(parents=True,exist_ok=True); offset=incoming.stat().st_size if incoming.exists() else 0
    headers={"User-Agent":"avbox-bootstrap-preservation/2.0"}
    if offset: headers["Range"]=f"bytes={offset}-"
    redirects=Redirects(); opener=urllib.request.build_opener(redirects); started=utcnow()
    try:
        with opener.open(urllib.request.Request(a["url"],headers=headers),timeout=90) as r:
            status=getattr(r,"status",200); mode="ab" if offset and status==206 else "wb"
            if mode=="wb": offset=0
            with incoming.open(mode) as f:
                while True:
                    chunk=r.read(1024*1024)
                    if not chunk: break
                    f.write(chunk)
                f.flush(); os.fsync(f.fileno())
            response={"status":status,"final_url":r.geturl(),"headers":dict(r.headers.items()),"redirect_chain":redirects.chain,"resumed_from":offset,"certificate_validation_enforced":True}
    except Exception as e:
        append(ROOT/"logs/failures.jsonl",failure_record(a,started,e,redirects.chain,incoming)); print(f"FAILED {a.get('id')}: {e}",file=sys.stderr); return False
    size=incoming.stat().st_size
    content_type=response.get("headers",{}).get("Content-Type","").split(";",1)[0].strip().casefold()
    expected_types=[x.casefold() for x in a.get("expected_content_types",[])]
    validation_errors=[]
    if a.get("expected_min_bytes") is not None and size < int(a["expected_min_bytes"]): validation_errors.append(f"response size {size} below expected minimum {a['expected_min_bytes']}")
    if expected_types and content_type not in expected_types: validation_errors.append(f"unexpected Content-Type {content_type or 'missing'}")
    if validation_errors:
        exc=ValueError("; ".join(validation_errors))
        append(ROOT/"logs/failures.jsonl",failure_record(a,started,exc,redirects.chain,incoming,response))
        print(f"FAILED {a.get('id')}: {exc}",file=sys.stderr); return False
    dig=hashes(incoming); prior_events=events()
    same=next((e for e in prior_events if e.get("hashes",{}).get("sha256")==dig["sha256"] and Path(e.get("stored_path","")).exists()),None)
    source_prior=[e for e in prior_events if e.get("source_url")==a["url"]]; changed=bool(source_prior and all(e.get("hashes",{}).get("sha256")!=dig["sha256"] for e in source_prior))
    if same: stored=Path(same["stored_path"]); incoming.unlink(); duplicate=True
    else:
        dest=ROOT/"artifacts"/artifact_dir(kind)/name; dest.parent.mkdir(parents=True,exist_ok=True)
        if dest.exists(): dest=dest.with_name(f"{dest.stem}.{dig['sha256'][:12]}{dest.suffix}")
        if dest.exists(): raise RuntimeError(f"refusing to overwrite {dest}")
        os.replace(incoming,dest); os.chmod(dest,0o444); stored=dest; duplicate=False
    event={"schema":2,"artifact_id":a["id"],"original_filename":name,"source_url":a["url"],"vendor":a["vendor"],"product":a["product"],"product_version":a.get("product_version"),"scanner_engine_version":a.get("scanner_engine_version"),"definition_version":a.get("definition_version"),"definition_date":a.get("definition_date"),"platform":a.get("platform"),"architecture":a.get("architecture"),"artifact_type":kind,"compatibility_status":a.get("compatibility_status"),"relationships":a.get("relationships",[]),"source_type":a.get("source_type"),"source_risk":a.get("source_risk"),"rights_provenance_status":a.get("rights_provenance_status"),"redistribution_rights":a.get("redistribution_rights","unknown"),"acquisition_started_utc":started,"acquisition_completed_utc":utcnow(),"http":response,"byte_size":size,"hashes":dig,"provenance_notes":a.get("notes",""),"stored_path":str(stored),"duplicate_bytes":duplicate,"upstream_object_changed":changed,"prior_source_sha256":sorted({e.get("hashes",{}).get("sha256") for e in source_prior if e.get("hashes",{}).get("sha256")})}
    append(ROOT/"logs/acquisitions.jsonl",event)
    hp=ROOT/"logs/http"/f"{a['id']}-{dig['sha256'][:12]}-{datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.json"; hp.parent.mkdir(parents=True,exist_ok=True); hp.write_text(json.dumps(response,indent=2,sort_keys=True)+"\n",encoding="utf-8")
    print(f"OK {a['id']} {dig['sha256']} {size} {stored}"+(" (deduplicated)" if duplicate else "")+(" (UPSTREAM CHANGED)" if changed else "")); return True
def acquire(path,refresh_mutable=False,ids=None):
    prior_ids={e.get("artifact_id") for e in events()}; ok=True; selected=[]
    for raw in load_manifest(path)["artifacts"]:
        a=normalize(raw)
        if ids and a.get("id") not in ids: continue
        if a.get("status") in ("wanted","failed"):
            print(f"{a.get('status','').upper()} {a.get('id')} (not attempted)"); continue
        if refresh_mutable:
            if a.get("source_risk")!="mutable": continue
        elif a.get("id") in prior_ids: print(f"SKIP {a.get('id')} (already acquired)"); continue
        selected.append(a)
    for a in selected:
        try: ok=acquire_one(a) and ok
        except Exception as e: append(ROOT/"logs/failures.jsonl",failure_record(a,utcnow(),e,[])); print(f"FAILED {a.get('id')}: {e}",file=sys.stderr); ok=False
    return 0 if ok else 2
def backfill_blake3():
    if not shutil.which("b3sum"):
        try: import blake3
        except ImportError: print("BLAKE3 implementation unavailable",file=sys.stderr); return 2
    known=latest_integrity(); seen=set(); rc=0
    for e in events():
        sha=e.get("hashes",{}).get("sha256"); p=Path(e.get("stored_path",""))
        if not sha or sha in seen: continue
        seen.add(sha)
        if sha in known and known[sha].get("blake3"): print(f"SKIP {sha} already has BLAKE3"); continue
        if not p.is_file(): print(f"FAIL missing {p}",file=sys.stderr); rc=1; continue
        dig=hashes(p)
        if dig["sha256"]!=sha: print(f"FAIL SHA-256 mismatch {p}",file=sys.stderr); rc=1; continue
        append(ROOT/"logs/integrity.jsonl",{"schema":1,"timestamp_utc":utcnow(),"sha256":sha,"blake3":dig["blake3"],"byte_size":p.stat().st_size,"stored_path":str(p),"method":"Debian-packaged b3sum" if shutil.which("b3sum") else "Debian-packaged Python blake3","event_type":"blake3-backfill"}); print(f"OK {sha} {dig['blake3']} {p}")
    return rc
def combined_records(manifest_path=DEFAULT_MANIFEST):
    mi=manifest_index(manifest_path); ii=latest_integrity(); out=[]; seen=set()
    for e in events():
        sha=e.get("hashes",{}).get("sha256")
        if not sha or sha in seen: continue
        seen.add(sha); m=mi.get(e.get("artifact_id"),{}); h=dict(e.get("hashes",{}))
        if ii.get(sha,{}).get("blake3"): h["blake3"]=ii[sha]["blake3"]
        rec={**e,**{k:v for k,v in m.items() if k not in ("url","filename","id","notes")},"hashes":h}; rec["source_hostname"]=urllib.parse.urlparse(e.get("source_url","")).hostname; out.append(rec)
    return out
def verify():
    rc=0
    for e in combined_records():
        p=Path(e["stored_path"]); actual=hashes(p) if p.is_file() else {}; expected=e["hashes"]
        good=p.is_file() and p.stat().st_size==e["byte_size"] and all(actual.get(k)==v for k,v in expected.items() if v)
        print(("OK" if good else "FAIL"),expected.get("sha256"),p)
        if not good: rc=1
    return rc
def inventory(args):
    rows=[]
    for e in combined_records():
        if args.vendor and e.get("vendor","").casefold()!=args.vendor.casefold(): continue
        platforms=e.get("platform") or []
        if isinstance(platforms,str): platforms=[platforms]
        if args.platform and args.platform not in platforms: continue
        if args.type and e.get("artifact_type")!=args.type: continue
        if args.risk and e.get("source_risk")!=args.risk: continue
        rows.append({"vendor":e.get("vendor"),"product":e.get("product"),"version":e.get("product_version"),"platform":e.get("platform"),"artifact_type":e.get("artifact_type"),"byte_size":e.get("byte_size"),"sha256":e.get("hashes",{}).get("sha256"),"blake3":e.get("hashes",{}).get("blake3"),"acquisition_date":e.get("acquisition_completed_utc"),"source_risk":e.get("source_risk"),"source_hostname":e.get("source_hostname"),"source_url":e.get("source_url"),"stored_path":e.get("stored_path")})
    if args.json: print(json.dumps(rows,indent=2,sort_keys=True)); return
    fields=("vendor","product","version","platform","artifact_type","byte_size","sha256","blake3","acquisition_date","source_risk","source_hostname"); print("\t".join(fields))
    for r in rows:
        values=[]
        for field in fields:
            value=r.get(field)
            if isinstance(value,list): value=",".join(str(item) for item in value)
            values.append(str(value or "unknown"))
        print("\t".join(values))
def export(dest):
    dest=Path(dest)
    if dest.exists(): raise RuntimeError(f"refusing to overwrite {dest}")
    dest.mkdir(parents=True)
    for rel in ("artifacts","manifests","logs"):
        if (ROOT/rel).exists(): shutil.copytree(ROOT/rel,dest/rel,copy_function=shutil.copy2)
    catalog={"schema":1,"generated_utc":utcnow(),"purpose":"RAB preservation ingest staging","redistribution_notice":"Public download availability does not establish redistribution rights.","artifacts":combined_records(),"failed_sources":failure_events()}
    (dest/"rab-catalog.json").write_text(json.dumps(catalog,indent=2,sort_keys=True)+"\n",encoding="utf-8")
    lines=[]
    for p in sorted((dest/"artifacts").rglob("*")):
        if p.is_file(): lines.append(f"{hashes(p)['sha256']}  {p.relative_to(dest)}")
    (dest/"SHA256SUMS").write_text("\n".join(lines)+"\n",encoding="utf-8")
    for p in dest.rglob("*"):
        if p.is_file(): os.chmod(p,0o444)
def verify_export(dest):
    dest=Path(dest); catalog_path=dest/"rab-catalog.json"
    if not catalog_path.is_file(): print(f"FAIL missing {catalog_path}",file=sys.stderr); return 1
    catalog=json.loads(catalog_path.read_text(encoding="utf-8")); rc=0; seen=set()
    for record in catalog.get("artifacts",[]):
        sha=record.get("hashes",{}).get("sha256")
        if not sha or sha in seen: continue
        seen.add(sha); source=Path(record["stored_path"]); rel=source.relative_to(ROOT); exported=dest/rel
        actual=hashes(exported) if exported.is_file() else {}
        expected=record.get("hashes",{})
        good=exported.is_file() and exported.stat().st_size==record.get("byte_size") and all(actual.get(k)==v for k,v in expected.items() if v)
        print(("OK" if good else "FAIL"),sha,exported)
        if not good: rc=1
    required=(dest/"logs/acquisitions.jsonl",dest/"logs/failures.jsonl",dest/"manifests/acquisition.yaml",dest/"SHA256SUMS")
    for path in required:
        if not path.is_file(): print(f"FAIL missing export metadata {path}",file=sys.stderr); rc=1
    return rc
def main():
    p=argparse.ArgumentParser(); sub=p.add_subparsers(dest="cmd",required=True)
    a=sub.add_parser("acquire"); a.add_argument("manifest",nargs="?",default=str(DEFAULT_MANIFEST)); a.add_argument("--refresh-mutable",action="store_true"); a.add_argument("--id",action="append",dest="ids")
    sub.add_parser("verify"); sub.add_parser("backfill-blake3")
    i=sub.add_parser("inventory"); i.add_argument("--vendor"); i.add_argument("--platform"); i.add_argument("--type",choices=sorted(TYPES)); i.add_argument("--risk",choices=sorted(RISKS)); i.add_argument("--json",action="store_true")
    x=sub.add_parser("export-for-rab"); x.add_argument("destination")
    xv=sub.add_parser("verify-rab-export"); xv.add_argument("destination")
    n=p.parse_args()
    if n.cmd=="acquire": return acquire(Path(n.manifest),n.refresh_mutable,n.ids)
    if n.cmd=="verify": return verify()
    if n.cmd=="backfill-blake3": return backfill_blake3()
    if n.cmd=="inventory": inventory(n); return 0
    if n.cmd=="verify-rab-export": return verify_export(n.destination)
    export(n.destination); return 0
if __name__=="__main__": raise SystemExit(main())
