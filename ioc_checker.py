import os
import json
import argparse
from dotenv import load_dotenv
from rich.console import Console
from rich.table import Table

from utils.ioc_detect import detect_ioc_type
from utils.normalize import vt_url_id
from utils.defang import defang_ioc
from utils.cache import Cache
from utils.scoring import score_from_vt

from providers.virustotal import VirusTotalClient
from reports.pdf_report import export_pdf

console = Console()

def read_iocs_from_file(path: str) -> list[str]:
    iocs = []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            iocs.append(s)
    return iocs

def render_table(results: list[dict]):
    t = Table(title="IOC Reputation Results (VirusTotal)")
    t.add_column("IOC")
    t.add_column("Type")
    t.add_column("Verdict")
    t.add_column("Score")
    t.add_column("VT malicious")
    t.add_column("VT suspicious")

    for r in results:
        vt = r.get("virustotal", {}).get("stats") or {}
        t.add_row(
            r.get("ioc_defanged", r["ioc"]),
            r.get("type", ""),
            r["verdict"]["verdict"],
            str(r["verdict"]["score"]),
            str(vt.get("malicious", "")),
            str(vt.get("suspicious", "")),
        )

    console.print(t)

def main():
    load_dotenv()

    parser = argparse.ArgumentParser(description="IOC Validator & Reputation Checker (VirusTotal only)")
    parser.add_argument("--ioc", help="Single IOC to check")
    parser.add_argument("--infile", help="File with IOCs (one per line)")
    parser.add_argument("--cache-ttl", type=int, default=86400, help="Cache TTL seconds (default 1 day)")
    parser.add_argument("--out-json", default="ioc_report.json", help="Output JSON path")
    parser.add_argument("--no-pdf", action="store_true", help="Disable PDF export")
    parser.add_argument("--out-pdf", default="ioc_report.pdf", help="Output PDF path")
    args = parser.parse_args()

    vt_key = (os.getenv("VT_API_KEY") or "").strip()
    if not vt_key:
        console.print("[red]Missing VT_API_KEY in .env[/red]")
        return

    vt = VirusTotalClient(vt_key)
    cache = Cache("ioc_cache.db")

    # Get IOCs
    if args.ioc:
        iocs = [args.ioc.strip()]
    elif args.infile:
        iocs = read_iocs_from_file(args.infile)
    else:
        user_ioc = input("Enter IOC: ").strip()
        if not user_ioc:
            return
        iocs = [user_ioc]

    results = []

    for ioc in iocs:
        ioc_type = detect_ioc_type(ioc)
        entry = {
            "ioc": ioc,
            "ioc_defanged": defang_ioc(ioc),
            "type": ioc_type,
            "virustotal": {},
        }

        try:
            # Cache lookup
            cached = cache.get(ioc, "virustotal", ttl_seconds=args.cache_ttl)
            if cached:
                vt_stats = cached.get("stats")
                entry["virustotal"] = cached
            else:
                # VT fetch
                if ioc_type == "ip":
                    data = vt.lookup_ip(ioc)
                elif ioc_type == "domain":
                    data = vt.lookup_domain(ioc)
                elif ioc_type == "url":
                    data = vt.lookup_url(vt_url_id(ioc))
                elif ioc_type in ("md5", "sha1", "sha256"):
                    data = vt.lookup_hash(ioc)
                else:
                    entry["error"] = "Unknown IOC format"
                    entry["verdict"] = {"score": 0, "verdict": "unknown"}
                    results.append(entry)
                    continue

                vt_stats = data["data"]["attributes"].get("last_analysis_stats", {})
                entry["virustotal"] = {"stats": vt_stats}
                cache.set(ioc, "virustotal", entry["virustotal"])

            entry["verdict"] = score_from_vt(vt_stats)

        except Exception as e:
            entry["error"] = str(e)
            entry["verdict"] = {"score": 0, "verdict": "error"}

        results.append(entry)

    render_table(results)

    # Export JSON
    with open(args.out_json, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
    console.print(f"[green]Saved JSON -> {args.out_json}[/green]")

    # Optional PDF
    if not args.no_pdf:
        export_pdf(results, args.out_pdf)
        console.print(f"[green]Saved PDF  -> {args.out_pdf}[/green]")

    console.print("[cyan]Cache DB -> ioc_cache.db[/cyan]")

if __name__ == "__main__":
    main()
