"""Impossible-travel detection over Entra ID sign-in logs (Microsoft Graph).

Pulls recent sign-ins via Graph (or reads an exported JSON for offline runs),
computes the implied speed between consecutive sign-ins per user, and flags
pairs exceeding a plausible travel speed.

Online:  GRAPH_TOKEN=<token> python impossible_travel.py
Offline: python impossible_travel.py --input sample_sign_ins.json
"""
import argparse, json, math, os, pathlib, sys
from datetime import datetime

MAX_PLAUSIBLE_KMH = 900  # roughly airliner cruise speed

def haversine_km(lat1, lon1, lat2, lon2):
    r = 6371.0
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp, dl = math.radians(lat2 - lat1), math.radians(lon2 - lon1)
    a = math.sin(dp/2)**2 + math.cos(p1)*math.cos(p2)*math.sin(dl/2)**2
    return 2 * r * math.asin(math.sqrt(a))

def fetch_from_graph():
    import urllib.request
    token = os.environ["GRAPH_TOKEN"]
    url = ("https://graph.microsoft.com/v1.0/auditLogs/signIns"
           "?$top=500&$orderby=createdDateTime desc")
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
    with urllib.request.urlopen(req) as resp:
        return json.load(resp)["value"]

def normalize(signins):
    out = []
    for s in signins:
        loc = s.get("location") or {}
        geo = loc.get("geoCoordinates") or {}
        if geo.get("latitude") is None:
            continue
        out.append({
            "user": s.get("userPrincipalName", "unknown"),
            "time": datetime.fromisoformat(s["createdDateTime"].replace("Z", "+00:00")),
            "lat": geo["latitude"], "lon": geo["longitude"],
            "city": loc.get("city", "?"), "country": loc.get("countryOrRegion", "?"),
        })
    return out

def detect(events):
    findings = []
    by_user = {}
    for e in sorted(events, key=lambda x: (x["user"], x["time"])):
        prev = by_user.get(e["user"])
        if prev:
            km = haversine_km(prev["lat"], prev["lon"], e["lat"], e["lon"])
            hours = max((e["time"] - prev["time"]).total_seconds() / 3600, 1e-6)
            speed = km / hours
            if km > 100 and speed > MAX_PLAUSIBLE_KMH:
                findings.append({
                    "control": "AC-2(12)", "type": "impossible_travel",
                    "user": e["user"],
                    "from": f"{prev['city']}, {prev['country']}",
                    "to": f"{e['city']}, {e['country']}",
                    "km": round(km), "hours": round(hours, 2),
                    "implied_kmh": round(speed),
                })
        by_user[e["user"]] = e
    return findings

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", help="offline sign-in export (JSON)")
    ap.add_argument("--out", default=str(pathlib.Path(__file__).parents[1] / "reports" / "impossible_travel.json"))
    args = ap.parse_args()

    raw = (json.loads(pathlib.Path(args.input).read_text())
           if args.input else fetch_from_graph())
    findings = detect(normalize(raw))
    pathlib.Path(args.out).write_text(json.dumps(findings, indent=2, default=str))
    for f in findings:
        print(f"FLAG {f['user']}: {f['from']} -> {f['to']} "
              f"({f['km']} km in {f['hours']} h = {f['implied_kmh']} km/h)")
    print(f"\n{len(findings)} finding(s) -> {args.out}")
    return 0

if __name__ == "__main__":
    sys.exit(main())
