def handle(method, path, headers, body, state):
    db.exec("CREATE TABLE IF NOT EXISTS visits (id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT)")
    if method == "POST":
        note = str((body or {}).get("note") or "ping")[:120]
        db.exec("INSERT INTO visits (ts) VALUES (?)", [note])
    rows = db.query("SELECT id, ts FROM visits ORDER BY id DESC LIMIT 10")["rows"]
    return {"status": 200, "body": {"visits": rows, "count": len(rows)}}
