import sqlite3
import os
import json
from pathlib import Path
from typing import Dict, List

DB = Path("layer1_mapper.db")

# -------------------------------
# 1️⃣ Database Initialization
# -------------------------------
def init_db():
    con = sqlite3.connect(DB)
    con.executescript("""
    CREATE TABLE IF NOT EXISTS entities (
        entity_id TEXT PRIMARY KEY,
        confidence REAL,
        fragment_count INTEGER DEFAULT 0,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS fragments (
        frag_id INTEGER PRIMARY KEY AUTOINCREMENT,
        entity_id TEXT,
        frag_type TEXT,
        value TEXT,
        source TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS erasures (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        entity_id TEXT,
        requested_by TEXT,
        reason TEXT,
        timestamp TEXT DEFAULT CURRENT_TIMESTAMP
    );
    """)
    con.close()

# -------------------------------
# 2️⃣ Save Mapping (from Layer 1)
# -------------------------------
def save_mapping(mapping: Dict, fragments: List[Dict]):
    con = sqlite3.connect(DB)
    cur = con.cursor()
    
    for i, f in enumerate(fragments):
        eid = mapping.get(i, {}).get("entity_id")
        if not eid:
            continue
        cur.execute(
            "INSERT OR IGNORE INTO entities (entity_id, confidence, fragment_count) VALUES (?,?,0)",
            (eid, mapping.get(i, {}).get("confidence", 0.9))
        )
        cur.execute(
            "INSERT INTO fragments (entity_id, frag_type, value, source) VALUES (?,?,?,?)",
            (eid, f.get("type"), f.get("value"), f.get("source"))
        )

    # Update fragment counts
    cur.execute("""
        UPDATE entities 
        SET fragment_count = (
            SELECT COUNT(*) FROM fragments WHERE fragments.entity_id = entities.entity_id
        )
    """)
    
    con.commit()
    con.close()

# -------------------------------
# 3️⃣ Get One Entity
# -------------------------------
def get_entity(eid: str):
    con = sqlite3.connect(DB)
    con.row_factory = sqlite3.Row
    cur = con.cursor()
    
    cur.execute("SELECT * FROM entities WHERE entity_id=?", (eid,))
    entity = cur.fetchone()
    
    if not entity:
        con.close()
        return None

    cur.execute("SELECT frag_type, value, source FROM fragments WHERE entity_id=?", (eid,))
    fragments = [dict(row) for row in cur.fetchall()]
    con.close()

    return {
        "entity": dict(entity),
        "fragments": fragments
    }

# -------------------------------
# 4️⃣ Erase Entity (GDPR)
# -------------------------------
def erase_entity(eid: str, requested_by="system", reason="GDPR Erasure"):
    con = sqlite3.connect(DB)
    cur = con.cursor()
    cur.execute("DELETE FROM fragments WHERE entity_id=?", (eid,))
    cur.execute("DELETE FROM entities WHERE entity_id=?", (eid,))
    cur.execute(
        "INSERT INTO erasures (entity_id, requested_by, reason) VALUES (?,?,?)",
        (eid, requested_by, reason)
    )
    con.commit()
    con.close()
    return True

# -------------------------------
# 5️⃣ Search Entities
# -------------------------------
def search_entities(query: str):
    con = sqlite3.connect(DB)
    cur = con.cursor()
    q = f"%{query}%"
    cur.execute("""
        SELECT DISTINCT e.entity_id, e.confidence, e.fragment_count, e.created_at
        FROM entities e
        JOIN fragments f ON e.entity_id = f.entity_id
        WHERE f.value LIKE ? OR f.source LIKE ?
        ORDER BY e.created_at DESC
        LIMIT 50
    """, (q, q))
    res = cur.fetchall()
    con.close()
    return [{"entity_id": r[0], "confidence": r[1], "fragment_count": r[2], "created_at": r[3]} for r in res]

# -------------------------------
# 6️⃣ List Entities (for Dashboard)
# -------------------------------
def list_entities(limit=20):
    con = sqlite3.connect(DB)
    cur = con.cursor()
    cur.execute("""
        SELECT entity_id, confidence, fragment_count, created_at 
        FROM entities
        ORDER BY created_at DESC
        LIMIT ?
    """, (limit,))
    res = cur.fetchall()
    con.close()
    return [{"entity_id": r[0], "confidence": r[1], "fragment_count": r[2], "created_at": r[3]} for r in res]

# -------------------------------
# 7️⃣ Get Statistics
# -------------------------------
def get_statistics():
    con = sqlite3.connect(DB)
    cur = con.cursor()
    
    cur.execute("SELECT COUNT(*) FROM entities")
    total_entities = cur.fetchone()[0]
    
    cur.execute("SELECT COUNT(*) FROM fragments")
    total_fragments = cur.fetchone()[0]
    
    cur.execute("SELECT AVG(fragment_count) FROM entities")
    avg_fragments = cur.fetchone()[0] or 0
    
    cur.execute("SELECT COUNT(*) FROM erasures")
    erasures_done = cur.fetchone()[0]
    
    con.close()
    return {
        "total_entities": total_entities,
        "total_fragments": total_fragments,
        "avg_fragments_per_entity": round(avg_fragments, 2),
        "erasures_performed": erasures_done
    }

# -------------------------------
# 8️⃣ Export Golden Records
# -------------------------------
def get_all_entities():
    con = sqlite3.connect(DB)
    con.row_factory = sqlite3.Row
    cur = con.cursor()
    cur.execute("""
        SELECT e.entity_id, e.confidence, e.created_at, f.frag_type, f.value, f.source
        FROM entities e
        LEFT JOIN fragments f ON e.entity_id = f.entity_id
        ORDER BY e.entity_id
    """)
    rows = cur.fetchall()
    con.close()
    
    records = {}
    for r in rows:
        eid = r["entity_id"]
        if eid not in records:
            records[eid] = {
                "entity_id": eid,
                "confidence": r["confidence"],
                "created_at": r["created_at"],
                "fragments": []
            }
        if r["frag_type"]:
            records[eid]["fragments"].append({
                "type": r["frag_type"],
                "value": r["value"],
                "source": r["source"]
            })
    return list(records.values())

def export_golden_records(path="outputs/golden_records.json"):
    os.makedirs("outputs", exist_ok=True)
    records = get_all_entities()
    with open(path, "w", encoding="utf-8") as f:
        json.dump(records, f, indent=2)
    return path
