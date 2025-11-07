import pandas as pd
import uuid
from difflib import SequenceMatcher

def cluster_fragments(fragments, score_threshold=0.85):
    """
    Performs simple probabilistic clustering (fuzzy linking)
    based on name/email similarity.
    Returns: mapping (dict), df_prepared (DataFrame)
    """

    # Convert fragments to DataFrame
    df = pd.DataFrame(fragments)
    df["entity_id"] = None
    df["score"] = 0.0

    if "value" not in df.columns:
        return {}, df

    mapping = {}
    entity_counter = 0

    for i, row in df.iterrows():
        val = str(row.get("value", "")).lower()
        assigned = False

        for eid, group in mapping.items():
            existing_vals = [v["value"].lower() for v in group["members"]]
            similarity = max([SequenceMatcher(None, val, ev).ratio() for ev in existing_vals] or [0])
            if similarity >= score_threshold:
                df.at[i, "entity_id"] = eid
                df.at[i, "score"] = similarity
                group["members"].append(row.to_dict())
                assigned = True
                break

        if not assigned:
            eid = f"E-{entity_counter+1:06d}"
            df.at[i, "entity_id"] = eid
            df.at[i, "score"] = 1.0
            mapping[eid] = {
                "entity_id": eid,
                "members": [row.to_dict()]
            }
            entity_counter += 1

    return mapping, df


def get_cluster_summary(mapping, df):
    """
    Generate a human-readable summary of all entities.
    """
    summary = []

    # Ensure entity_id column exists
    if "entity_id" not in df.columns:
        df["entity_id"] = None

    for eid in mapping.keys():
        subset = df[df["entity_id"] == eid]
        if subset.empty:
            continue

        names = ", ".join(subset.loc[subset["type"] == "PERSON", "value"].unique()[:3]) or None
        emails = ", ".join(subset.loc[subset["type"] == "EMAIL_ADDRESS", "value"].unique()[:3]) or None
        avg_conf = round(subset["score"].mean(), 2) if "score" in subset else 0.9

        summary.append({
            "entity_id": eid,
            "fragment_count": len(subset),
            "names": names,
            "emails": emails,
            "avg_confidence": avg_conf
        })

    return pd.DataFrame(summary)
