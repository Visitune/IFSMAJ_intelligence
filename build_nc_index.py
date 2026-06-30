"""
build_nc_index.py — Génère nc_index.json pour NC_ANALYZER.html
Usage: python build_nc_index.py
Lit: "LOCKEDIFS - version OR (1).csv"
Écrit: nc_index.json
"""

import csv
import json
import re
import math
import os
from collections import defaultdict

# ─── CONFIG ────────────────────────────────────────────────────────────────
CSV_FILE = "LOCKEDIFS - version OR (1).csv"
OUTPUT_FILE = "nc_index.json"
META_FILE = "nc_index_meta.json"
MIN_LOCK_REASON_LEN = 30
SUMMARY_LEN = 500

# ─── SEVERITY KEYWORDS (FR + EN) ───────────────────────────────────────────
SEVERITY_KEYWORDS = {
    # Weight 2.0 — CCP / Points critiques
    "ccp": 2.0, "point critique": 2.0, "critical control point": 2.0,
    "critical control": 2.0, "points de contrôle critiques": 2.0,
    # Weight 1.9 — Traçabilité
    "traçabilité": 1.9, "traceability": 1.9, "tracabilite": 1.9,
    "traçabilite": 1.9, "tracabilité": 1.9,
    # Weight 1.8 — HACCP
    "haccp": 1.8, "analyse de risque": 1.8, "hazard analysis": 1.8,
    "plan haccp": 1.8, "analyse des dangers": 1.8,
    # Weight 1.5 — Contamination / Sécurité alimentaire
    "contamination": 1.5, "sécurité alimentaire": 1.5, "food safety": 1.5,
    "contamination croisée": 1.5, "cross contamination": 1.5,
    "cross-contamination": 1.5, "contamination croisee": 1.5,
    # Weight 1.4 — Allergènes
    "allergène": 1.4, "allergen": 1.4, "allergenes": 1.4, "allergens": 1.4,
    # Weight 1.3 — Santé / Risque
    "risque santé": 1.3, "health risk": 1.3, "food poisoning": 1.3,
    "intoxication": 1.3, "toxi-infection": 1.3, "tiac": 1.3,
    # Weight 1.2 — Conscience / Responsabilité
    "not aware": 1.2, "pas au courant": 1.2, "no knowledge": 1.2,
    "responsibilities": 1.2, "responsabilités": 1.2,
    # Weight 1.1 — Corps étrangers / Pathogènes
    "corps étrangers": 1.1, "foreign matter": 1.1, "foreign body": 1.1,
    "listeria": 1.1, "salmonella": 1.1, "salmonelle": 1.1,
    "pathogène": 1.1, "pathogen": 1.1,
    # Weight 1.0 — NC Majeure
    "majeure": 1.0, "major": 1.0, "major non-conformity": 1.0,
    "non-conformité majeure": 1.0,
    # Weight 0.9 — Fraude alimentaire
    "fraude": 0.9, "fraud": 0.9, "falsification": 0.9,
    "food fraud": 0.9, "adultération": 0.9, "adulteration": 0.9,
    # Weight 0.8 — Documentation / Enregistrements
    "non documenté": 0.8, "not documented": 0.8, "non disponible": 0.8,
    "not available": 0.8, "no records": 0.8, "pas d'enregistrement": 0.8,
    "enregistrements manquants": 0.8,
    # Weight 0.7 — Hygiène
    "hygiène": 0.7, "hygiene": 0.7, "nettoyage": 0.7, "cleaning": 0.7,
    "désinfection": 0.7, "disinfection": 0.7,
    # Weight 0.6 — Nuisibles / Environnement
    "nuisibles": 0.6, "pest": 0.6, "rodent": 0.6, "rongeur": 0.6,
    "insecte": 0.6, "insect": 0.6,
    # Weight 0.5 — Surveillance
    "surveillance": 0.5, "monitoring": 0.5, "contrôle": 0.5, "control": 0.5,
}

# ─── KNOWN IFS KO REQUIREMENTS ─────────────────────────────────────────────
KO_REQUIREMENTS = {
    "1.2.1", "2.3.9.1", "3.2.2", "4.1.3", "4.2.1.3",
    "4.12.1", "4.18.1", "5.1.1", "5.9.1", "5.11.3"
}

# IFS chapter prefixes and max section numbers for validation
VALID_PREFIXES = {"1", "2", "3", "4", "5"}
CLAUSE_RX = re.compile(r'(?<![.\d])(\d{1,2}\.\d{1,2}(?:\.\d{1,2})?)(?![.\d])')

# ─── HELPERS ───────────────────────────────────────────────────────────────

def is_valid_ifs_clause(clause_str):
    """Filtre les faux positifs (dates, numéros de série...)"""
    parts = clause_str.split(".")
    if parts[0] not in VALID_PREFIXES:
        return False
    try:
        if int(parts[1]) > 21:
            return False
        if len(parts) >= 3 and int(parts[2]) > 15:
            return False
    except ValueError:
        return False
    # Reject date-like patterns (DD.MM.YY): first segment > 12 → day, not IFS
    if int(parts[0]) > 5:
        return False
    return True


def extract_clauses(text):
    """Extrait les numéros de clauses IFS valides d'un texte."""
    matches = CLAUSE_RX.findall(text)
    return sorted(set(m for m in matches if is_valid_ifs_clause(m)))


def detect_type(lock_reason):
    """Détecte KO / Major / Minor / Other depuis le texte."""
    text = lock_reason.upper()
    # KO signals
    if re.search(r'\bKO\b|\bKNOCK[\s-]?OUT\b', text):
        return "KO"
    # Major signals
    if re.search(r'\bMAJOR\b|\bMAJEURE?\b', text):
        return "Major"
    # Minor signals
    if re.search(r'\bMINOR\b|\bMINEURE?\b', text):
        return "Minor"
    # Payment-related lock
    if re.search(r'\bPAYMENT\b|\bPAIEMENT\b|\bFEE\b', text):
        return "Payment"
    return "Other"


def extract_themes(text):
    """Extrait les thèmes FSC identifiés dans le texte (heuristique)."""
    lower = text.lower()
    themes = []
    theme_patterns = {
        "Leadership": ["management", "direction", "leadership", "top management", "ceo", "directeur"],
        "HACCP": ["haccp", "ccp", "critical control", "hazard analysis", "analyse de risque"],
        "Traçabilité": ["traceability", "traçabilité", "tracabilit"],
        "Hygiène": ["hygiene", "hygiène", "cleaning", "nettoyage", "disinfect", "sanitiz"],
        "Formation": ["training", "formation", "instruction", "aware", "au courant"],
        "Allergènes": ["allergen", "allergène"],
        "Corps étrangers": ["foreign matter", "foreign body", "corps étrangers", "contamination physique"],
        "Documentation": ["documented", "records", "enregistrement", "documentation"],
        "Fournisseurs": ["supplier", "fournisseur", "vendor", "approved list"],
        "Culture": ["culture", "engagement", "commitment", "implication"],
    }
    for theme, patterns in theme_patterns.items():
        if any(p in lower for p in patterns):
            themes.append(theme)
    return themes


def build_keyword_vector(text):
    """Construit un vecteur TF pondéré par les poids de sévérité."""
    lower = text.lower()
    words = re.split(r'\W+', lower)
    word_count = max(len([w for w in words if len(w) > 2]), 1)
    vec = {}
    for kw, weight in SEVERITY_KEYWORDS.items():
        count = lower.count(kw)
        if count > 0:
            tf = count / word_count
            vec[kw] = round(tf * weight, 6)
    return vec


def make_summary(lock_reason, max_len=SUMMARY_LEN):
    """Extrait un résumé tronqué du motif de suspension."""
    text = lock_reason.strip().replace("\n", " ").replace("  ", " ")
    if len(text) <= max_len:
        return text
    # Couper proprement à la dernière espace
    cut = text[:max_len]
    last_space = cut.rfind(" ")
    return (cut[:last_space] if last_space > 0 else cut) + "…"


def parse_date(date_str):
    """Convertit DD.MM.YYYY en YYYY-MM-DD pour tri."""
    try:
        parts = date_str.strip().split(".")
        if len(parts) == 3:
            d, m, y = parts
            return f"{y}-{m.zfill(2)}-{d.zfill(2)}"
    except Exception:
        pass
    return date_str


# ─── DERIVED ANALYSIS ──────────────────────────────────────────────────────

def parse_ifs_clause_severity(ifs_path):
    """
    Parse exemplesNonConformites de chaque clause IFS pour extraire le
    niveau de sévérité attendu : KO / Major / Principal / None.
    """
    if not os.path.exists(ifs_path):
        return {}
    with open(ifs_path, "r", encoding="utf-8") as f:
        ifs_data = json.load(f)
    severity_map = {}
    for chap in ifs_data:
        for ss in chap.get("sous_sections", []):
            for req in ss.get("exigences", []):
                num = req.get("numero", "").replace("*", "").strip()
                if not num:
                    continue
                if req.get("estKO"):
                    severity_map[num] = "KO"
                    continue
                ex_nc = (req.get("onglets") or {}).get("exemplesNonConformites") or ""
                ex_up = ex_nc.upper()
                if re.search(r"\bMAJEURE?\b|\bMAJOR\b", ex_up):
                    severity_map[num] = "Major"
                elif re.search(r"\bPRINCIPAL\b", ex_up):
                    severity_map[num] = "Principal"
    return severity_map


def derive_major_clauses(index, min_count=5):
    """
    Clauses apparaissant >= min_count fois dans des cas Major de la base
    (hors clauses KO). Retourne {clause: count}.
    """
    counts = defaultdict(int)
    for entry in index:
        if entry["type"] == "Major":
            for c in entry["clauses"]:
                if c not in KO_REQUIREMENTS:
                    counts[c] += 1
    return {
        c: cnt
        for c, cnt in sorted(counts.items(), key=lambda x: -x[1])
        if cnt >= min_count
    }


def compute_idf(index):
    """
    Smooth IDF (log((N+1)/(df+1))+1) pour chaque keyword de sévérité
    présent dans le corpus.
    """
    N = len(index)
    df = defaultdict(int)
    for entry in index:
        for kw in (entry.get("kw_vec") or {}):
            df[kw] += 1
    return {
        kw: round(math.log((N + 1) / (d + 1)) + 1, 4)
        for kw, d in df.items()
    }


def train_classifier(index):
    """
    Entraîne un LogReg binaire KO vs Major sur les 711 cas labellisés.
    Retourne un dict exportable en JS, ou None si sklearn absent.
    """
    try:
        from sklearn.linear_model import LogisticRegression
        from sklearn.model_selection import cross_val_score, StratifiedKFold
        from sklearn.preprocessing import normalize as sk_norm
        import numpy as np
    except ImportError:
        print("   SKIP classifieur: pip install scikit-learn pour activer")
        return None

    labeled = [e for e in index if e["type"] in ("KO", "Major")]
    n_ko  = sum(1 for e in labeled if e["type"] == "KO")
    n_maj = len(labeled) - n_ko
    print(f"   Dataset: {n_ko} KO + {n_maj} Major = {len(labeled)} exemples")

    if len(labeled) < 40:
        print("   SKIP: echantillon insuffisant")
        return None

    # Vocabulaire : keywords presents dans >= 3 docs
    df_kw = defaultdict(int)
    for e in labeled:
        for kw in (e.get("kw_vec") or {}):
            df_kw[kw] += 1
    vocab = sorted(k for k, d in df_kw.items() if d >= 3)

    # Clauses top : presentes dans >= 3 docs
    df_cl = defaultdict(int)
    for e in labeled:
        for c in e.get("clauses", []):
            df_cl[c] += 1
    top_clauses = sorted(
        (c for c, d in df_cl.items() if d >= 3),
        key=lambda c: -df_cl[c]
    )[:40]

    vocab_idx  = {v: i for i, v in enumerate(vocab)}
    clause_idx = {c: len(vocab) + i for i, c in enumerate(top_clauses)}
    n_feat = len(vocab) + len(top_clauses)

    X = np.zeros((len(labeled), n_feat), dtype=np.float32)
    y = np.array([1 if e["type"] == "KO" else 0 for e in labeled], dtype=np.int32)

    for i, entry in enumerate(labeled):
        for kw, val in (entry.get("kw_vec") or {}).items():
            if kw in vocab_idx:
                X[i, vocab_idx[kw]] = float(val)
        for c in entry.get("clauses", []):
            if c in clause_idx:
                X[i, clause_idx[c]] = 1.0

    X = sk_norm(X, norm="l2")

    clf = LogisticRegression(
        max_iter=1000, C=1.0, random_state=42, class_weight="balanced"
    )
    clf.fit(X, y)

    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    f1  = cross_val_score(clf, X, y, cv=cv, scoring="f1").mean()
    f1m = cross_val_score(clf, X, y, cv=cv, scoring="f1_macro").mean()
    print(f"   F1 KO    (CV-5) : {f1:.3f}")
    print(f"   F1 macro (CV-5) : {f1m:.3f}")

    return {
        "vocab":       vocab,
        "top_clauses": top_clauses,
        "coef":        [round(float(c), 6) for c in clf.coef_[0]],
        "intercept":   round(float(clf.intercept_[0]), 6),
    }


# ─── MAIN ──────────────────────────────────────────────────────────────────

def main():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    csv_path = os.path.join(script_dir, CSV_FILE)

    print(f"Lecture de {csv_path}…")
    rows = []
    with open(csv_path, encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            rows.append(row)

    print(f"  {len(rows)} lignes lues")

    # Filtrer sur IFS Food uniquement avec lock_reason suffisant
    ifs_rows = [
        r for r in rows
        if "IFS Food" in (r.get("Standard", "") or "")
        and len(r.get("Lock reason", "") or "") >= MIN_LOCK_REASON_LEN
    ]
    print(f"  {len(ifs_rows)} lignes IFS Food avec motif de suspension")

    # Construire l'index
    index = []
    type_counts = defaultdict(int)
    keyword_df = defaultdict(int)  # document frequency par keyword

    for row in ifs_rows:
        lock_reason = row.get("Lock reason", "") or ""
        entry_type = detect_type(lock_reason)
        type_counts[entry_type] += 1

        clauses = extract_clauses(lock_reason)
        themes = extract_themes(lock_reason)
        kw_vec = build_keyword_vector(lock_reason)
        summary = make_summary(lock_reason)
        date_iso = parse_date(row.get("Certificate/Assessment lock date", "") or "")

        # Metadonnées de fréquence
        for kw in kw_vec:
            keyword_df[kw] += 1

        full_text = lock_reason.strip().replace("\n", " ").replace("  ", " ")
        entry = {
            "id": str(row.get("COID", "") or ""),
            "supplier": (row.get("Supplier", "") or "").strip(),
            "country": (row.get("Country/Region", "") or "").strip(),
            "date": date_iso,
            "type": entry_type,
            "clauses": clauses,
            "themes": themes,
            "summary": summary,
            "full_text": full_text,
            "kw_vec": kw_vec,
        }
        index.append(entry)

    # Écrire nc_index.json
    output_path = os.path.join(script_dir, OUTPUT_FILE)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(index, f, ensure_ascii=False, separators=(",", ":"))

    size_kb = os.path.getsize(output_path) / 1024
    print(f"\nOK: {output_path} ecrit")
    print(f"   {len(index)} entrees — {size_kb:.1f} KB")

    # Statistiques de type
    print(f"\n   Répartition des types :")
    for t, c in sorted(type_counts.items(), key=lambda x: -x[1]):
        print(f"   • {t}: {c}")

    # Identifier les top keywords
    print(f"\n   Top 10 keywords les plus fréquents :")
    for kw, df in sorted(keyword_df.items(), key=lambda x: -x[1])[:10]:
        print(f"   • {kw!r}: {df} docs")

    # Écrire nc_index_meta.json
    meta = {
        "total": len(index),
        "type_distribution": dict(type_counts),
        "keyword_df": dict(keyword_df),
    }
    meta_path = os.path.join(script_dir, META_FILE)
    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump(meta, f, ensure_ascii=False, indent=2)
    print(f"\nOK: {meta_path} ecrit")

    # ─── ANALYSE DERIVEE ───────────────────────────────────────────────────
    ifs_path = os.path.join(script_dir, "ifs_food_v8_fr.json")

    print("\nAnalyse referentiel IFS Food v8...")
    clause_severity = parse_ifs_clause_severity(ifs_path)
    print(f"   {len(clause_severity)} clauses avec marqueur de severite")

    major_clauses = derive_major_clauses(index)
    print(f"   {len(major_clauses)} clauses typiquement Majeures (>= 5 cas corpus)")

    kw_idf = compute_idf(index)
    print(f"   IDF calcule pour {len(kw_idf)} keywords")

    print("\nEntrainement classifieur KO vs Majeur...")
    classifier = train_classifier(index)

    # Écrire nc_derived.js
    derived_path = os.path.join(script_dir, "nc_derived.js")
    with open(derived_path, "w", encoding="utf-8") as f:
        f.write("// Auto-generated by build_nc_index.py -- ne pas editer manuellement\n")
        f.write(f"const __KEYWORD_IDF     = {json.dumps(kw_idf, ensure_ascii=False, separators=(',',':'))};\n")
        f.write(f"const __MAJOR_CLAUSES   = {json.dumps(major_clauses, ensure_ascii=False, separators=(',',':'))};\n")
        f.write(f"const __CLAUSE_SEVERITY = {json.dumps(clause_severity, ensure_ascii=False, separators=(',',':'))};\n")
        f.write(f"const __CLASSIFIER      = {json.dumps(classifier, ensure_ascii=False, separators=(',',':'))};\n")
    dk = os.path.getsize(derived_path) / 1024
    print(f"\nOK: nc_derived.js ecrit ({dk:.0f} KB)")

    derived = {
        "kw_idf": kw_idf,
        "major_clauses": major_clauses,
        "clause_severity": clause_severity,
        "classifier": classifier,
    }

    # Générer la version standalone (zéro serveur requis)
    generate_standalone(index, derived, script_dir)


# ─── GÉNÉRATION STANDALONE ──────────────────────────────────────────────────

def generate_standalone(nc_index_data, derived_data, script_dir):
    """
    Génère NC_ANALYZER_STANDALONE.html avec toutes les données embarquées.
    Le fichier résultant s'ouvre directement par double-clic, sans serveur.
    """
    template_path = os.path.join(script_dir, "NC_ANALYZER.html")
    ifs_path      = os.path.join(script_dir, "ifs_food_v8_fr.json")
    output_path   = os.path.join(script_dir, "NC_ANALYZER_STANDALONE.html")

    if not os.path.exists(template_path):
        print("WARN: NC_ANALYZER.html introuvable — standalone non généré")
        return
    if not os.path.exists(ifs_path):
        print("WARN: ifs_food_v8_fr.json introuvable — standalone non généré")
        return

    with open(template_path, "r", encoding="utf-8") as f:
        html = f.read()
    with open(ifs_path, "r", encoding="utf-8") as f:
        ifs_data = json.load(f)

    # Sérialiser les données (compact)
    nc_json  = json.dumps(nc_index_data, ensure_ascii=False, separators=(",", ":"))
    ifs_json = json.dumps(ifs_data,      ensure_ascii=False, separators=(",", ":"))
    idf_json = json.dumps(derived_data.get("kw_idf", {}),          ensure_ascii=False, separators=(",", ":"))
    maj_json = json.dumps(derived_data.get("major_clauses", {}),    ensure_ascii=False, separators=(",", ":"))
    sev_json = json.dumps(derived_data.get("clause_severity", {}),  ensure_ascii=False, separators=(",", ":"))
    clf_json = json.dumps(derived_data.get("classifier"),           ensure_ascii=False, separators=(",", ":"))

    # ── 1. Mettre à jour le titre
    html = html.replace(
        "<title>NC Analyzer — IFS Food v8</title>",
        "<title>NC Analyzer — IFS Food v8 · Standalone</title>"
    )

    # ── 2. Injecter les constantes de données juste après <script>
    # Note: __KEYWORD_IDF / __MAJOR_CLAUSES / __CLAUSE_SEVERITY / __CLASSIFIER
    # sont injectées via nc_derived.js (step 2b) — ne pas les dupliquer ici.
    data_block = (
        "\n// ════════════════════════════════════════════════════════\n"
        "// DONNÉES EMBARQUÉES — mode standalone (file://)\n"
        "// Générées par build_nc_index.py — ne pas éditer manuellement\n"
        "// ════════════════════════════════════════════════════════\n"
        f"const __NC_INDEX       = {nc_json};\n"
        f"const __IFS_DATA       = {ifs_json};\n"
    )
    html = html.replace("<script>\n// ══════════════════════════════════════════════════════════════════════════\n// STATE",
                        "<script>" + data_block + "\n// ══════════════════════════════════════════════════════════════════════════\n// STATE")

    # ── 2b. Remplacer le tag <script src="nc_derived.js"> par inline
    DERIVED_TAG = '<script src="nc_derived.js" onerror="window.__DERIVED_MISSING=true"></script>'
    derived_path_local = os.path.join(script_dir, "nc_derived.js")
    if os.path.exists(derived_path_local):
        with open(derived_path_local, "r", encoding="utf-8") as f:
            derived_inline = f.read()
        html = html.replace(DERIVED_TAG, f"<script>\n{derived_inline}\n</script>")
    else:
        html = html.replace(DERIVED_TAG, "")

    # ── 3. Remplacer loadData() par une version qui utilise les constantes
    OLD_LOAD = (
        "async function loadData() {\n"
        "  // Detect file:// protocol\n"
        "  if (location.protocol === 'file:') {\n"
        "    document.getElementById('file-warn').style.display = 'block';\n"
        "    setStatus('error', 'Serveur local requis');\n"
        "    return;\n"
        "  }\n"
        "\n"
        "  setStatus('loading', 'Chargement du référentiel IFS…');\n"
        "  try {\n"
        "    // Load IFS v8 JSON\n"
        "    const ifsRaw = await fetch('ifs_food_v8_fr.json').then(r => r.json());"
    )
    NEW_LOAD = (
        "async function loadData() {\n"
        "  // Mode standalone : données embarquées, aucun serveur requis\n"
        "  setStatus('loading', 'Initialisation…');\n"
        "  try {\n"
        "    const ifsRaw = __IFS_DATA;"
    )
    html = html.replace(OLD_LOAD, NEW_LOAD)

    OLD_FETCH_NC = "    // Load nc_index.json\n    ncIndex = await fetch('nc_index.json').then(r => r.json());"
    NEW_FETCH_NC = "    ncIndex = __NC_INDEX;"
    html = html.replace(OLD_FETCH_NC, NEW_FETCH_NC)

    # ── 4. Masquer l'avertissement file:// (inutile en standalone)
    html = html.replace(
        '<div class="file-warning" id="file-warn">',
        '<div class="file-warning" id="file-warn" style="display:none!important">'
    )

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)

    size_kb = os.path.getsize(output_path) / 1024
    print(f"\nOK: NC_ANALYZER_STANDALONE.html genere ({size_kb:.0f} KB)")
    print(f"   Double-clic pour ouvrir — aucun serveur requis")


if __name__ == "__main__":
    main()
