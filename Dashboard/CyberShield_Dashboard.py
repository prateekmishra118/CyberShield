"""
CyberShield - Network Threat Detection & Protection
====================================================
"""
from __future__ import annotations
import html
import os
import sqlite3
import time
from contextlib import closing
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Callable

import pandas as pd
import streamlit as st

try:  
    import plotly.express as px
    import plotly.graph_objects as go

    PLOTLY_AVAILABLE = True
except ImportError:  # pragma: no cover
    px = None
    go = None
    PLOTLY_AVAILABLE = False


# =============================================================================
# 1. PROJECT CONSTANTS
# =============================================================================

APP_NAME = "CyberShield"
APP_SUBTITLE = "Network Threat Detection & Protection"

# The dashboard presents 15 threat incidents grouped from the flagged records.
TARGET_INCIDENT_COUNT = 15

# Incident / protection states
SCAN_REQUIRED = "Scan Required"
THREATS_DETECTED = "Threats Detected"
PROTECTION_ACTIVE = "Protection is Active"

ACTION_REQUIRED = "ACTION REQUIRED"
PROTECTED = "PROTECTED"
ALLOWED = "ALLOWED"

ACTIONS = ("ALLOW", "RESTRICT", "BLOCK", "ISOLATE")
ACTION_TO_STATUS = {
    "ALLOW": ALLOWED,
    "RESTRICT": PROTECTED,
    "BLOCK": PROTECTED,
    "ISOLATE": PROTECTED,
}
ACTION_DESCRIPTION = {
    "ALLOW": "Allow the connection and continue monitoring.",
    "RESTRICT": "Restrict the suspicious connection and continue monitoring.",
    "BLOCK": "Block the suspicious connection.",
    "ISOLATE": "Immediately isolate the suspicious connection.",
}

# Severity assessment and protection policy (Protection_Engine.ipynb)
SEVERITY_ORDER = ["Critical", "High", "Medium"]
SEVERITY_BY_ATTACK = {
    "Analysis": "Medium",
    "Backdoor": "Critical",
    "DoS": "High",
    "Exploits": "Critical",
    "Fuzzers": "Medium",
    "Generic": "High",
    "Reconnaissance": "Medium",
    "Shellcode": "Critical",
    "Worms": "Critical",
    "Unknown": "High",
}
SEVERITY_POLICY = {"Critical": "ISOLATE", "High": "BLOCK", "Medium": "RESTRICT"}
SEVERITY_GUIDANCE = {
    "Critical": "Isolate the affected connection immediately and investigate the source.",
    "High": "Block the suspicious connection and review related network activity.",
    "Medium": "Restrict the connection and monitor it for additional suspicious behavior.",
}

# The engineered dataset stores attack_cat as a label-encoded integer
# (Feature_Engineering.ipynb: LabelEncoder over the sorted category names).
ATTACK_CODE_TO_NAME = {
    0: "Analysis",
    1: "Backdoor",
    2: "DoS",
    3: "Exploits",
    4: "Fuzzers",
    5: "Generic",
    6: "Normal",
    7: "Reconnaissance",
    8: "Shellcode",
    9: "Worms",
}

# Protection_Engine.ipynb maps the tuned attack classifier's predictions with
# {0..8}, but that classifier was trained on the raw codes {0-5, 7, 8, 9}
# (Hyperparameter_Tuning.ipynb). Codes 7, 8 and 9 were therefore stored one
# name too low: Reconnaissance -> "Shellcode", Shellcode -> "Worms",
# Worms -> "Unknown". The signature of that offset is an "Unknown" attack type
# combined with no "Reconnaissance" records. When it is detected, the labels
# are corrected on load (severity and action are recomputed from the project's
# own severity map and policy). If the Protection Engine is re-run with a fixed
# mapping the signature disappears and nothing is changed.
APPLY_CLASS_LABEL_CORRECTION = True
ENGINE_LABEL_CORRECTION = {
    "Shellcode": "Reconnaissance",
    "Worms": "Shellcode",
    "Unknown": "Worms",
}

# Database discovery
DATABASE_FILENAME = "cybershield.db"
DATABASE_ENV_VARIABLE = "CYBERSHIELD_DB"
DATABASE_RELATIVE_LOCATIONS = (
    "cybershield.db",
    "database/cybershield.db",
    "../database/cybershield.db",
    "../cybershield.db",
    "data/cybershield.db",
)

# ------------------------------------------------------------------ results
# The values below are the recorded outputs of the executed project notebooks.

DATASET_NAME = "UNSW-NB15"
DOCUMENTED_TOTAL_RECORDS = 145_222          # after removing duplicates
DETECTION_MODEL = "HistGradientBoosting"
CLASSIFICATION_MODEL = "Random Forest"
PROTECTION_THRESHOLD = 0.30
PROTECTION_RECALL = 0.970503
ROC_AUC = 0.9726
AVERAGE_PRECISION = 0.9661

MODEL_RESULTS = [  # Final_Model_Evaluation.ipynb (test split, default threshold)
    ("HistGradientBoosting", 0.897091, 0.876863, 0.896951, 0.886793),
    ("Random Forest", 0.896574, 0.882868, 0.887603, 0.885230),
    ("Extra Trees", 0.891031, 0.874877, 0.883926, 0.879378),
    ("Gradient Boosting", 0.886865, 0.844845, 0.916565, 0.879244),
    ("Decision Tree", 0.876984, 0.864717, 0.860941, 0.862825),
    ("K-Nearest Neighbors", 0.859218, 0.837335, 0.852283, 0.844743),
    ("AdaBoost", 0.849819, 0.790092, 0.906681, 0.844381),
    ("Logistic Regression", 0.773627, 0.690736, 0.898560, 0.781060),
    ("Linear SVM", 0.733001, 0.635134, 0.953724, 0.762488),
    ("Gaussian Naive Bayes", 0.763505, 0.698287, 0.834125, 0.760186),
]
METRICS = ["Accuracy", "Precision", "Recall", "F1 Score"]

TUNING_RESULTS = {  # Hyperparameter_Tuning.ipynb
    "Before Tuning": (0.897091, 0.876863, 0.896951, 0.886793),
    "After Tuning": (0.898915, 0.881563, 0.895342, 0.888399),
}
TUNED_DETECTION_PARAMETERS = {
    "learning_rate": 0.05,
    "max_iter": 200,
    "max_leaf_nodes": 63,
    "min_samples_leaf": 20,
    "l2_regularization": 0,
}

THRESHOLD_RESULTS = [  # threshold, accuracy, precision, recall, f1, FN, FP
    (0.30, 0.880083, 0.803489, 0.970503, 0.879134, 385, 3098),
    (0.35, 0.889206, 0.824127, 0.957861, 0.885975, 550, 2668),
    (0.40, 0.896092, 0.844858, 0.941695, 0.890652, 761, 2257),
    (0.45, 0.898984, 0.865958, 0.917177, 0.890832, 1081, 1853),
    (0.50, 0.898915, 0.881563, 0.895342, 0.888399, 1366, 1570),
]

ATTACK_CLASSIFIER_ACCURACY = 0.7466
ATTACK_CLASSIFIER_WEIGHTED_F1 = 0.7318
ATTACK_CLASSIFIER_REPORT = [  # category, precision, recall, f1, support (tuned)
    ("Analysis", 0.20, 0.24, 0.22, 288),
    ("Backdoor", 0.39, 0.15, 0.21, 278),
    ("DoS", 0.26, 0.18, 0.21, 975),
    ("Exploits", 0.78, 0.87, 0.82, 5350),
    ("Fuzzers", 0.81, 0.88, 0.84, 3663),
    ("Generic", 0.93, 0.59, 0.72, 611),
    ("Reconnaissance", 0.81, 0.73, 0.77, 1603),
    ("Shellcode", 0.41, 0.23, 0.29, 251),
    ("Worms", 0.33, 0.09, 0.14, 33),
]

FEATURE_IMPORTANCE = [  # Feature_Engineering.ipynb (Random Forest, top 15)
    ("ackdat", 0.093989),
    ("synack", 0.079521),
    ("dload", 0.077850),
    ("tcprtt", 0.072696),
    ("dmean", 0.056583),
    ("rate", 0.054557),
    ("sbytes", 0.052953),
    ("dbytes", 0.049060),
    ("smean", 0.048598),
    ("dinpkt", 0.048580),
    ("dur", 0.040007),
    ("sload", 0.038115),
    ("sinpkt", 0.034190),
    ("djit", 0.033275),
    ("sjit", 0.031030),
]

DATA_PREPARATION_SUMMARY = [  # Data_Preprocessing / Feature_Engineering notebooks
    ("Raw records (training + testing sets)", "257,673"),
    ("Duplicate records removed", "112,451 (43.64%)"),
    ("Records after cleaning", "145,222"),
    ("Normal / attack records", "79,965 / 65,257"),
    ("Features after encoding and scaling", "34"),
    ("Features selected (Random Forest importance)", "15"),
    ("Train / test split", "80% / 20%, stratified"),
]


# =============================================================================
# 2. VISUAL SYSTEM
# =============================================================================

FONT_STACK = '"Segoe UI", "Helvetica Neue", Arial, sans-serif'

COLOR_NAVY = "#12305A"
COLOR_BLUE = "#1F5FA6"
COLOR_LIGHT_BLUE = "#8FB3D9"
COLOR_GREY = "#98A2B3"
COLOR_TEXT = "#1B2430"
COLOR_GRID = "#E6EAF0"

SEVERITY_COLORS = {"Critical": "#B42318", "High": "#DD6B20", "Medium": "#D9A400"}
STATUS_COLORS = {ACTION_REQUIRED: "#B42318", PROTECTED: "#187A4A", ALLOWED: "#667085"}
SEVERITY_TONE = {"Critical": "red", "High": "orange", "Medium": "amber"}
STATUS_TONE = {ACTION_REQUIRED: "red", PROTECTED: "green", ALLOWED: "slate"}

ICON_SHIELD = (
    '<svg viewBox="0 0 24 24" width="30" height="30" aria-hidden="true">'
    '<path d="M12 2 4 5v6c0 5 3.4 9.3 8 11 4.6-1.7 8-6 8-11V5l-8-3z" fill="#12305A"/>'
    '<path d="m8.5 12 2.5 2.5 4.5-5" stroke="#fff" stroke-width="2" fill="none" '
    'stroke-linecap="round" stroke-linejoin="round"/></svg>'
)
BANNER_ICONS = {
    "slate": (
        '<svg viewBox="0 0 24 24" width="30" height="30" aria-hidden="true">'
        '<circle cx="12" cy="12" r="10" fill="#475467"/>'
        '<rect x="11" y="10.5" width="2" height="6.5" fill="#fff"/>'
        '<circle cx="12" cy="7.5" r="1.3" fill="#fff"/></svg>'
    ),
    "red": (
        '<svg viewBox="0 0 24 24" width="30" height="30" aria-hidden="true">'
        '<path d="M12 2 2 21h20L12 2z" fill="#B42318"/>'
        '<rect x="11" y="9" width="2" height="6" fill="#fff"/>'
        '<circle cx="12" cy="17.5" r="1.2" fill="#fff"/></svg>'
    ),
    "green": (
        '<svg viewBox="0 0 24 24" width="30" height="30" aria-hidden="true">'
        '<path d="M12 2 4 5v6c0 5 3.4 9.3 8 11 4.6-1.7 8-6 8-11V5l-8-3z" fill="#187A4A"/>'
        '<path d="m8.5 12 2.5 2.5 4.5-5" stroke="#fff" stroke-width="2" fill="none" '
        'stroke-linecap="round" stroke-linejoin="round"/></svg>'
    ),
}

APP_CSS = """
<style>
:root {
    --cs-bg: #F1F3F6;
    --cs-surface: #FFFFFF;
    --cs-border: #D3D9E2;
    --cs-border-strong: #B9C2CF;
    --cs-text: #1B2430;
    --cs-muted: #5A6676;
    --cs-navy: #12305A;
    --cs-blue: #1F5FA6;
    --cs-green: #187A4A;
    --cs-green-bg: #E7F4EC;
    --cs-red: #B42318;
    --cs-red-bg: #FCEBE9;
    --cs-orange: #B54708;
    --cs-orange-bg: #FDF0E1;
    --cs-amber: #8A6100;
    --cs-amber-bg: #FFF6D6;
    --cs-slate: #475467;
    --cs-slate-bg: #ECEFF3;
}
html, body, .stApp, [data-testid="stApp"], [data-testid="stAppViewContainer"],
[data-testid="stMain"], section.main {
    background: var(--cs-bg) !important;
    color-scheme: light;
    font-family: __FONT__;
}
[data-testid="stHeader"] { background: transparent !important; }
[data-testid="stSidebar"], [data-testid="stSidebar"] > div:first-child {
    background: #FFFFFF !important;
    border-right: 1px solid var(--cs-border);
}
.block-container { max-width: 1180px; padding-top: 2.2rem; padding-bottom: 3rem; }
footer { visibility: hidden; }

/* Buttons */
button[kind="secondary"], [data-testid="stBaseButton-secondary"] {
    background: #FFFFFF !important;
    color: var(--cs-text) !important;
    border: 1px solid var(--cs-border-strong) !important;
    border-radius: 6px !important;
    font-weight: 600 !important;
    box-shadow: none !important;
}
button[kind="secondary"]:hover, [data-testid="stBaseButton-secondary"]:hover {
    background: #F3F6FA !important;
    border-color: var(--cs-blue) !important;
    color: var(--cs-navy) !important;
}
button[kind="primary"], [data-testid="stBaseButton-primary"] {
    background: var(--cs-blue) !important;
    color: #FFFFFF !important;
    border: 1px solid var(--cs-blue) !important;
    border-radius: 6px !important;
    font-weight: 600 !important;
    box-shadow: none !important;
}
button[kind="primary"]:hover, [data-testid="stBaseButton-primary"]:hover {
    background: var(--cs-navy) !important;
    border-color: var(--cs-navy) !important;
}
button[kind="secondary"] p, button[kind="primary"] p,
[data-testid="stBaseButton-secondary"] p, [data-testid="stBaseButton-primary"] p {
    color: inherit !important;
    font-weight: 600;
}
[data-testid="stSidebar"] button { justify-content: flex-start; text-align: left; }
[data-testid="stSidebar"] button p { text-align: left; width: 100%; }
[data-testid="stSidebar"] button[kind="secondary"],
[data-testid="stSidebar"] [data-testid="stBaseButton-secondary"] {
    border-color: transparent !important;
    background: transparent !important;
}
[data-testid="stSidebar"] button[kind="secondary"]:hover,
[data-testid="stSidebar"] [data-testid="stBaseButton-secondary"]:hover {
    background: #EEF2F7 !important;
    border-color: transparent !important;
}

/* Tabs */
button[role="tab"] p { color: var(--cs-muted) !important; font-weight: 600; }
button[role="tab"][aria-selected="true"] p { color: var(--cs-navy) !important; }

/* Charts */
[data-testid="stPlotlyChart"] {
    background: #FFFFFF;
    border: 1px solid var(--cs-border);
    border-radius: 8px;
    padding: 6px 8px;
    box-shadow: 0 1px 2px rgba(16, 24, 40, 0.05);
}

/* Application header */
.cs-header { padding-bottom: 14px; margin-bottom: 22px; border-bottom: 1px solid var(--cs-border); }
.cs-title { font-size: 46px; font-weight: 700; line-height: 1.08; color: var(--cs-navy); letter-spacing: -0.5px; }
.cs-subtitle { font-size: 23px; font-weight: 500; line-height: 1.3; color: var(--cs-slate); margin-top: 4px; }

/* Sidebar brand and info */
.cs-brand { display: flex; align-items: center; gap: 10px; padding: 4px 2px 2px 2px; }
.cs-brand-name { font-size: 21px; font-weight: 700; color: var(--cs-navy); line-height: 1.1; }
.cs-brand-sub { font-size: 12px; color: var(--cs-muted); margin: 2px 0 10px 2px; line-height: 1.3; }
.cs-side-label { font-size: 12px; font-weight: 600; color: var(--cs-muted); margin: 14px 0 6px 2px; }
.cs-side-info { font-size: 12.5px; color: var(--cs-muted); line-height: 1.6; padding-left: 2px; }
.cs-side-info b { color: var(--cs-text); font-weight: 600; }

/* Page headings */
.cs-page-title { font-size: 26px; font-weight: 650; color: var(--cs-text); margin: 4px 0 2px 0; }
.cs-page-desc { font-size: 15px; color: var(--cs-muted); margin-bottom: 18px; max-width: 820px; line-height: 1.5; }
.cs-section { font-size: 17px; font-weight: 650; color: var(--cs-text); margin: 26px 0 10px 0; }
.cs-note { font-size: 12.5px; color: var(--cs-muted); margin: 8px 0 4px 0; line-height: 1.5; }

/* Cards */
.cs-card {
    background: var(--cs-surface);
    border: 1px solid var(--cs-border);
    border-radius: 8px;
    padding: 18px 20px;
    box-shadow: 0 1px 2px rgba(16, 24, 40, 0.05);
    color: var(--cs-text);
}
.cs-card-title { font-size: 15px; font-weight: 650; color: var(--cs-text); margin-bottom: 6px; }
.cs-card-text { font-size: 14px; color: var(--cs-muted); line-height: 1.55; }
.cs-card-text b { color: var(--cs-text); }
.cs-empty {
    background: var(--cs-surface);
    border: 1px dashed var(--cs-border-strong);
    border-radius: 8px;
    padding: 30px 20px;
    text-align: center;
}
.cs-empty-title { font-size: 16px; font-weight: 650; color: var(--cs-text); }
.cs-empty-text { font-size: 14px; color: var(--cs-muted); margin-top: 4px; }

/* Status banner */
.cs-banner {
    display: flex; gap: 16px; align-items: center;
    background: var(--cs-surface);
    border: 1px solid var(--cs-border);
    border-left: 6px solid var(--cs-slate);
    border-radius: 8px;
    padding: 18px 22px;
    box-shadow: 0 1px 2px rgba(16, 24, 40, 0.05);
    margin-bottom: 18px;
}
.cs-banner-red { border-left-color: var(--cs-red); }
.cs-banner-green { border-left-color: var(--cs-green); }
.cs-banner-slate { border-left-color: var(--cs-slate); }
.cs-banner-label { font-size: 12.5px; color: var(--cs-muted); font-weight: 600; }
.cs-banner-title { font-size: 26px; font-weight: 700; line-height: 1.2; color: var(--cs-text); }
.cs-banner-red .cs-banner-title { color: var(--cs-red); }
.cs-banner-green .cs-banner-title { color: var(--cs-green); }
.cs-banner-text { font-size: 14.5px; color: var(--cs-muted); margin-top: 3px; line-height: 1.5; }

/* KPI cards */
.cs-kpis { display: grid; gap: 14px; margin: 4px 0 8px 0; }
.cs-kpi {
    background: var(--cs-surface);
    border: 1px solid var(--cs-border);
    border-radius: 8px;
    padding: 14px 18px 16px 18px;
    box-shadow: 0 1px 2px rgba(16, 24, 40, 0.05);
}
.cs-kpi-label { font-size: 13px; font-weight: 600; color: var(--cs-muted); }
.cs-kpi-value { font-size: 32px; font-weight: 700; color: var(--cs-text); line-height: 1.25; margin-top: 2px; }
.cs-kpi-value-sm { font-size: 22px; padding-top: 6px; }
.cs-kpi-note { font-size: 12.5px; color: var(--cs-muted); margin-top: 2px; }
.cs-kpi-red .cs-kpi-value { color: var(--cs-red); }
.cs-kpi-green .cs-kpi-value { color: var(--cs-green); }
.cs-kpi-blue .cs-kpi-value { color: var(--cs-blue); }
.cs-kpi-slate .cs-kpi-value { color: var(--cs-slate); }

/* Badges */
.cs-badge {
    display: inline-block; padding: 2px 9px; border-radius: 4px;
    font-size: 12px; font-weight: 650; letter-spacing: 0.2px; white-space: nowrap;
}
.cs-badge-red { background: var(--cs-red-bg); color: var(--cs-red); }
.cs-badge-green { background: var(--cs-green-bg); color: var(--cs-green); }
.cs-badge-orange { background: var(--cs-orange-bg); color: var(--cs-orange); }
.cs-badge-amber { background: var(--cs-amber-bg); color: var(--cs-amber); }
.cs-badge-slate { background: var(--cs-slate-bg); color: var(--cs-slate); }
.cs-badge-blue { background: #E8F0FA; color: var(--cs-blue); }

/* Tables */
.cs-table-wrap {
    background: var(--cs-surface);
    border: 1px solid var(--cs-border);
    border-radius: 8px;
    overflow-x: auto;
    box-shadow: 0 1px 2px rgba(16, 24, 40, 0.05);
}
.cs-table { width: 100%; border-collapse: collapse; font-size: 14px; color: var(--cs-text); }
.cs-table th {
    text-align: left; background: #F6F8FA; color: var(--cs-muted);
    font-size: 12.5px; font-weight: 650; padding: 10px 14px;
    border-bottom: 1px solid var(--cs-border); white-space: nowrap;
}
.cs-table td { padding: 10px 14px; border-bottom: 1px solid #EDF0F4; vertical-align: middle; }
.cs-table tr:last-child td { border-bottom: none; }
.cs-table td.cs-num, .cs-table th.cs-num { text-align: right; }
.cs-table tr.cs-row-best td { background: #F1F7FD; font-weight: 600; }

/* Detail grid inside cards and dialogs */
.cs-detail-grid { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 14px; }
.cs-detail-grid-2 { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 12px; }
.cs-detail-label { font-size: 12.5px; font-weight: 600; color: var(--cs-muted); margin-bottom: 3px; }
.cs-detail-value { font-size: 15.5px; font-weight: 600; color: var(--cs-text); }

/* Progress */
.cs-progress { background: #E3E8EF; border-radius: 4px; height: 10px; overflow: hidden; }
.cs-progress-bar { background: var(--cs-blue); height: 10px; border-radius: 4px; }
.cs-progress-bar-green { background: var(--cs-green); }
.cs-progress-label { font-size: 13.5px; color: var(--cs-muted); margin: 8px 0 0 0; }
.cs-progress-label b { color: var(--cs-text); }

/* Notices */
.cs-notice {
    border: 1px solid var(--cs-border); border-left: 5px solid var(--cs-slate);
    border-radius: 6px; background: #FFFFFF; padding: 12px 16px;
    font-size: 14.5px; color: var(--cs-text); margin-bottom: 16px;
}
.cs-notice-success { border-left-color: var(--cs-green); background: #F3FAF6; }
.cs-notice-error { border-left-color: var(--cs-red); background: #FEF4F3; }
.cs-notice-warning { border-left-color: var(--cs-orange); background: #FFF8EE; }

@media (max-width: 900px) {
    .cs-detail-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
    .cs-title { font-size: 36px; }
    .cs-subtitle { font-size: 18px; }
}
</style>
""".replace("__FONT__", FONT_STACK)


# =============================================================================
# 3. DATA ACCESS  (read-only — nothing here writes to the database)
# =============================================================================

def _candidate_db_paths() -> list[Path]:
    paths: list[Path] = []
    env_path = os.environ.get(DATABASE_ENV_VARIABLE)
    if env_path:
        paths.append(Path(env_path))
    here = Path(__file__).resolve().parent
    for rel in DATABASE_RELATIVE_LOCATIONS:
        paths.append(here / rel)
    return paths


def _locate_database() -> Path | None:
    for path in _candidate_db_paths():
        if path.is_file():
            return path
    return None


@st.cache_data(show_spinner=False)
def load_protection_incidents(db_path: str) -> pd.DataFrame:
    """Read the Protection Engine's flagged-record table (read-only)."""
    uri = f"file:{db_path}?mode=ro"
    with closing(sqlite3.connect(uri, uri=True)) as connection:
        return pd.read_sql_query(
            'SELECT "Attack Type", "Severity" FROM protection_incidents',
            connection,
        )


@st.cache_data(show_spinner=False)
def load_traffic_summary(db_path: str) -> dict | None:
    """Read normal/attack totals from the engineered network_data table, if present."""
    uri = f"file:{db_path}?mode=ro"
    try:
        with closing(sqlite3.connect(uri, uri=True)) as connection:
            counts = pd.read_sql_query(
                "SELECT label, COUNT(*) AS total FROM network_data GROUP BY label",
                connection,
            )
    except Exception:
        return None
    normal = int(counts.loc[counts["label"] == 0, "total"].sum())
    attack = int(counts.loc[counts["label"] == 1, "total"].sum())
    return {"normal": normal, "attack": attack, "total": normal + attack}


def _detect_and_correct_label_offset(counts: dict[str, int]) -> dict[str, int]:
    """
    Correct the attack-classifier label offset documented above, if present.

    Signature of the bug: an "Unknown" category with no "Reconnaissance"
    category — the classifier never predicts a class outside its known
    codes, so a real "Unknown" bucket can only appear if code 9 (Worms)
    fell through the Protection Engine's incomplete name-lookup table.
    """
    has_unknown = counts.get("Unknown", 0) > 0
    has_reconnaissance = counts.get("Reconnaissance", 0) > 0
    if not (APPLY_CLASS_LABEL_CORRECTION and has_unknown and not has_reconnaissance):
        return counts

    corrected: dict[str, int] = {}
    for name, count in counts.items():
        corrected_name = ENGINE_LABEL_CORRECTION.get(name, name)
        corrected[corrected_name] = corrected.get(corrected_name, 0) + count
    return corrected


@dataclass(frozen=True)
class IncidentTemplate:
    incident_id: str
    attack_type: str
    severity: str
    recommended_action: str


def _allocate_incident_counts(
    category_counts: dict[str, int], target_total: int
) -> dict[str, int]:
    """Give every category at least one incident, then weight the rest by prevalence."""
    ordered = sorted(category_counts.items(), key=lambda item: item[1], reverse=True)
    allocation = {name: 1 for name, _ in ordered}
    remaining = target_total - len(ordered)
    index = 0
    while remaining > 0 and ordered:
        name = ordered[index % len(ordered)][0]
        allocation[name] += 1
        remaining -= 1
        index += 1
    return allocation


@st.cache_data(show_spinner=False)
def build_incident_catalog(db_path: str) -> tuple[list[dict], dict, int]:
    """
    Build the 15 dashboard-level threat incidents from the Protection Engine's
    flagged records, grouped into their attack categories.

    Returns (incidents, category_counts, records_analyzed).
    """
    raw = load_protection_incidents(db_path)
    records_analyzed = len(raw)

    raw_counts = raw["Attack Type"].value_counts().to_dict()
    category_counts = _detect_and_correct_label_offset(raw_counts)

    allocation = _allocate_incident_counts(category_counts, TARGET_INCIDENT_COUNT)

    incidents: list[dict] = []
    counter = 1
    for attack_type, _ in sorted(
        category_counts.items(), key=lambda item: item[1], reverse=True
    ):
        severity = SEVERITY_BY_ATTACK.get(attack_type, "High")
        recommended = SEVERITY_POLICY.get(severity, "BLOCK")
        for _ in range(allocation.get(attack_type, 0)):
            incidents.append(
                {
                    "Incident ID": f"INC-{counter:03d}",
                    "Attack Type": attack_type,
                    "Severity": severity,
                    "Recommended Action": recommended,
                }
            )
            counter += 1

    return incidents, category_counts, records_analyzed


@st.cache_resource(show_spinner=False)
def get_project_data() -> dict:
    """Load everything the dashboard needs from disk once per server process."""
    db_path = _locate_database()
    if db_path is None:
        return {"error": "missing_database"}

    try:
        incidents, category_counts, records_analyzed = build_incident_catalog(str(db_path))
    except Exception as exc:  # pragma: no cover - surfaced to the user, not swallowed
        return {"error": "query_failed", "detail": str(exc)}

    if not incidents:
        return {"error": "no_incidents"}

    traffic_summary = load_traffic_summary(str(db_path))

    return {
        "error": None,
        "db_path": str(db_path),
        "incidents": incidents,
        "category_counts": category_counts,
        "records_analyzed": records_analyzed,
        "traffic_summary": traffic_summary,
        "category_count": len(category_counts),
    }


# =============================================================================
# 4. SESSION STATE
# =============================================================================

def init_session_state(incidents: list[dict]) -> None:
    """Create every session-state key exactly once. Never called again after that."""
    if st.session_state.get("cs_initialized"):
        return

    st.session_state.cs_initialized = True
    st.session_state.cs_page = "Home"
    st.session_state.cs_scan_started = False
    st.session_state.cs_scan_count = 0
    st.session_state.cs_incident_status = {
        incident["Incident ID"]: ACTION_REQUIRED for incident in incidents
    }
    st.session_state.cs_action_log: list[dict] = []
    st.session_state.cs_selected_incident = None
    st.session_state.cs_flash_message = None
    st.session_state.cs_confirm_incident = None
    st.session_state.cs_confirm_action = None
    st.session_state.cs_reset_requested = False


def go_to(page: str) -> None:
    st.session_state.cs_page = page


def perform_scan() -> None:
    """
    Starting (or re-running) a scan only reveals the current incident queue —
    it never rebuilds incident_status, so handled incidents never reappear.
    """
    st.session_state.cs_scan_started = True
    st.session_state.cs_scan_count += 1


def reset_session(incidents: list[dict]) -> None:
    st.session_state.cs_incident_status = {
        incident["Incident ID"]: ACTION_REQUIRED for incident in incidents
    }
    st.session_state.cs_scan_started = False
    st.session_state.cs_scan_count = 0
    st.session_state.cs_action_log = []
    st.session_state.cs_selected_incident = None
    st.session_state.cs_flash_message = "Session reset. All 15 incidents require action again."
    st.session_state.cs_confirm_incident = None
    st.session_state.cs_confirm_action = None
    go_to("Home")


def apply_protection_action(incident: dict, action: str) -> None:
    incident_id = incident["Incident ID"]
    new_status = ACTION_TO_STATUS[action]
    st.session_state.cs_incident_status[incident_id] = new_status
    st.session_state.cs_action_log.insert(
        0,
        {
            "Time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "Incident ID": incident_id,
            "Attack Type": incident["Attack Type"],
            "Severity": incident["Severity"],
            "Action": action,
            "Status": new_status,
        },
    )
    st.session_state.cs_flash_message = (
        f"{action} applied to {incident['Attack Type']} ({incident_id})."
    )
    if st.session_state.cs_selected_incident == incident_id:
        st.session_state.cs_selected_incident = None
    st.session_state.cs_confirm_incident = None
    st.session_state.cs_confirm_action = None


# ---- derived counters -------------------------------------------------------

def scan_has_run() -> bool:
    return st.session_state.cs_scan_started


def count_by_status(status: str) -> int:
    if not scan_has_run():
        return 0
    return sum(1 for value in st.session_state.cs_incident_status.values() if value == status)


def count_action_required() -> int:
    return count_by_status(ACTION_REQUIRED)


def count_protected() -> int:
    return count_by_status(PROTECTED)


def count_allowed() -> int:
    return count_by_status(ALLOWED)


def count_handled() -> int:
    return count_protected() + count_allowed()


def security_status() -> str:
    if not scan_has_run():
        return SCAN_REQUIRED
    if count_action_required() > 0:
        return THREATS_DETECTED
    return PROTECTION_ACTIVE


def status_tone(status: str) -> str:
    if status == SCAN_REQUIRED:
        return "slate"
    if status == THREATS_DETECTED:
        return "red"
    return "green"


def incidents_by_id(incidents: list[dict]) -> dict[str, dict]:
    return {incident["Incident ID"]: incident for incident in incidents}


def action_required_incidents(incidents: list[dict]) -> list[dict]:
    status_map = st.session_state.cs_incident_status
    return [i for i in incidents if status_map.get(i["Incident ID"]) == ACTION_REQUIRED]


# =============================================================================
# 5. RENDER HELPERS
# =============================================================================

def inject_css() -> None:
    st.markdown(APP_CSS, unsafe_allow_html=True)


def render_app_header() -> None:
    st.markdown(
        f'<div class="cs-header">'
        f'<div class="cs-title">{APP_NAME}</div>'
        f'<div class="cs-subtitle">{APP_SUBTITLE}</div>'
        f"</div>",
        unsafe_allow_html=True,
    )


def render_page_heading(title: str, description: str) -> None:
    st.markdown(f'<div class="cs-page-title">{html.escape(title)}</div>', unsafe_allow_html=True)
    st.markdown(f'<div class="cs-page-desc">{html.escape(description)}</div>', unsafe_allow_html=True)


def render_section_heading(title: str) -> None:
    st.markdown(f'<div class="cs-section">{html.escape(title)}</div>', unsafe_allow_html=True)


def render_status_banner(status: str, detail: str) -> None:
    tone = status_tone(status)
    icon = BANNER_ICONS[tone]
    st.markdown(
        f'<div class="cs-banner cs-banner-{tone}">'
        f"{icon}"
        f'<div><div class="cs-banner-label">Security Status</div>'
        f'<div class="cs-banner-title">{html.escape(status)}</div>'
        f'<div class="cs-banner-text">{html.escape(detail)}</div></div></div>',
        unsafe_allow_html=True,
    )


def render_kpi_row(items: list[tuple[str, str, str, str | None]]) -> None:
    """items: list of (label, value, tone, note-or-None)."""
    cols = st.columns(len(items))
    for col, (label, value, tone, note) in zip(cols, items):
        with col:
            note_html = f'<div class="cs-kpi-note">{html.escape(note)}</div>' if note else ""
            size_class = " cs-kpi-value-sm" if len(value) > 14 else ""
            st.markdown(
                f'<div class="cs-kpi cs-kpi-{tone}">'
                f'<div class="cs-kpi-label">{html.escape(label)}</div>'
                f'<div class="cs-kpi-value{size_class}">{html.escape(value)}</div>'
                f"{note_html}</div>",
                unsafe_allow_html=True,
            )


def severity_badge(severity: str) -> str:
    tone = SEVERITY_TONE.get(severity, "slate")
    return f'<span class="cs-badge cs-badge-{tone}">{html.escape(severity)}</span>'


def status_badge(status: str) -> str:
    tone = STATUS_TONE.get(status, "slate")
    return f'<span class="cs-badge cs-badge-{tone}">{html.escape(status)}</span>'


def action_badge(action: str) -> str:
    return f'<span class="cs-badge cs-badge-blue">{html.escape(action)}</span>'


def render_html_table(headers: list[str], rows: list[list[str]], numeric_cols: set[int] | None = None) -> None:
    numeric_cols = numeric_cols or set()
    head_html = "".join(
        f'<th class="{"cs-num" if i in numeric_cols else ""}">{html.escape(h)}</th>'
        for i, h in enumerate(headers)
    )
    body_rows = []
    for row in rows:
        cells = "".join(
            f'<td class="{"cs-num" if i in numeric_cols else ""}">{cell}</td>'
            for i, cell in enumerate(row)
        )
        body_rows.append(f"<tr>{cells}</tr>")
    st.markdown(
        f'<div class="cs-table-wrap"><table class="cs-table">'
        f"<thead><tr>{head_html}</tr></thead><tbody>{''.join(body_rows)}</tbody></table></div>",
        unsafe_allow_html=True,
    )


def render_empty_state(title: str, text: str) -> None:
    st.markdown(
        f'<div class="cs-empty"><div class="cs-empty-title">{html.escape(title)}</div>'
        f'<div class="cs-empty-text">{html.escape(text)}</div></div>',
        unsafe_allow_html=True,
    )


def render_card(title: str, text: str) -> None:
    st.markdown(
        f'<div class="cs-card"><div class="cs-card-title">{html.escape(title)}</div>'
        f'<div class="cs-card-text">{text}</div></div>',
        unsafe_allow_html=True,
    )


def render_flash_message() -> None:
    message = st.session_state.get("cs_flash_message")
    if message:
        st.markdown(
            f'<div class="cs-notice cs-notice-success">{html.escape(message)}</div>',
            unsafe_allow_html=True,
        )
        st.session_state.cs_flash_message = None


def render_progress(value: int, label: str, tone_green: bool = False) -> None:
    bar_class = "cs-progress-bar-green" if tone_green else ""
    st.markdown(
        f'<div class="cs-progress"><div class="cs-progress-bar {bar_class}" '
        f'style="width:{value}%;"></div></div>'
        f'<div class="cs-progress-label">{html.escape(label)}</div>',
        unsafe_allow_html=True,
    )


def plotly_layout(fig, height: int = 380):
    fig.update_layout(
        template="plotly_white",
        font=dict(family=FONT_STACK, color=COLOR_TEXT, size=13),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        height=height,
        margin=dict(l=10, r=10, t=48, b=10),
        title_font=dict(size=15, color=COLOR_NAVY),
        legend=dict(bgcolor="rgba(0,0,0,0)"),
    )
    fig.update_xaxes(showgrid=False, linecolor=COLOR_GRID)
    fig.update_yaxes(showgrid=True, gridcolor=COLOR_GRID, zeroline=False)
    return fig


# =============================================================================
# 6. SIDEBAR
# =============================================================================

NAV_PAGES = [
    "Home",
    "Network Scan",
    "Threat Protection",
    "Protection Center",
    "Protection History",
    "Security Analytics",
]


def render_sidebar(data: dict) -> None:
    with st.sidebar:
        st.markdown(
            f'<div class="cs-brand">{ICON_SHIELD}'
            f'<div class="cs-brand-name">{APP_NAME}</div></div>'
            f'<div class="cs-brand-sub">{APP_SUBTITLE}</div>',
            unsafe_allow_html=True,
        )
        st.markdown('<div class="cs-side-label">NAVIGATION</div>', unsafe_allow_html=True)
        for page in NAV_PAGES:
            is_current = st.session_state.cs_page == page
            if st.button(
                page,
                key=f"nav_{page}",
                use_container_width=True,
                type="primary" if is_current else "secondary",
            ):
                go_to(page)
                st.rerun()

        st.markdown('<div class="cs-side-label">SYSTEM STATUS</div>', unsafe_allow_html=True)
        status = security_status()
        st.markdown(status_badge(status), unsafe_allow_html=True)
        st.markdown(
            '<div class="cs-side-info" style="margin-top:8px;">'
            f"<b>Detection model</b><br>{DETECTION_MODEL}<br><br>"
            f"<b>Classification model</b><br>{CLASSIFICATION_MODEL}<br><br>"
            f"<b>Protection threshold</b><br>{PROTECTION_THRESHOLD:.2f}"
            "</div>",
            unsafe_allow_html=True,
        )

        st.markdown('<div class="cs-side-label">DATA SOURCE</div>', unsafe_allow_html=True)
        db_name = Path(data["db_path"]).name
        st.markdown(
            f'<div class="cs-side-info">{DATASET_NAME} dataset<br>'
            f"Read from <b>{html.escape(db_name)}</b></div>",
            unsafe_allow_html=True,
        )

        st.markdown("<div style='margin-top:18px;'></div>", unsafe_allow_html=True)
        if st.button("Reset Current Session", use_container_width=True):
            st.session_state.cs_reset_requested = True
            st.rerun()


@st.dialog("Reset Current Session")
def reset_confirmation_dialog(incidents: list[dict]) -> None:
    st.write(
        "This clears every protection action taken so far and returns all "
        f"{TARGET_INCIDENT_COUNT} incidents to **{ACTION_REQUIRED}**. "
        "This cannot be undone."
    )
    col_cancel, col_confirm = st.columns(2)
    with col_cancel:
        if st.button("Cancel", use_container_width=True):
            st.session_state.cs_reset_requested = False
            st.rerun()
    with col_confirm:
        if st.button("Confirm Reset", type="primary", use_container_width=True):
            reset_session(incidents)
            st.session_state.cs_reset_requested = False
            st.rerun()


# =============================================================================
# 7. PAGE: HOME
# =============================================================================

def page_home(data: dict) -> None:
    incidents = data["incidents"]
    render_page_heading(
        "Security Control Center",
        "Overall status of network threat detection and protection for this session.",
    )

    status = security_status()
    remaining = count_action_required()
    if status == SCAN_REQUIRED:
        detail = "Run a security scan to analyze the network environment."
    elif status == THREATS_DETECTED:
        detail = f"{remaining} of {TARGET_INCIDENT_COUNT} threat incidents require a protection action."
    else:
        detail = "All detected threats have been handled. CyberShield is actively monitoring."
    render_status_banner(status, detail)

    render_kpi_row(
        [
            (
                "Threats Requiring Action",
                str(remaining),
                "red" if remaining else "green",
                None,
            ),
            (
                "Threat Categories Detected",
                str(data["category_count"]) if scan_has_run() else "0",
                "blue",
                None,
            ),
            ("Threats Handled", str(count_handled()), "slate", None),
            ("Security Scans Run", str(st.session_state.cs_scan_count), "slate", None),
        ]
    )

    render_section_heading("Quick Actions")
    c1, c2, c3 = st.columns(3)
    with c1:
        render_card("Network Scan", "Analyze network traffic for potential threats.")
        if st.button("Open Network Scan", key="home_scan", use_container_width=True):
            go_to("Network Scan")
            st.rerun()
    with c2:
        render_card("Threat Protection", "Review detected incidents and apply protection actions.")
        if st.button("Open Threat Protection", key="home_protection", use_container_width=True):
            go_to("Threat Protection")
            st.rerun()
    with c3:
        render_card("Security Analytics", "Model performance and detection analysis.")
        if st.button("Open Security Analytics", key="home_analytics", use_container_width=True):
            go_to("Security Analytics")
            st.rerun()

    st.markdown("<div style='height:6px;'></div>", unsafe_allow_html=True)
    if status == THREATS_DETECTED:
        if st.button("Review & Protect Threats", type="primary", use_container_width=True):
            go_to("Threat Protection")
            st.rerun()
    elif status == SCAN_REQUIRED:
        if st.button("Start Security Scan", type="primary", use_container_width=True):
            go_to("Network Scan")
            st.rerun()


# =============================================================================
# 8. PAGE: NETWORK SCAN
# =============================================================================

def page_network_scan(data: dict) -> None:
    render_page_heading(
        "Network Security Scan",
        "Run a scan to analyze network traffic and identify threat incidents "
        "requiring protection action.",
    )

    if not scan_has_run():
        render_kpi_row(
            [
                ("Network Records Analyzed", f"{data['records_analyzed']:,}", "blue", None),
                ("Threats Requiring Action", "0", "slate", None),
                ("Threat Categories Detected", "0", "slate", None),
            ]
        )
        st.markdown("<div style='height:8px;'></div>", unsafe_allow_html=True)
        if st.button("Start Security Scan", type="primary", use_container_width=True):
            progress_slot = st.empty()
            status_slot = st.empty()
            for value in (20, 45, 70, 90, 100):
                with progress_slot.container():
                    render_progress(value, f"Analyzing network traffic — {value}%")
                status_slot.write("")
                time.sleep(0.12)
            perform_scan()
            st.rerun()
        return

    remaining = count_action_required()
    render_section_heading("Scan Result")
    if remaining > 0:
        render_kpi_row(
            [
                ("Threats Requiring Action", str(remaining), "red", None),
                ("Threat Categories Detected", str(data["category_count"]), "blue", None),
                ("Security Status", THREATS_DETECTED, "red", None),
            ]
        )
        st.markdown(
            f"<div class='cs-note'>{remaining} individual threat incidents require a "
            f"protection action, across {data['category_count']} attack categories.</div>",
            unsafe_allow_html=True,
        )
        if st.button("Review & Protect Threats", type="primary", use_container_width=True):
            go_to("Threat Protection")
            st.rerun()
    else:
        render_kpi_row(
            [
                ("Threats Requiring Action", "0", "green", None),
                ("Threat Categories Detected", str(data["category_count"]), "blue", None),
                ("Security Status", PROTECTION_ACTIVE, "green", None),
            ]
        )
        render_empty_state(
            "No Threats Requiring Action",
            "All detected threat incidents have already been handled. Protection is active.",
        )

    st.markdown("<div style='height:10px;'></div>", unsafe_allow_html=True)
    if st.button("Run Security Scan Again", use_container_width=True):
        perform_scan()
        st.rerun()


# =============================================================================
# 9. PAGE: THREAT PROTECTION
# =============================================================================

def render_incident_table(incidents: list[dict]) -> None:
    status_map = st.session_state.cs_incident_status
    headers = ["Incident ID", "Attack Type", "Severity", "Recommended Action", "Status"]
    rows = []
    for incident in incidents:
        status = status_map.get(incident["Incident ID"], ACTION_REQUIRED)
        rows.append(
            [
                incident["Incident ID"],
                html.escape(incident["Attack Type"]),
                severity_badge(incident["Severity"]),
                action_badge(incident["Recommended Action"]),
                status_badge(status),
            ]
        )
    render_html_table(headers, rows)


@st.dialog("Confirm Protection Action")
def protection_confirmation_dialog(incident: dict, action: str) -> None:
    st.markdown(f"**Incident ID:** {incident['Incident ID']}")
    st.markdown(f"**Attack Type:** {incident['Attack Type']}")
    st.markdown(f"**Severity:** {incident['Severity']}")
    st.divider()
    st.markdown(f"**Recommended Action:** {incident['Recommended Action']}")
    st.markdown(f"**Selected Action:** {action}")
    st.info(ACTION_DESCRIPTION[action])
    st.caption("Confirming this action will mark this threat incident as handled.")
    col_cancel, col_confirm = st.columns(2)
    with col_cancel:
        if st.button("Cancel", use_container_width=True, key="cancel_action_dialog"):
            st.session_state.cs_confirm_incident = None
            st.session_state.cs_confirm_action = None
            st.rerun()
    with col_confirm:
        if st.button("Confirm Action", type="primary", use_container_width=True, key="confirm_action_dialog"):
            apply_protection_action(incident, action)
            st.rerun()


def page_threat_protection(data: dict) -> None:
    incidents = data["incidents"]
    render_page_heading(
        "Threat Protection",
        "Review each detected threat incident and choose how CyberShield should respond.",
    )

    remaining = count_action_required()
    render_kpi_row(
        [
            ("Threats Requiring Action", str(remaining), "red" if remaining else "green", None),
            ("Threats Handled", str(count_handled()), "slate", None),
            (
                "Threat Categories",
                str(data["category_count"]) if scan_has_run() else "0",
                "blue",
                None,
            ),
        ]
    )

    if not scan_has_run():
        render_empty_state(
            "Scan Required",
            "Run a Network Scan before reviewing threats.",
        )
        if st.button("Go to Network Scan", type="primary"):
            go_to("Network Scan")
            st.rerun()
        return

    pending = action_required_incidents(incidents)

    if not pending:
        render_empty_state(
            "All Threats Handled",
            f"All {TARGET_INCIDENT_COUNT} detected threat incidents have been handled. "
            "Run another scan to verify the current protection state.",
        )
        if st.button("Run Security Scan", type="primary", use_container_width=True):
            go_to("Network Scan")
            st.rerun()
        return

    render_section_heading(f"Detected Threat Incidents ({len(pending)} pending)")
    render_incident_table(incidents)

    st.markdown("<div style='height:16px;'></div>", unsafe_allow_html=True)
    render_section_heading("Review a Threat")
    options = [i["Incident ID"] for i in pending]
    selected_id = st.selectbox("Select a threat requiring action", options)
    incident = incidents_by_id(incidents)[selected_id]

    st.markdown(
        f'<div class="cs-detail-grid">'
        f'<div><div class="cs-detail-label">Incident ID</div>'
        f'<div class="cs-detail-value">{incident["Incident ID"]}</div></div>'
        f'<div><div class="cs-detail-label">Attack Type</div>'
        f'<div class="cs-detail-value">{html.escape(incident["Attack Type"])}</div></div>'
        f'<div><div class="cs-detail-label">Severity</div>'
        f'<div class="cs-detail-value">{severity_badge(incident["Severity"])}</div></div>'
        f'<div><div class="cs-detail-label">Status</div>'
        f'<div class="cs-detail-value">{status_badge(ACTION_REQUIRED)}</div></div>'
        f"</div>",
        unsafe_allow_html=True,
    )

    st.markdown("<div style='height:10px;'></div>", unsafe_allow_html=True)
    render_card("Security Recommendation", SEVERITY_GUIDANCE[incident["Severity"]])
    st.markdown(
        f"<div class='cs-note'>Recommended action: "
        f"{action_badge(incident['Recommended Action'])}</div>",
        unsafe_allow_html=True,
    )

    render_section_heading("Protection Action Center")
    st.caption("Choose how CyberShield should respond to this threat. The recommended "
               "action is not applied automatically — you must confirm it.")
    selected_action = st.radio(
        "Protection Action",
        ACTIONS,
        index=ACTIONS.index(incident["Recommended Action"]),
        horizontal=True,
        key=f"action_choice_{selected_id}",
    )
    st.info(ACTION_DESCRIPTION[selected_action])
    if st.button(f"Apply {selected_action}", type="primary", use_container_width=True):
        st.session_state.cs_confirm_incident = selected_id
        st.session_state.cs_confirm_action = selected_action
        st.rerun()

    if st.session_state.get("cs_confirm_incident") == selected_id:
        protection_confirmation_dialog(incident, st.session_state.cs_confirm_action)


# =============================================================================
# 10. PAGE: PROTECTION CENTER
# =============================================================================

def page_protection_center(data: dict) -> None:
    render_page_heading(
        "Protection Center",
        "Overview of protection coverage across all detected threat incidents.",
    )

    total = TARGET_INCIDENT_COUNT if scan_has_run() else 0
    remaining = count_action_required()
    protected = count_protected()
    allowed = count_allowed()
    handled = count_handled()
    categories = data["category_count"] if scan_has_run() else 0

    render_kpi_row(
        [
            ("Total Threat Incidents", str(total), "slate", None),
            ("Threats Requiring Action", str(remaining), "red" if remaining else "green", None),
            ("Protected", str(protected), "green", None),
        ]
    )
    render_kpi_row(
        [
            ("Allowed", str(allowed), "slate", None),
            ("Handled", str(handled), "blue", None),
            ("Threat Categories", str(categories), "slate", None),
        ]
    )

    render_section_heading("Overall Protection Status")
    status = security_status()
    if status == SCAN_REQUIRED:
        render_empty_state("Scan Required", "Run a security scan to establish the current protection state.")
    elif status == PROTECTION_ACTIVE:
        render_card("Protection is Active", "Every detected threat incident has been handled. CyberShield continues to monitor the network.")
    else:
        render_card(
            "Action Required",
            f"{remaining} of {TARGET_INCIDENT_COUNT} threat incidents still need a protection "
            "action. Visit Threat Protection to review them.",
        )

    if scan_has_run():
        render_section_heading("Protection Policy")
        render_html_table(
            ["Severity", "Recommended Action", "Response"],
            [
                [severity_badge(sev), action_badge(SEVERITY_POLICY[sev]), html.escape(SEVERITY_GUIDANCE[sev])]
                for sev in SEVERITY_ORDER
            ],
        )


# =============================================================================
# 11. PAGE: PROTECTION HISTORY
# =============================================================================

def page_protection_history(data: dict) -> None:
    render_page_heading(
        "Protection History",
        "All protection actions taken during this session, most recent first.",
    )
    log = st.session_state.cs_action_log
    if not log:
        render_empty_state("No History", "No protection actions have been recorded yet.")
        return

    render_html_table(
        ["Time", "Incident ID", "Attack Type", "Severity", "Action", "Status"],
        [
            [
                html.escape(entry["Time"]),
                entry["Incident ID"],
                html.escape(entry["Attack Type"]),
                severity_badge(entry["Severity"]),
                action_badge(entry["Action"]),
                status_badge(entry["Status"]),
            ]
            for entry in log
        ],
    )
    st.markdown(
        f"<div class='cs-note'>{len(log)} action(s) recorded this session.</div>",
        unsafe_allow_html=True,
    )


# =============================================================================
# 12. PAGE: SECURITY ANALYTICS
# =============================================================================

PLOTLY_COLORWAY = [COLOR_NAVY, COLOR_BLUE, COLOR_LIGHT_BLUE, "#5B8DBF", "#2E4B6E", "#7FA8CC"]
SEVERITY_PLOTLY_COLORS = {"Critical": SEVERITY_COLORS["Critical"], "High": SEVERITY_COLORS["High"], "Medium": SEVERITY_COLORS["Medium"]}
ACTION_PLOTLY_COLORS = {"ISOLATE": SEVERITY_COLORS["Critical"], "BLOCK": SEVERITY_COLORS["High"], "RESTRICT": SEVERITY_COLORS["Medium"]}


def _plotly_unavailable_notice() -> None:
    st.warning("Plotly is not installed in this environment, so interactive charts cannot be drawn. "
               "Install `plotly` to enable the charts on this page.")


def page_security_analytics(data: dict) -> None:
    render_page_heading(
        "Security Analytics",
        "Model performance, threat-category analysis, and protection statistics "
        f"from the {DATASET_NAME} dataset and the trained CyberShield models.",
    )

    render_section_heading("Dataset & Detection Summary")
    traffic = data.get("traffic_summary")
    kpis = [
        ("Network Records Analyzed", f"{data['records_analyzed']:,}", "blue", "Flagged by the Protection Engine"),
        ("Attack Categories", str(data["category_count"]), "slate", None),
        ("Detection Model", DETECTION_MODEL, "slate", None),
        ("Protection Threshold", f"{PROTECTION_THRESHOLD:.2f}", "slate", f"Recall {PROTECTION_RECALL:.1%}"),
    ]
    render_kpi_row(kpis)

    if traffic:
        st.markdown(
            f"<div class='cs-note'>Underlying engineered dataset: {traffic['total']:,} network "
            f"records ({traffic['normal']:,} normal, {traffic['attack']:,} attack) after "
            "de-duplication.</div>",
            unsafe_allow_html=True,
        )

    if not PLOTLY_AVAILABLE:
        _plotly_unavailable_notice()
        return

    # ---- Attack category distribution (from the actual flagged records) ----
    render_section_heading("Attack Category Distribution")
    cat_df = (
        pd.DataFrame(
            {"Attack Type": list(data["category_counts"].keys()), "Records": list(data["category_counts"].values())}
        )
        .sort_values("Records", ascending=True)
    )
    fig_cat = px.bar(
        cat_df, x="Records", y="Attack Type", orientation="h",
        title="Flagged Records by Attack Category", text="Records",
        color_discrete_sequence=[COLOR_BLUE],
    )
    fig_cat.update_traces(textposition="outside", marker_line_width=0)
    st.plotly_chart(plotly_layout(fig_cat, height=420), use_container_width=True)

    col_a, col_b = st.columns(2)
    with col_a:
        render_section_heading("Threat Severity Distribution")
        severity_totals: dict[str, int] = {}
        for attack, count in data["category_counts"].items():
            sev = SEVERITY_BY_ATTACK.get(attack, "High")
            severity_totals[sev] = severity_totals.get(sev, 0) + count
        sev_df = pd.DataFrame(
            {"Severity": list(severity_totals.keys()), "Records": list(severity_totals.values())}
        )
        fig_sev = px.pie(
            sev_df, names="Severity", values="Records", hole=0.55,
            color="Severity", color_discrete_map=SEVERITY_PLOTLY_COLORS,
            title="Records by Severity",
        )
        fig_sev.update_traces(textinfo="label+percent")
        st.plotly_chart(plotly_layout(fig_sev, height=360), use_container_width=True)

    with col_b:
        render_section_heading("Protection Action Distribution")
        action_totals: dict[str, int] = {}
        for attack, count in data["category_counts"].items():
            sev = SEVERITY_BY_ATTACK.get(attack, "High")
            action = SEVERITY_POLICY.get(sev, "BLOCK")
            action_totals[action] = action_totals.get(action, 0) + count
        act_df = pd.DataFrame(
            {"Action": list(action_totals.keys()), "Records": list(action_totals.values())}
        )
        fig_act = px.pie(
            act_df, names="Action", values="Records", hole=0.55,
            color="Action", color_discrete_map=ACTION_PLOTLY_COLORS,
            title="Recommended Protection Actions",
        )
        fig_act.update_traces(textinfo="label+percent")
        st.plotly_chart(plotly_layout(fig_act, height=360), use_container_width=True)

    # ---- Session-level threat status (only meaningful once scanned) --------
    if scan_has_run():
        render_section_heading("This Session's Threat Status")
        status_counts = {
            ACTION_REQUIRED: count_action_required(),
            PROTECTED: count_protected(),
            ALLOWED: count_allowed(),
        }
        status_df = pd.DataFrame(
            {"Status": list(status_counts.keys()), "Incidents": list(status_counts.values())}
        )
        fig_status = px.bar(
            status_df, x="Status", y="Incidents", text="Incidents", title="Incident Status (This Session)",
            color="Status",
            color_discrete_map={ACTION_REQUIRED: STATUS_COLORS[ACTION_REQUIRED], PROTECTED: STATUS_COLORS[PROTECTED], ALLOWED: STATUS_COLORS[ALLOWED]},
        )
        fig_status.update_traces(textposition="outside")
        fig_status.update_layout(showlegend=False)
        st.plotly_chart(plotly_layout(fig_status, height=340), use_container_width=True)

    # ---- Model performance comparison --------------------------------------
    render_section_heading("Model Performance Comparison")
    model_df = pd.DataFrame(MODEL_RESULTS, columns=["Model"] + METRICS)
    model_long = model_df.melt(id_vars="Model", value_vars=METRICS, var_name="Metric", value_name="Score")
    fig_model = px.bar(
        model_long, x="Model", y="Score", color="Metric", barmode="group",
        title="Detection Model Comparison (test split)", color_discrete_sequence=PLOTLY_COLORWAY,
    )
    fig_model.update_yaxes(range=[0, 1])
    fig_model.update_layout(xaxis_tickangle=-30)
    st.plotly_chart(plotly_layout(fig_model, height=430), use_container_width=True)
    best_row = max(MODEL_RESULTS, key=lambda r: r[4])
    st.markdown(
        f"<div class='cs-note'>Best F1 score: <b>{best_row[0]}</b> ({best_row[4]:.4f}), "
        f"selected as the CyberShield detection model.</div>",
        unsafe_allow_html=True,
    )

    # ---- Hyperparameter tuning ---------------------------------------------
    render_section_heading("Hyperparameter Tuning")
    tuning_rows = [{"Version": v, **dict(zip(METRICS, s))} for v, s in TUNING_RESULTS.items()]
    tuning_df = pd.DataFrame(tuning_rows)
    tuning_long = tuning_df.melt(id_vars="Version", var_name="Metric", value_name="Score")
    fig_tuning = px.bar(
        tuning_long, x="Metric", y="Score", color="Version", barmode="group",
        title=f"{DETECTION_MODEL}: Before vs. After Tuning",
        color_discrete_sequence=[COLOR_LIGHT_BLUE, COLOR_NAVY],
    )
    fig_tuning.update_yaxes(range=[0, 1])
    st.plotly_chart(plotly_layout(fig_tuning, height=380), use_container_width=True)
    tuned_params = ", ".join(f"{k}={v}" for k, v in TUNED_DETECTION_PARAMETERS.items())
    st.markdown(f"<div class='cs-note'>Tuned parameters: {html.escape(tuned_params)}</div>", unsafe_allow_html=True)

    # ---- Detection threshold analysis --------------------------------------
    render_section_heading("Detection Threshold Analysis")
    threshold_df = pd.DataFrame(
        THRESHOLD_RESULTS, columns=["Threshold", "Accuracy", "Precision", "Recall", "F1 Score", "False Negatives", "False Positives"]
    )
    col_t1, col_t2 = st.columns(2)
    with col_t1:
        fig_recall = px.line(
            threshold_df, x="Threshold", y="Recall", markers=True,
            title="Recall vs. Detection Threshold", color_discrete_sequence=[COLOR_BLUE],
        )
        fig_recall.add_vline(x=PROTECTION_THRESHOLD, line_dash="dash", line_color=COLOR_NAVY)
        fig_recall.update_yaxes(range=[0.85, 1.0])
        st.plotly_chart(plotly_layout(fig_recall, height=340), use_container_width=True)
    with col_t2:
        fn_fp_long = threshold_df.melt(
            id_vars="Threshold", value_vars=["False Negatives", "False Positives"],
            var_name="Metric", value_name="Count",
        )
        fig_fn = px.bar(
            fn_fp_long, x="Threshold", y="Count", color="Metric", barmode="group",
            title="False Negatives vs. False Positives",
            color_discrete_sequence=[SEVERITY_COLORS["Critical"], COLOR_GREY],
        )
        st.plotly_chart(plotly_layout(fig_fn, height=340), use_container_width=True)
    st.markdown(
        f"<div class='cs-note'>Threshold {PROTECTION_THRESHOLD:.2f} was selected to prioritize "
        f"recall ({PROTECTION_RECALL:.1%}) over precision, since a missed attack is costlier "
        "than an additional alert in a protection context.</div>",
        unsafe_allow_html=True,
    )

    # ---- Attack classification performance ---------------------------------
    render_section_heading("Attack Classification Performance")
    render_kpi_row(
        [
            ("Classifier", CLASSIFICATION_MODEL, "slate", None),
            ("Accuracy", f"{ATTACK_CLASSIFIER_ACCURACY:.1%}", "blue", None),
            ("Weighted F1", f"{ATTACK_CLASSIFIER_WEIGHTED_F1:.3f}", "blue", None),
        ]
    )
    report_df = pd.DataFrame(
        ATTACK_CLASSIFIER_REPORT, columns=["Attack Category", "Precision", "Recall", "F1 Score", "Support"]
    )
    render_html_table(
        ["Attack Category", "Precision", "Recall", "F1 Score", "Support"],
        [
            [html.escape(r["Attack Category"]), f"{r['Precision']:.2f}", f"{r['Recall']:.2f}", f"{r['F1 Score']:.2f}", f"{r['Support']:,}"]
            for r in report_df.to_dict("records")
        ],
        numeric_cols={1, 2, 3, 4},
    )
    st.markdown(
        "<div class='cs-note'>Rare categories (Backdoor, Worms) are harder to classify "
        "correctly due to few training examples — a limitation of the source dataset, "
        "not the dashboard.</div>",
        unsafe_allow_html=True,
    )

    # ---- Feature importance --------------------------------------------------
    render_section_heading("Top Features (Random Forest Importance)")
    feat_df = pd.DataFrame(FEATURE_IMPORTANCE, columns=["Feature", "Importance"]).sort_values("Importance")
    fig_feat = px.bar(
        feat_df, x="Importance", y="Feature", orientation="h",
        title="Feature Importance Used for Attack Detection",
        color_discrete_sequence=[COLOR_NAVY],
    )
    st.plotly_chart(plotly_layout(fig_feat, height=430), use_container_width=True)

    # ---- Data preparation summary --------------------------------------------
    render_section_heading("Data Preparation Summary")
    render_html_table(
        ["Step", "Value"],
        [[html.escape(step), html.escape(value)] for step, value in DATA_PREPARATION_SUMMARY],
    )


# =============================================================================
# 13. MAIN
# =============================================================================

PAGE_RENDERERS: dict[str, Callable[[dict], None]] = {
    "Home": page_home,
    "Network Scan": page_network_scan,
    "Threat Protection": page_threat_protection,
    "Protection Center": page_protection_center,
    "Protection History": page_protection_history,
    "Security Analytics": page_security_analytics,
}


def main() -> None:
    st.set_page_config(
        page_title=f"{APP_NAME} | {APP_SUBTITLE}",
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="expanded",
    )
    inject_css()

    data = get_project_data()
    if data.get("error") == "missing_database":
        render_app_header()
        st.error(
            f"Could not find `{DATABASE_FILENAME}`. Place the CyberShield database next to "
            f"`dashboard.py`, or set the `{DATABASE_ENV_VARIABLE}` environment variable to its path. "
            "The dashboard cannot display real project data without it."
        )
        st.stop()
    if data.get("error") == "query_failed":
        render_app_header()
        st.error(
            "The CyberShield database was found, but the `protection_incidents` table could not "
            f"be read. Details: {data.get('detail')}"
        )
        st.stop()
    if data.get("error") == "no_incidents":
        render_app_header()
        st.error(
            "The `protection_incidents` table in the CyberShield database is empty. "
            "Re-run the Protection Engine notebook to populate it before using this dashboard."
        )
        st.stop()

    init_session_state(data["incidents"])
    render_sidebar(data)

    if st.session_state.get("cs_reset_requested"):
        reset_confirmation_dialog(data["incidents"])

    render_app_header()
    render_flash_message()

    renderer = PAGE_RENDERERS.get(st.session_state.cs_page, page_home)
    renderer(data)


if __name__ == "__main__":
    main()
