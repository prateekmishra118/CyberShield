import streamlit as st
import pandas as pd
import plotly.express as px
from datetime import datetime


# ============================================================
# PAGE CONFIGURATION
# ============================================================

st.set_page_config(
    page_title="CyberShield Security Center",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)


# ============================================================
# PROJECT CONFIGURATION
# ============================================================

TOTAL_NETWORK_RECORDS = 145222

# There are only 9 different attack categories
NUMBER_OF_THREAT_CATEGORIES = 9

# After a scan, 15 individual threat incidents are detected.
# These incidents belong to the 9 categories above.
TOTAL_DETECTED_THREATS = 15

DETECTION_MODEL = "HistGradientBoosting"
CLASSIFICATION_MODEL = "Random Forest"
PROTECTION_THRESHOLD = 0.30

PROTECTION_RECALL = 0.9705026049647564
TUNED_F1 = 0.888399

DEFAULT_FALSE_NEGATIVES = 1366
PROTECTION_FALSE_NEGATIVES = 385

FN_REDUCTION = (
    DEFAULT_FALSE_NEGATIVES -
    PROTECTION_FALSE_NEGATIVES
)

FN_REDUCTION_PERCENT = (
    FN_REDUCTION / DEFAULT_FALSE_NEGATIVES
) * 100


# ============================================================
# ATTACK CATEGORIES
# ============================================================

attack_categories = pd.DataFrame({
    "Attack Type": [
        "Exploits",
        "Fuzzers",
        "Shellcode",
        "DoS",
        "Generic",
        "Analysis",
        "Worms",
        "Backdoor",
        "Unknown"
    ]
})



incident_data = pd.DataFrame({

    "Incident ID": [
        "EXP-001",
        "FUZ-002",
        "SHL-003",
        "DOS-004",
        "GEN-005",
        "ANA-006",
        "WOR-007",
        "BAC-008",
        "UNK-009",
        "EXP-010",
        "FUZ-011",
        "DOS-012",
        "GEN-013",
        "SHL-014",
        "BAC-015"
    ],

    "Attack Type": [
        "Exploits",
        "Fuzzers",
        "Shellcode",
        "DoS",
        "Generic",
        "Analysis",
        "Worms",
        "Backdoor",
        "Unknown",
        "Exploits",
        "Fuzzers",
        "DoS",
        "Generic",
        "Shellcode",
        "Backdoor"
    ],

    "Severity": [
        "Critical",
        "Medium",
        "Critical",
        "High",
        "Medium",
        "Medium",
        "High",
        "Critical",
        "Medium",
        "High",
        "Medium",
        "Critical",
        "Medium",
        "High",
        "Critical"
    ]
})


# ============================================================
# PROTECTION POLICY
# ============================================================

PROTECTION_POLICY = {
    "Critical": "ISOLATE",
    "High": "BLOCK",
    "Medium": "RESTRICT"
}


# ============================================================
# PROTECTION RESPONSE
# ============================================================

PROTECTION_RESPONSE = {

    "ALLOW":
        "Allow the connection and continue monitoring.",

    "RESTRICT":
        "Restrict the suspicious connection and continue monitoring.",

    "BLOCK":
        "Block the suspicious connection.",

    "ISOLATE":
        "Immediately isolate the suspicious connection."
}


# ============================================================
# SECURITY RECOMMENDATIONS
# ============================================================

SECURITY_SUGGESTIONS = {

    "Critical":
        "Isolate the affected connection immediately and investigate the source.",

    "High":
        "Block the suspicious connection and review related network activity.",

    "Medium":
        "Restrict the connection and monitor it for additional suspicious behavior."
}


# ============================================================
# ADD RECOMMENDED ACTION
# ============================================================

incident_data["Suggested Action"] = (
    incident_data["Severity"].map(PROTECTION_POLICY)
)


# ============================================================
# SESSION STATE
# ============================================================

if "page" not in st.session_state:
    st.session_state.page = "Home"

if "scan_complete" not in st.session_state:
    st.session_state.scan_complete = False

if "scan_count" not in st.session_state:
    st.session_state.scan_count = 0

if "action_history" not in st.session_state:
    st.session_state.action_history = []

if "incident_status" not in st.session_state:
    # No threats exist in the dashboard state until a scan is completed.
    st.session_state.incident_status = {
        incident_id: "NOT SCANNED"
        for incident_id in incident_data["Incident ID"]
    }


# ============================================================
# HELPER FUNCTIONS
# ============================================================

def count_threats_requiring_action():

    # Before the first scan, there are no detected threats requiring action.
    if not st.session_state.scan_complete:
        return 0

    return sum(
        status == "ACTION REQUIRED"
        for status in st.session_state.incident_status.values()
    )


def count_protected():

    if not st.session_state.scan_complete:
        return 0

    return sum(
        status == "PROTECTED"
        for status in st.session_state.incident_status.values()
    )


def count_allowed():

    if not st.session_state.scan_complete:
        return 0

    return sum(
        status == "ALLOWED"
        for status in st.session_state.incident_status.values()
    )


def count_handled():

    return (
        count_protected()
        +
        count_allowed()
    )


def all_threats_handled():

    return count_threats_requiring_action() == 0


def get_incident_status(incident_id):

    return st.session_state.incident_status.get(
        incident_id,
        "ACTION REQUIRED"
    )


# ============================================================
# RESET SIMULATION
# ============================================================

def reset_simulation():

    st.session_state.action_history = []

    # Reset to a clean state: no threats are detected before a new scan.
    st.session_state.incident_status = {
        incident_id: "NOT SCANNED"
        for incident_id in incident_data["Incident ID"]
    }

    st.session_state.scan_complete = False
    st.session_state.scan_count = 0
    st.session_state.page = "Home"

    if "action_message" in st.session_state:
        del st.session_state.action_message


# ============================================================
# PERFORM SECURITY SCAN
# ============================================================

def perform_scan():

    # A completed scan creates the detected-threat queue.
    # Running a new scan starts a fresh detection state.
    st.session_state.incident_status = {
        incident_id: "ACTION REQUIRED"
        for incident_id in incident_data["Incident ID"]
    }

    st.session_state.scan_complete = True
    st.session_state.scan_count += 1


# ============================================================
# EXECUTE PROTECTION ACTION
# ============================================================

def execute_action(
    incident_id,
    attack_type,
    severity,
    action
):

    timestamp = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    if action == "ALLOW":
        status = "ALLOWED"
    else:
        status = "PROTECTED"

    st.session_state.incident_status[
        incident_id
    ] = status

    history_entry = {

        "Time": timestamp,

        "Incident ID": incident_id,

        "Attack Type": attack_type,

        "Severity": severity,

        "Action": action,

        "Status": status
    }

    st.session_state.action_history.insert(
        0,
        history_entry
    )


# ============================================================
# CONFIRMATION POPUP
# ============================================================

@st.dialog("Confirm Protection Action")
def confirmation_dialog(
    incident_id,
    attack_type,
    severity,
    suggested_action,
    selected_action
):

    st.subheader("Review Protection Action")

    st.write(
        f"**Incident ID:** {incident_id}"
    )

    st.write(
        f"**Attack Type:** {attack_type}"
    )

    st.write(
        f"**Severity:** {severity}"
    )

    st.divider()

    st.write(
        f"**Recommended Action:** {suggested_action}"
    )

    st.write(
        f"**Selected Action:** {selected_action}"
    )

    st.info(
        PROTECTION_RESPONSE[selected_action]
    )

    st.warning(
        "Confirming this action will mark this individual "
        "threat incident as handled."
    )

    st.caption(
        SECURITY_SUGGESTIONS[severity]
    )

    col1, col2 = st.columns(2)

    with col1:

        if st.button(
            "Cancel",
            use_container_width=True
        ):

            st.rerun()

    with col2:

        if st.button(
            "Confirm Action",
            type="primary",
            use_container_width=True
        ):

            execute_action(
                incident_id,
                attack_type,
                severity,
                selected_action
            )

            st.session_state.action_message = (
                f"{selected_action} applied to "
                f"{attack_type} ({incident_id})."
            )

            st.rerun()


# ============================================================
# GLOBAL DARK THEME
# ============================================================

st.markdown(
    """
    <style>

    [data-testid="stAppViewContainer"] {
        background-color: #061321;
    }

    [data-testid="stSidebar"] {
        background-color: #07111f;
    }

    [data-testid="stHeader"] {
        background-color: #061321;
    }

    .block-container {
        max-width: 1500px;
        padding-top: 2rem;
        padding-bottom: 3rem;
    }

    div[data-testid="stMetric"] {
        background-color: #071a2c;
        border: 1px solid #183957;
        border-radius: 12px;
        padding: 16px;
    }

    div[data-testid="stMetricValue"] {
        font-size: 30px;
        font-weight: 700;
    }

    div[data-testid="stMetricLabel"] {
        font-size: 15px;
    }

    button {
        border-radius: 8px !important;
    }

    .status-card {
        padding: 28px;
        border-radius: 15px;
        margin-bottom: 25px;
    }

    .active-status {
        border: 1px solid #00c853;
        background: linear-gradient(
            90deg,
            #03241e,
            #061b1e
        );
    }

    .danger-status {
        border: 1px solid #ff3d4d;
        background: linear-gradient(
            90deg,
            #2b0c12,
            #17111a
        );
    }

    .status-title {
        font-size: 28px;
        font-weight: 700;
    }

    .status-description {
        font-size: 16px;
        margin-top: 8px;
    }

    .quick-card {
        padding: 18px;
        border: 1px solid #21496a;
        border-radius: 12px;
        background-color: #071a2c;
        min-height: 180px;
    }

    </style>
    """,
    unsafe_allow_html=True
)


# ============================================================
# SIDEBAR
# ============================================================

with st.sidebar:

    st.title("🛡️ CyberShield")

    st.caption(
        "Network Threat Detection & Protection"
    )

    st.divider()

    st.subheader("Security Center")

    navigation_options = [
        "Home",
        "Network Scan",
        "Threat Protection",
        "Protection Center",
        "Protection History",
        "Security Analytics"
    ]

    selected_page = st.radio(
        "Navigation",
        navigation_options,
        index=navigation_options.index(
            st.session_state.page
        ),
        label_visibility="collapsed"
    )

    st.session_state.page = selected_page

    st.divider()

    st.subheader("System Status")

    st.success(
        "SYSTEM OPERATIONAL"
    )

    st.caption(
        f"Detection Model: {DETECTION_MODEL}"
    )

    st.caption(
        f"Classification Model: {CLASSIFICATION_MODEL}"
    )

    st.caption(
        f"Protection Threshold: "
        f"{PROTECTION_THRESHOLD:.2f}"
    )

    st.divider()

    st.caption(
        "CyberShield security operations "
        "simulation environment."
    )

    st.divider()

    if st.button(
        "↻ Reset Current Session",
        use_container_width=True
    ):

        reset_simulation()
        st.rerun()


# ============================================================
# HEADER
# ============================================================

st.markdown(
    '<div style="margin-bottom: 5px;">'
    '<div style="font-size:52px; font-weight:800; line-height:1.1; color:white; margin-bottom:10px;">'
    'CyberShield'
    '</div>'
    '<div style="font-size:26px; font-weight:700; line-height:1.2; color:#b8c4d4;">'
    'Network Threat Detection & Protection'
    '</div>'
    '</div>',
    unsafe_allow_html=True
)

# ============================================================
# ACTION MESSAGE
# ============================================================

if "action_message" in st.session_state:

    st.success(
        st.session_state.action_message
    )

    del st.session_state.action_message


# ============================================================
# HOME PAGE
# ============================================================

if st.session_state.page == "Home":

    threats_remaining = (
        count_threats_requiring_action()
    )

    handled = count_handled()


    # ========================================================
    # SECURITY STATUS
    # ========================================================

    if (
        st.session_state.scan_complete
        and
        threats_remaining > 0
    ):

        st.markdown(
            """
            <div class="status-card danger-status">
                <div class="status-title">
                    🔴 Threats detected
                </div>
                <div class="status-description">
                    CyberShield detected threats requiring
                    protection action.
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )

    else:

        st.markdown(
            """
            <div class="status-card active-status">
                <div class="status-title">
                    🟢 Protection is active
                </div>
                <div class="status-description">
                    CyberShield protection services are
                    operational and monitoring the system.
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )


    if st.session_state.scan_complete:

        st.subheader("Security Overview")

        c1, c2, c3, c4 = st.columns(4)

        with c1:

            st.metric(
                "Network Records Analyzed",
                f"{TOTAL_NETWORK_RECORDS:,}"
            )

        with c2:

            st.metric(
                "Threat Categories Detected",
                NUMBER_OF_THREAT_CATEGORIES
            )

        with c3:

            # This is the number of individual threat incidents
            # still requiring action.
            st.metric(
                "Threats Requiring Action",
                threats_remaining
            )

        with c4:

            st.metric(
                "Threats Handled",
                handled
            )


    # ========================================================
    # QUICK ACTIONS
    # ========================================================

    st.subheader("Quick Actions")

    q1, q2, q3 = st.columns(3)

    with q1:

        st.write("### 🔍 Network Scan")

        st.write(
            "Scan network traffic for potential threats."
        )

        if st.button(
            "Start Scan",
            key="home_scan",
            use_container_width=True
        ):

            st.session_state.page = "Network Scan"
            st.rerun()


    with q2:

        st.write("### 🛡️ Threat Protection")

        st.write(
            "Review detected threats and choose "
            "protection actions."
        )

        if st.button(
            "Review Threats",
            key="home_protection",
            use_container_width=True
        ):

            st.session_state.page = "Threat Protection"
            st.rerun()


    with q3:

        st.write("### ⚙️ Protection Center")

        st.write(
            "View protection policies and "
            "security controls."
        )

        if st.button(
            "Open Center",
            key="home_center",
            use_container_width=True
        ):

            st.session_state.page = "Protection Center"
            st.rerun()


    q4, q5, q6 = st.columns(3)


    with q4:

        st.write("### 📋 Protection History")

        st.write(
            "View actions performed during this session."
        )

        if st.button(
            "View History",
            key="home_history",
            use_container_width=True
        ):

            st.session_state.page = "Protection History"
            st.rerun()


    with q5:

        st.write("### 📊 Security Analytics")

        st.write(
            "Review model performance and "
            "detection analysis."
        )

        if st.button(
            "View Analytics",
            key="home_analytics",
            use_container_width=True
        ):

            st.session_state.page = "Security Analytics"
            st.rerun()


    with q6:

        st.write("### 🔐 Protection Status")

        if (
            all_threats_handled()
            and
            st.session_state.scan_complete
        ):

            st.success(
                "All detected threats handled."
            )

        elif st.session_state.scan_complete:

            st.warning(
                f"{threats_remaining} individual threats "
                "still require action."
            )

        else:

            st.info(
                "Run a scan to determine the "
                "current threat state."
            )


    # ========================================================
    # MAIN HOME ACTION
    # ========================================================

    st.divider()

    if (
        st.session_state.scan_complete
        and
        threats_remaining > 0
    ):

        if st.button(
            "🚨 Review Detected Threats",
            type="primary",
            use_container_width=True
        ):

            st.session_state.page = "Threat Protection"
            st.rerun()

    else:

        if st.button(
            "🔍 Start Security Scan",
            type="primary",
            use_container_width=True
        ):

            st.session_state.page = "Network Scan"
            st.rerun()


    # ========================================================
    # SECURITY SUGGESTIONS
    # ========================================================

    st.subheader("Security Suggestions")

    s1, s2, s3 = st.columns(3)

    with s1:

        st.info(
            "Keep network monitoring enabled "
            "and review new detections promptly."
        )

    with s2:

        st.info(
            "Use BLOCK or ISOLATE for "
            "high-risk network activity."
        )

    with s3:

        st.info(
            "Review Protection History after "
            "handling detected threats."
        )


# ============================================================
# NETWORK SCAN
# ============================================================

elif st.session_state.page == "Network Scan":

    st.header("🔍 Network Scan")

    st.write(
        "Run a security scan against the "
        "available network records."
    )

    st.divider()


    # ========================================================
    # BEFORE SCAN
    # ========================================================

    if not st.session_state.scan_complete:

        st.subheader("Ready to Scan")

        st.metric(
            "Network Records Available",
            f"{TOTAL_NETWORK_RECORDS:,}"
        )

        if st.button(
            "🔍 Start Security Scan",
            type="primary",
            use_container_width=True
        ):

            progress = st.progress(0)
            status = st.empty()

            for value in range(0, 101, 10):

                progress.progress(value)

                status.write(
                    f"Scanning network traffic... "
                    f"{value}%"
                )

            perform_scan()

            status.success(
                "Security scan completed. "
                "15 threat incidents detected."
            )

            st.rerun()


    # ========================================================
    # AFTER SCAN
    # ========================================================

    else:

        threats_remaining = (
            count_threats_requiring_action()
        )

        st.subheader("Scan Result")


        if threats_remaining > 0:

            st.error(
                "🔴 Threats Detected"
            )

            st.metric(
                "Threats Requiring Action",
                threats_remaining
            )

            st.write(
                f"{threats_remaining} individual threat "
                f"incidents require protection action."
            )

            st.caption(
                f"These incidents belong to "
                f"{NUMBER_OF_THREAT_CATEGORIES} attack categories."
            )

            if st.button(
                "🚨 Review & Protect Threats",
                type="primary",
                use_container_width=True
            ):

                st.session_state.page = "Threat Protection"
                st.rerun()

        else:

            st.success(
                "🟢 No Threats Requiring Action"
            )

            st.metric(
                "Threats Requiring Action",
                0
            )

            st.write(
                "All detected threat incidents have "
                "already been handled."
            )

            st.info(
                "The network is currently in a protected state."
            )


        st.divider()

        if st.button(
            "↻ Run Security Scan Again",
            use_container_width=True
        ):

            perform_scan()
            st.rerun()


# ============================================================
# THREAT PROTECTION
# ============================================================

elif st.session_state.page == "Threat Protection":

    st.header("🛡️ Threat Protection")

    st.write(
        "Review each detected threat incident and "
        "choose how CyberShield should respond."
    )

    st.divider()

    threats_remaining = (
        count_threats_requiring_action()
    )

    handled = count_handled()


    # ========================================================
    # TOP COUNTERS
    # ========================================================

    c1, c2, c3 = st.columns(3)

    with c1:

        st.metric(
            "Threats Requiring Action",
            threats_remaining
        )

    with c2:

        st.metric(
            "Threats Handled",
            handled
        )

    with c3:

        st.metric(
            "Threat Categories",
            NUMBER_OF_THREAT_CATEGORIES
            if st.session_state.scan_complete
            else 0
        )


    st.divider()


    # ========================================================
    # NO SCAN
    # ========================================================

    if not st.session_state.scan_complete:

        st.warning(
            "Run a Network Scan before reviewing threats."
        )

        if st.button(
            "Go to Network Scan",
            type="primary"
        ):

            st.session_state.page = "Network Scan"
            st.rerun()


    # ========================================================
    # ALL HANDLED
    # ========================================================

    elif threats_remaining == 0:

        st.success(
            "🟢 Protection Complete"
        )

        st.subheader(
            f"All {TOTAL_DETECTED_THREATS} detected threat incidents have been handled."
        )

        a1, a2, a3 = st.columns(3)

        with a1:

            st.metric(
                "Requiring Action",
                0
            )

        with a2:

            st.metric(
                "Protected",
                count_protected()
            )

        with a3:

            st.metric(
                "Allowed",
                count_allowed()
            )

        st.info(
            "Run another security scan to verify "
            "the current protection state."
        )

        if st.button(
            "🔍 Run Security Scan",
            type="primary",
            use_container_width=True
        ):

            st.session_state.page = "Network Scan"
            st.rerun()


    # ========================================================
    # THREAT QUEUE
    # ========================================================

    else:

        st.subheader(
            "Detected Threat Incidents"
        )

        display_data = incident_data.copy()

        display_data["Status"] = (
            display_data["Incident ID"].map(
                st.session_state.incident_status
            )
        )

        st.dataframe(
            display_data[
                [
                    "Incident ID",
                    "Attack Type",
                    "Severity",
                    "Suggested Action",
                    "Status"
                ]
            ],
            use_container_width=True,
            hide_index=True
        )

        st.divider()


        # ====================================================
        # ONLY UNHANDLED THREATS
        # ====================================================

        action_required_ids = [

            incident_id

            for incident_id, status

            in st.session_state.incident_status.items()

            if status == "ACTION REQUIRED"
        ]


        if len(action_required_ids) == 0:

            st.success(
                "All threat incidents have been handled."
            )

        else:

            selected_id = st.selectbox(
                "Select a threat requiring action",
                action_required_ids
            )

            selected_row = incident_data[
                incident_data["Incident ID"]
                ==
                selected_id
            ].iloc[0]

            attack_type = selected_row[
                "Attack Type"
            ]

            severity = selected_row[
                "Severity"
            ]

            suggested_action = selected_row[
                "Suggested Action"
            ]


            # ================================================
            # THREAT DETAILS
            # ================================================

            st.subheader(
                "Threat Details"
            )

            d1, d2, d3, d4 = st.columns(4)

            with d1:

                st.write("**Incident ID**")

                st.write(
                    selected_id
                )

            with d2:

                st.write("**Attack Type**")

                st.write(
                    attack_type
                )

            with d3:

                st.write("**Severity**")

                if severity == "Critical":

                    st.error(severity)

                elif severity == "High":

                    st.warning(severity)

                else:

                    st.info(severity)

            with d4:

                st.write("**Status**")

                st.warning(
                    "ACTION REQUIRED"
                )


            st.divider()


            # ================================================
            # SECURITY RECOMMENDATION
            # ================================================

            st.subheader(
                "Security Recommendation"
            )

            st.info(
                SECURITY_SUGGESTIONS[severity]
            )

            st.write(
                f"Recommended action: "
                f"**{suggested_action}**"
            )


            # ================================================
            # PROTECTION ACTION CENTER
            # ================================================

            st.subheader(
                "⚡ Protection Action Center"
            )

            st.caption(
                "Choose how CyberShield should "
                "respond to this threat."
            )

            actions = [
                "ALLOW",
                "RESTRICT",
                "BLOCK",
                "ISOLATE"
            ]

            selected_action = st.radio(
                "Protection Action",
                actions,
                index=actions.index(
                    suggested_action
                ),
                horizontal=True
            )

            st.info(
                PROTECTION_RESPONSE[
                    selected_action
                ]
            )

            if st.button(
                f"🛡️ Apply {selected_action}",
                type="primary",
                use_container_width=True
            ):

                confirmation_dialog(
                    selected_id,
                    attack_type,
                    severity,
                    suggested_action,
                    selected_action
                )


# ============================================================
# PROTECTION CENTER
# ============================================================

elif st.session_state.page == "Protection Center":

    st.header("⚙️ Protection Center")

    st.write(
        "Manage the protection policies used "
        "by CyberShield."
    )

    st.divider()


    # ========================================================
    # CURRENT PROTECTION STATUS
    # ========================================================

    st.subheader(
        "Current Protection Status"
    )

    c1, c2, c3 = st.columns(3)

    with c1:

        st.metric(
            "Threats Requiring Action",
            count_threats_requiring_action()
            if st.session_state.scan_complete
            else 0
        )

    with c2:

        st.metric(
            "Threats Protected",
            count_protected()
            if st.session_state.scan_complete
            else 0
        )

    with c3:

        st.metric(
            "Threats Allowed",
            count_allowed()
            if st.session_state.scan_complete
            else 0
        )

    st.divider()


    # ========================================================
    # PROTECTION POLICY
    # ========================================================

    st.subheader(
        "Protection Policy"
    )

    policy_data = pd.DataFrame({

        "Severity": [
            "Critical",
            "High",
            "Medium"
        ],

        "Recommended Action": [
            "ISOLATE",
            "BLOCK",
            "RESTRICT"
        ],

        "Purpose": [
            "Immediately isolate high-risk activity.",
            "Block suspicious network activity.",
            "Restrict and monitor suspicious activity."
        ]
    })

    st.dataframe(
        policy_data,
        use_container_width=True,
        hide_index=True
    )

    st.divider()


    # ========================================================
    # AVAILABLE ACTIONS
    # ========================================================

    st.subheader(
        "Available Protection Actions"
    )

    a1, a2, a3, a4 = st.columns(4)

    with a1:

        st.write("### 🟢 ALLOW")

        st.write(
            "Allow the connection and "
            "continue monitoring."
        )

    with a2:

        st.write("### 🟡 RESTRICT")

        st.write(
            "Restrict and monitor the connection."
        )

    with a3:

        st.write("### 🔴 BLOCK")

        st.write(
            "Block the suspicious connection."
        )

    with a4:

        st.write("### 🛡️ ISOLATE")

        st.write(
            "Immediately isolate the connection."
        )


# ============================================================
# PROTECTION HISTORY
# ============================================================

elif st.session_state.page == "Protection History":

    st.header("📋 Protection History")

    st.write(
        "Protection actions performed during "
        "the current dashboard session."
    )

    st.divider()


    if len(
        st.session_state.action_history
    ) == 0:

        st.info(
            "No protection actions have been "
            "executed yet."
        )

    else:

        history_df = pd.DataFrame(
            st.session_state.action_history
        )

        st.dataframe(
            history_df,
            use_container_width=True,
            hide_index=True
        )

        st.divider()

        h1, h2, h3 = st.columns(3)

        with h1:

            st.metric(
                "Actions Executed",
                len(
                    st.session_state.action_history
                )
            )

        with h2:

            st.metric(
                "Protected",
                count_protected()
            )

        with h3:

            st.metric(
                "Allowed",
                count_allowed()
            )

        st.divider()

        if st.button(
            "Reset Protection Simulation",
            type="secondary"
        ):

            reset_simulation()
            st.rerun()


# ============================================================
# SECURITY ANALYTICS
# ============================================================

elif st.session_state.page == "Security Analytics":

    st.header("📊 Security Analytics")

    st.write(
        "Model performance, threat-category "
        "analysis and protection optimization."
    )

    st.divider()


    # ========================================================
    # NETWORK SUMMARY
    # ========================================================

    st.subheader(
        "Network Analysis"
    )

    n1, n2, n3 = st.columns(3)

    with n1:

        st.metric(
            "Network Records Analyzed",
            f"{TOTAL_NETWORK_RECORDS:,}"
        )

    with n2:

        st.metric(
            "Threat Categories",
            NUMBER_OF_THREAT_CATEGORIES
        )

    with n3:

        st.metric(
            "Protection Threshold",
            f"{PROTECTION_THRESHOLD:.2f}"
        )

    st.divider()


    # ========================================================
    # THREAT CATEGORY DISTRIBUTION
    # ========================================================

    st.subheader(
        "Threat Category Distribution"
    )

    category_chart_data = attack_categories.copy()

    category_chart_data["Categories"] = 1

    fig_attack = px.bar(
        category_chart_data,
        x="Attack Type",
        y="Categories",
        text="Categories",
        title="Nine Threat Categories"
    )

    fig_attack.update_traces(
        textposition="outside"
    )

    fig_attack.update_yaxes(
        dtick=1,
        range=[0, 1.5],
        title="Threat Categories"
    )

    fig_attack.update_layout(
        template="plotly_dark",
        height=430
    )

    st.plotly_chart(
        fig_attack,
        use_container_width=True
    )

    st.divider()


    # ========================================================
    # SEVERITY DISTRIBUTION
    # ========================================================

    st.subheader(
        "Threat Severity Distribution"
    )

    severity_data = pd.DataFrame({

        "Severity": [
            "Critical",
            "Medium",
            "High"
        ],

        "Threat Categories": [
            3,
            4,
            2
        ]
    })

    fig_severity = px.pie(
        severity_data,
        names="Severity",
        values="Threat Categories",
        hole=0.55,
        title="Nine Threat Categories by Severity"
    )

    fig_severity.update_layout(
        template="plotly_dark",
        height=430
    )

    st.plotly_chart(
        fig_severity,
        use_container_width=True
    )

    st.divider()


    # ========================================================
    # MODEL PERFORMANCE
    # ========================================================

    st.subheader(
        "Model Performance"
    )

    model_performance = pd.DataFrame({

        "Metric": [
            "Accuracy",
            "Precision",
            "Recall",
            "F1 Score"
        ],

        "Score": [
            0.8971,
            0.8829,
            0.9537,
            0.8868
        ],

        "Best Model": [
            "HistGradientBoosting",
            "Random Forest",
            "Linear SVM",
            "HistGradientBoosting"
        ]
    })

    fig_model = px.bar(
        model_performance,
        x="Metric",
        y="Score",
        color="Best Model",
        text="Score",
        title="Best Model by Evaluation Metric"
    )

    fig_model.update_traces(
        texttemplate="%{text:.4f}",
        textposition="outside"
    )

    fig_model.update_yaxes(
        range=[0, 1]
    )

    fig_model.update_layout(
        template="plotly_dark",
        height=450
    )

    st.plotly_chart(
        fig_model,
        use_container_width=True
    )

    st.divider()


    # ========================================================
    # HYPERPARAMETER TUNING
    # ========================================================

    st.subheader(
        "Hyperparameter Tuning"
    )

    tuning = pd.DataFrame({

        "Version": [
            "Before Tuning",
            "After Tuning"
        ],

        "Accuracy": [
            0.897091,
            0.898915
        ],

        "Precision": [
            0.876863,
            0.881563
        ],

        "Recall": [
            0.896951,
            0.895342
        ],

        "F1 Score": [
            0.886793,
            0.888399
        ]
    })

    tuning_long = tuning.melt(
        id_vars="Version",
        var_name="Metric",
        value_name="Score"
    )

    fig_tuning = px.bar(
        tuning_long,
        x="Metric",
        y="Score",
        color="Version",
        barmode="group",
        text="Score",
        title="Before vs After Hyperparameter Tuning"
    )

    fig_tuning.update_traces(
        texttemplate="%{text:.4f}",
        textposition="outside"
    )

    fig_tuning.update_yaxes(
        range=[0, 1]
    )

    fig_tuning.update_layout(
        template="plotly_dark",
        height=450
    )

    st.plotly_chart(
        fig_tuning,
        use_container_width=True
    )

    st.divider()


    # ========================================================
    # THRESHOLD ANALYSIS
    # ========================================================

    st.subheader(
        "Detection Threshold Analysis"
    )

    threshold_analysis = pd.DataFrame({

        "Configuration": [
            "Default 0.50",
            "Protection 0.30"
        ],

        "False Negatives": [
            DEFAULT_FALSE_NEGATIVES,
            PROTECTION_FALSE_NEGATIVES
        ],

        "Recall": [
            0.895341710082746,
            PROTECTION_RECALL
        ]
    })

    t1, t2 = st.columns(2)

    with t1:

        fig_fn = px.bar(
            threshold_analysis,
            x="Configuration",
            y="False Negatives",
            text="False Negatives",
            title="False Negatives by Detection Threshold"
        )

        fig_fn.update_traces(
            textposition="outside"
        )

        fig_fn.update_layout(
            template="plotly_dark",
            height=400
        )

        st.plotly_chart(
            fig_fn,
            use_container_width=True
        )

    with t2:

        fig_recall = px.bar(
            threshold_analysis,
            x="Configuration",
            y="Recall",
            text="Recall",
            title="Recall by Detection Threshold"
        )

        fig_recall.update_traces(
            texttemplate="%{text:.2%}",
            textposition="outside"
        )

        fig_recall.update_yaxes(
            range=[0, 1]
        )

        fig_recall.update_layout(
            template="plotly_dark",
            height=400
        )

        st.plotly_chart(
            fig_recall,
            use_container_width=True
        )

    st.divider()


    # ========================================================
    # FALSE NEGATIVE REDUCTION
    # ========================================================

    st.subheader(
        "False-Negative Reduction"
    )

    f1, f2, f3 = st.columns(3)

    with f1:

        st.metric(
            "Default False Negatives",
            f"{DEFAULT_FALSE_NEGATIVES:,}"
        )

    with f2:

        st.metric(
            "Protection False Negatives",
            f"{PROTECTION_FALSE_NEGATIVES:,}",
            delta=f"-{FN_REDUCTION:,}"
        )

    with f3:

        st.metric(
            "Reduction",
            f"{FN_REDUCTION_PERCENT:.2f}%"
        )

    st.divider()


    # ========================================================
    # FINAL SECURITY CONFIGURATION
    # ========================================================

    st.subheader(
        "Final Security Configuration"
    )

    m1, m2, m3 = st.columns(3)

    with m1:

        st.info(
            f"Detection Model\n\n"
            f"**{DETECTION_MODEL}**"
        )

    with m2:

        st.info(
            f"Classification Model\n\n"
            f"**{CLASSIFICATION_MODEL}**"
        )

    with m3:

        st.info(
            f"Protection Threshold\n\n"
            f"**{PROTECTION_THRESHOLD:.2f}**"
        )


# ============================================================
# FOOTER
# ============================================================

st.divider()

st.caption(
    "CyberShield — Network Threat Detection & Protection"
)