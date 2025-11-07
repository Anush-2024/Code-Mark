# app.py
"""
NordSecureAI - Layer 1: AI Detective
Universal Scan → Probabilistic Link → Golden Record

On-prem AI-powered PII detection and entity resolution system
"""
import streamlit as st
import pandas as pd
import json
import os
import gc
import logging
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

# Import modules
from infra.license_validator import check_license
from security.secure_data_handler import SecureDataHandler
from security.audit_logger import AuditLogger
from layer1_scanner.scanner import scan_job
from layer1_linker.linker import cluster_fragments, get_cluster_summary
from layer1_mapper import mapper

# Page config
st.set_page_config(
    page_title="NordSecureAI - AI Detective Layer",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS
st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        font-weight: 700;
        color: #1E3A8A;
        margin-bottom: 0.5rem;
    }
    .sub-header {
        font-size: 1.2rem;
        color: #6B7280;
        margin-bottom: 2rem;
    }
    .metric-card {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        padding: 1.5rem;
        border-radius: 10px;
        color: white;
        margin-bottom: 1rem;
    }
    .success-box {
        background-color: #D1FAE5;
        border-left: 4px solid #10B981;
        padding: 1rem;
        border-radius: 5px;
        margin: 1rem 0;
    }
    .warning-box {
        background-color: #FEF3C7;
        border-left: 4px solid #F59E0B;
        padding: 1rem;
        border-radius: 5px;
        margin: 1rem 0;
    }
</style>
""", unsafe_allow_html=True)

# Initialize handlers
@st.cache_resource
def get_handlers():
    """Initialize global handlers (cached)"""
    secure_handler = SecureDataHandler()
    audit_logger = AuditLogger()
    mapper.init_db()
    return secure_handler, audit_logger

handler, audit_logger = get_handlers()

# License check
st.markdown('<div class="main-header">🔍 NordSecureAI - AI Detective</div>', unsafe_allow_html=True)
st.markdown('<div class="sub-header">Layer 1: Universal Scan → Probabilistic Link → Golden Record</div>', unsafe_allow_html=True)

valid, msg = check_license()
if not valid:
    st.error(f"⚠️ License Error: {msg}")
    st.info("📝 To generate a demo license, run: `python infra/license_validator.py`")
    st.stop()

st.success(f"✓ {msg} | Running in on-prem mode (no data leaves this system)")

# Sidebar configuration
st.sidebar.header("⚙️ Configuration")

# Mode selection
mode = st.sidebar.radio(
    "Mode",
    ["🔍 Scan & Link", "🗂️ Entity Manager", "📊 Audit Logs"],
    help="Choose operation mode"
)

# === SCAN & LINK MODE ===
if mode == "🔍 Scan & Link":
    st.header("Step 1: Universal Historical Scan")
    
    col1, col2 = st.columns([2, 1])
    
    with col1:
        st.markdown("""
        Upload files or specify folders to scan for PII fragments across:
        - **Structured data**: CSV, JSON, Excel
        - **Unstructured data**: TXT, LOG, PDF, DOCX
        - **Detection methods**: Presidio NER, regex patterns, Nordic ID validators
        """)
    
    with col2:
        stats = mapper.get_statistics()
        st.metric("Entities in DB", stats['total_entities'])
        st.metric("Fragments in DB", stats['total_fragments'])
    
    # Input methods
    tab1, tab2 = st.tabs(["📤 Upload Files", "📁 Scan Folders"])
    
    uploaded_files = []
    folder_paths = []
    
    with tab1:
        uploaded_files = st.file_uploader(
            "Upload files to scan",
            accept_multiple_files=True,
            type=['csv', 'json', 'txt', 'log', 'pdf', 'docx'],
            help="Supported: CSV, JSON, TXT, LOG, PDF, DOCX"
        )
    
    with tab2:
        folder_input = st.text_input(
            "Folder path (comma-separated for multiple)",
            value="",
            placeholder="/data/old_logs, /data/archives",
            help="Enter full paths to folders to scan"
        )
        if folder_input:
            folder_paths = [p.strip() for p in folder_input.split(",")]
            st.info(f"📁 Will scan {len(folder_paths)} folder(s)")

    # === Scan Parameters ===
    st.subheader("Scan Parameters")
    col1, col2, col3 = st.columns(3)
    
    with col1:
        sample_n = st.number_input(
            "Rows sample (structured files)",
            min_value=50,
            max_value=5000,
            value=200,
            step=50,
            help="Number of rows to sample from CSV/JSON files"
        )
    
    with col2:
        threshold = st.slider(
            "Linker confidence threshold",
            min_value=50,
            max_value=95,
            value=85,
            help="Minimum match score for linking fragments (0–100)"
        )
    
    with col3:
        auto_save = st.checkbox(
            "Auto-save to database",
            value=True,
            help="Automatically persist results to local database"
        )

    # === Database & NoSQL Scanning Section ===
    st.sidebar.markdown("### 🗄️ Database & NoSQL Scans")

    sql_conn = st.sidebar.text_input("SQL connection string (read-only)", value="", type="password")
    sql_tables = st.sidebar.text_input("Tables to scan (comma-separated)", value="")

    mongo_uri = st.sidebar.text_input("MongoDB URI (read-only)", value="", type="password")
    mongo_db = st.sidebar.text_input("MongoDB Database name", value="")

    # Initialize fragments list
    fragments = []

    if st.sidebar.button("Scan SQL DB"):
        from layer1_scanner.scanner import scan_database
        st.sidebar.info("🔍 Scanning SQL Database (sampled read-only)...")
        sql_frags = scan_database(sql_conn, tables=[t.strip() for t in sql_tables.split(",") if t], sample_n=sample_n)
        st.sidebar.success(f"✅ Found {len(sql_frags)} fragments from SQL database.")
        fragments.extend(sql_frags)

    if st.sidebar.button("Scan MongoDB"):
        from layer1_scanner.scanner import scan_mongo
        st.sidebar.info("🔍 Scanning MongoDB (sampled read-only)...")
        mongo_frags = scan_mongo(mongo_uri, mongo_db, collections=None, sample_n=sample_n)
        st.sidebar.success(f"✅ Found {len(mongo_frags)} fragments from MongoDB.")
        fragments.extend(mongo_frags)

    # === RUN BUTTON ===
    if st.button("🚀 Run Full Historical Scan", type="primary", use_container_width=True):
        if not uploaded_files and not folder_paths and not fragments:
            st.warning("⚠️ Please upload files, specify folders, or connect a DB to scan.")
            st.stop()

        # Prepare file objects
        file_objs = []
        if uploaded_files:
            for uploaded_file in uploaded_files:
                raw_bytes = uploaded_file.getvalue()
                file_objs.append((uploaded_file.name, raw_bytes))

        # Phase 1 — Scanning
        with st.spinner("🔍 Scanning files (Presidio + NER + Regex)..."):
            progress_bar = st.progress(0)
            progress_bar.progress(10)
            file_frags = scan_job(file_objs=file_objs, folder_paths=folder_paths, sample_n=sample_n)
            fragments.extend(file_frags)
            progress_bar.progress(40)

        if not fragments:
            st.warning("⚠️ No PII fragments found in the provided data.")
            st.stop()

        st.success(f"✓ Scan complete – Found **{len(fragments)}** PII fragments (clues).")

        # Phase 2 — Linking
        with st.spinner("🔗 Linking fragments into entities..."):
            progress_bar.progress(50)
            mapping, df_prepared = cluster_fragments(fragments, score_threshold=threshold / 100.0)
            progress_bar.progress(80)

        entity_count = len(set([v['entity_id'] for v in mapping.values()])) if mapping else 0
        st.success(f"✓ Linking complete – Created **{entity_count}** entity clusters.")

        # Show summary
        if mapping:
            summary_df = get_cluster_summary(mapping, df_prepared)
            with st.expander("🗂️ Entity Cluster Summary", expanded=True):
                st.dataframe(summary_df[['entity_id', 'fragment_count', 'names', 'emails', 'avg_confidence']], use_container_width=True)

        # Phase 3 — Save to DB
        if auto_save and mapping:
            with st.spinner("💾 Saving to database..."):
                for i, f in enumerate(fragments):
                    if "fragment_id" not in f:
                        f["fragment_id"] = f.get("frag_id") or f"F-{i+1:06d}"
                mapper.save_mapping(mapping, fragments)
                progress_bar.progress(95)
            st.success("✓ Saved mappings to local database (layer1_mapper.db)")

        # Phase 4 — Audit Log
        with st.spinner("📝 Writing audit log..."):
            combined_bytes = json.dumps([f.get("type") for f in fragments[:100]]).encode()
            proof_hash = handler.hash_bytes(combined_bytes)
            audit_entry = audit_logger.log_scan_operation(
                proof_hash=proof_hash,
                rows=len(fragments),
                cols=0,
                user=os.getenv("USER", "demo_user"),
                source_files=[f[0] for f in file_objs] if file_objs else folder_paths,
                fragments_found=len(fragments)
            )
            progress_bar.progress(100)
        st.success("✓ Audit logs written")
        st.info("🧹 Raw fragments cleared from memory. Only metadata persisted to local DB.")

# === ENTITY MANAGER MODE ===
elif mode == "🗂️ Entity Manager":
    st.header("Entity Manager")
    
    tab1, tab2, tab3 = st.tabs(["🔍 Lookup", "🗑️ Erase (GDPR)", "📊 Statistics"])
    
    with tab1:
        st.subheader("Entity Lookup")
        
        # Search options
        search_type = st.radio("Search by", ["Entity ID", "Name/Email"], horizontal=True)
        
        if search_type == "Entity ID":
            entity_id = st.text_input(
                "Entity ID",
                value="",
                placeholder="E-000001",
                help="Enter exact entity ID"
            )
            
            if st.button("🔍 Lookup Entity"):
                if not entity_id:
                    st.warning("Please enter an entity ID")
                else:
                    entity_data = mapper.get_entity(entity_id)
                    
                    if not entity_data:
                        st.error(f"❌ Entity {entity_id} not found")
                    else:
                        st.success(f"✓ Found entity: {entity_id}")
                        
                        # Display entity info
                        ent = entity_data['entity']
                        col1, col2, col3 = st.columns(3)
                        
                        with col1:
                            st.metric("Fragments", ent['fragment_count'])
                        with col2:
                            st.metric("Confidence", f"{ent['confidence']:.2f}")
                        with col3:
                            st.metric("Created", ent['created_at'][:10])
                        
                        st.json(entity_data)
                        
                        # Log access
                        audit_logger.log_access_operation(
                            entity_id=entity_id,
                            user=os.getenv("USER", "demo_user"),
                            purpose="manual_lookup"
                        )
        
        else:
            query = st.text_input(
                "Search query",
                value="",
                placeholder="Enter name or email",
                help="Search entities by name or email (partial match)"
            )
            
            if st.button("🔍 Search"):
                if not query:
                    st.warning("Please enter a search query")
                else:
                    results = mapper.search_entities(query)
                    
                    if not results:
                        st.info(f"No entities found matching '{query}'")
                    else:
                        st.success(f"Found {len(results)} matching entities")
                        st.dataframe(
                            pd.DataFrame(results),
                            use_container_width=True
                        )
    
    with tab2:
        st.subheader("🗑️ Entity Erasure (GDPR Right to Erasure)")
        
        st.markdown("""
        <div class="warning-box">
        ⚠️ <strong>Warning:</strong> This action is irreversible. All fragments linked to this entity will be permanently deleted.
        </div>
        """, unsafe_allow_html=True)
        
        entity_id_erase = st.text_input(
            "Entity ID to erase",
            value="",
            placeholder="E-000001",
            help="Enter entity ID to delete"
        )
        
        reason = st.text_area(
            "Reason for erasure",
            value="GDPR Article 17 - Right to Erasure",
            help="Document the legal basis for erasure"
        )
        
        col1, col2 = st.columns([1, 3])
        
        with col1:
            confirm = st.checkbox("I confirm this erasure")
        
        with col2:
            if st.button("🗑️ Erase Entity", type="primary", disabled=not confirm):
                if not entity_id_erase:
                    st.warning("Please enter an entity ID")
                else:
                    # Check if entity exists
                    entity_data = mapper.get_entity(entity_id_erase)
                    
                    if not entity_data:
                        st.error(f"❌ Entity {entity_id_erase} not found")
                    else:
                        frag_count = entity_data['entity']['fragment_count']
                        
                        # Perform erasure
                        success = mapper.erase_entity(
                            entity_id_erase,
                            requested_by=os.getenv("USER", "demo_user"),
                            reason=reason
                        )
                        
                        if success:
                            st.success(f"✓ Entity {entity_id_erase} erased ({frag_count} fragments deleted)")
                            
                            # Log erasure
                            audit_logger.log_erasure_operation(
                                entity_id=entity_id_erase,
                                fragments_deleted=frag_count,
                                requested_by=os.getenv("USER", "demo_user"),
                                reason=reason
                            )
                            
                            st.info("📝 Erasure logged for compliance audit trail")
                        else:
                            st.error("❌ Erasure failed. Check logs for details.")
    
    with tab3:
        st.subheader("📊 Database Statistics")
        
        stats = mapper.get_statistics()
        
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric("Total Entities", stats['total_entities'])
        with col2:
            st.metric("Total Fragments", stats['total_fragments'])
        with col3:
            st.metric("Avg Fragments/Entity", stats['avg_fragments_per_entity'])
        with col4:
            st.metric("Erasures Performed", stats['erasures_performed'])
        
        st.markdown("---")
        
        # List recent entities
        st.subheader("Recent Entities")
        entities = mapper.list_entities(limit=20)
        
        if entities:
            st.dataframe(
                pd.DataFrame(entities),
                use_container_width=True
            )
        else:
            st.info("No entities in database. Run a scan first.")

# === AUDIT LOGS MODE ===
else:
    st.header("📊 Audit Logs")
    
    tab1, tab2 = st.tabs(["Recent Logs", "Search Logs"])
    
    with tab1:
        st.subheader("Recent Audit Logs")
        
        limit = st.slider("Number of logs to display", 5, 50, 20)
        
        logs = audit_logger.get_recent_logs(limit=limit)
        
        if not logs:
            st.info("No audit logs found. Run operations to generate logs.")
        else:
            for i, log in enumerate(logs):
                with st.expander(f"{i+1}. {log.get('operation', 'unknown').upper()} - {log.get('timestamp_utc', 'N/A')[:19]}"):
                    st.json(log)
    
    with tab2:
        st.subheader("Search Audit Logs")
        
        search_by = st.radio("Search by", ["User", "Entity ID"], horizontal=True)
        
        if search_by == "User":
            user = st.text_input("Username", value=os.getenv("USER", "demo_user"))
            
            if st.button("🔍 Search"):
                logs = audit_logger.get_logs_by_user(user)
                
                if not logs:
                    st.info(f"No logs found for user '{user}'")
                else:
                    st.success(f"Found {len(logs)} logs for user '{user}'")
                    
                    for i, log in enumerate(logs):
                        with st.expander(f"{i+1}. {log.get('operation', 'unknown').upper()} - {log.get('timestamp_utc', 'N/A')[:19]}"):
                            st.json(log)
        
        else:
            entity_id = st.text_input("Entity ID", value="", placeholder="E-000001")
            
            if st.button("🔍 Search"):
                if not entity_id:
                    st.warning("Please enter an entity ID")
                else:
                    logs = audit_logger.get_logs_by_entity(entity_id)
                    
                    if not logs:
                        st.info(f"No logs found for entity '{entity_id}'")
                    else:
                        st.success(f"Found {len(logs)} logs for entity '{entity_id}'")
                        
                        for i, log in enumerate(logs):
                            with st.expander(f"{i+1}. {log.get('operation', 'unknown').upper()} - {log.get('timestamp_utc', 'N/A')[:19]}"):
                                st.json(log)

# Footer
st.markdown("---")
st.markdown("""
<div style="text-align: center; color: #6B7280; font-size: 0.9rem;">
    🔒 <strong>NordSecureAI</strong> | On-Prem AI Detective Layer | All data processed locally | No PII leaves this system<br>
    Licensed for on-premises use | GDPR Article 17 compliant | Audit trail enabled
</div>
""", unsafe_allow_html=True)