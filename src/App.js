import React, { useState, useEffect, useRef, useMemo, useCallback } from "react";
import { BarChart, Bar, LineChart, Line, PieChart, Pie, Cell, RadarChart, Radar, PolarGrid, PolarAngleAxis, PolarRadiusAxis, AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer } from "recharts";
import { AlertTriangle, Eye, FileWarning, TrendingUp, Activity, Plus, X, CheckCircle2, Bell, Search, Menu, ArrowUp, ArrowDown, AlertOctagon, ClipboardList, BookOpen, Download, Trash2, LogOut, Sun, Moon, Users, Edit2, Save, Lock, UserCheck, Shield, Mail, Key } from "lucide-react";
// ── EmailJS (bundled locally — no runtime CDN dependency) ────────────────────
import emailjs from "@emailjs/browser";
// ── Neon REST API — replaces Firebase SDK ─────────────────────────────────────
import { neonAuth as auth, neonDb as db, neonCompat, refreshAllSnapshots } from "./neon-client";
const { collection, onSnapshot, addDoc, deleteDoc, doc, updateDoc,
        setDoc, query, where,
        signInWithEmailAndPassword, signOut, updatePassword,
        sendPasswordResetEmail, createUserWithEmailAndPassword } = neonCompat;

// ── THEMES ────────────────────────────────────────────────────────────────────
const DARK  = {bg:"#0f172a",card:"#1e293b",border:"#334155",text:"#e2e8f0",sub:"#94a3b8",muted:"#64748b",red:"#ef4444",orange:"#f97316",yellow:"#eab308",green:"#22c55e",teal:"#14b8a6",blue:"#3b82f6",indigo:"#6366f1",purple:"#a855f7",pink:"#ec4899"};
const LIGHT = {bg:"#f1f5f9",card:"#ffffff",border:"#e2e8f0",text:"#0f172a",sub:"#475569",muted:"#94a3b8",red:"#ef4444",orange:"#f97316",yellow:"#ca8a04",green:"#16a34a",teal:"#0d9488",blue:"#2563eb",indigo:"#4f46e5",purple:"#9333ea",pink:"#db2777"};

// ── DAN LOGO ──────────────────────────────────────────────────────────────────
const DanLogo = ({size=48}) => (
  <img src="/dan-logo.png" alt="DAN Logo" style={{width:size,height:size,objectFit:"contain"}}/>
);

// ── CONSTANTS ─────────────────────────────────────────────────────────────────
const ROLE_META = {
  admin:  {label:"Administrator",color:"#ef4444",icon:Shield,canAdd:true, canEdit:true, canDelete:true, canManageUsers:true},
  editor: {label:"Editor",       color:"#f97316",icon:Edit2, canAdd:true, canEdit:true, canDelete:false,canManageUsers:false},
  viewer: {label:"View Only",    color:"#3b82f6",icon:Eye,   canAdd:false,canEdit:false,canDelete:false,canManageUsers:false},
};
const NAV = [
  // ── Home dashboard (admin / All Sites only) — executive landing page ──────
  {id:"overview",     label:"🏠 Home Dashboard",   icon:Activity,   color:"#14b8a6", siteAccess:"All Sites"},
  // ── Site dashboards — each is a full HSSE hub filtered to that site ───────
  {id:"site1",        label:"Palm1 Al-Ahsa",      icon:Activity,   color:"#14b8a6", siteAccess:"Site 1"},
  {id:"site2",        label:"Palm2 Al-Madinah",   icon:Activity,   color:"#8b5cf6", siteAccess:"Site 2"},
  {id:"site3",        label:"Site 3",             icon:Activity,   color:"#f97316", siteAccess:"Site 3"},
  // ── Shared resources (all authenticated users) ────────────────────────────
  {id:"resources",    label:"Resources",          icon:Users,      color:"#06b6d4"},
  // ── Admin-only sections ───────────────────────────────────────────────────
  {id:"notifications",label:"Email Alerts",       icon:Bell,       color:"#f59e0b", adminOnly:true},
  {id:"users",        label:"User Management",    icon:Users,      color:"#6366f1", adminOnly:true},
  {id:"dropdowns",    label:"Dropdown Settings",  icon:Edit2,      color:"#0d9488", adminOnly:true},
];
// Site-specific permissions: which nav items a user can see based on their assigned site
// and their grants. A viewer with a grant for Site 2 can now see Site 2 in nav.
const getSiteNavItems = (userSite, userRole, userPerms, grants = []) => {
  // Sites where the user has ANY grant — these should show in nav even for viewers
  const grantedSites = new Set(
    (Array.isArray(grants) ? grants : [])
      .filter(g => g && g.site && Array.isArray(g.actions) && g.actions.length > 0)
      .map(g => g.site)
  );
  return NAV.filter(n=>{
    // Admin sees everything
    if(userRole==="admin") return true;
    // adminOnly items — check explicit permissions
    if(n.adminOnly) return userPerms.includes(n.id);
    // siteAccess items — show if user's site matches, user has All Sites,
    // user has explicit permission, OR user has a grant for that site
    if(n.siteAccess){
      if(n.siteAccess==="All Sites") return userSite==="All Sites";
      if(userSite==="All Sites" || userSite===n.siteAccess) return true;
      if(userPerms.includes(n.id)) return true;
      if(grantedSites.has(n.siteAccess) || grantedSites.has("All Sites")) return true;
      return false;
    }
    // General items (e.g. "resources") — show to all logged-in users
    return true;
  });
};
const DEFAULT_PERMISSIONS = {
  admin:  ["overview","site1","site2","site3","resources","notifications","users","dropdowns"],
  editor: ["resources"],
  viewer: ["resources"],
};

// ── SCOPED-GRANTS PERMISSION CHECK ────────────────────────────────────────────
// Mirror of the backend's canDo(). The UI uses this to hide buttons the user
// can't use (cosmetic + UX only — the backend enforces the real thing).
//
// Signature: can(user, section, site, action, record?)
//   user    — userProfile object ({ role, site, grants, uid, ... })
//   section — "observations" | "ncr" | "incidents" | "risks" | "equipment" | "manpower" | "weekly_reports"
//   site    — "Site 1" | "Site 2" | "Site 3" | "" (for site-less sections)
//   action  — "add" | "edit_own" | "edit_any" | "delete"
//   record  — optional record object { created_by, site } — required for edit_own
//
// Rules (kept identical to netlify/functions/api.js canDo):
//   • admin always wins
//   • users/settings/dropdowns sections are admin-only (never grantable)
//   • viewer must have an explicit matching grant
//   • editor with NO grants keeps legacy blanket add/edit_any on accessible sites
//   • editor WITH grants — grants become the sole source of truth
const canAccessSiteClient = (user, site) => {
  if(!user) return false;
  if(user.role === "admin") return true;
  if(user.site === "All Sites") return true;
  if(!site) return true;
  return user.site === site;
};
const can = (user, section, site, action, record = null) => {
  if(!user) return false;
  if(user.role === "admin") return true;
  if(["users","settings","dropdowns"].includes(section)) return false;
  if(!canAccessSiteClient(user, site)) return false;
  const grants = Array.isArray(user.grants) ? user.grants : [];
  const matching = grants.filter(g =>
    g && g.section === section &&
    (g.site === site || g.site === "All Sites") &&
    Array.isArray(g.actions)
  );
  if(action === "edit_own") {
    if(!record || !record.created_by) return false;
    if(record.created_by !== user.uid) return false;
    return matching.some(g => g.actions.includes("edit_own"));
  }
  if(matching.some(g => g.actions.includes(action))) return true;
  // Legacy fallback: editor without ANY grants keeps old blanket behavior
  if(user.role === "editor" && grants.length === 0) {
    return ["add","edit_any"].includes(action);
  }
  return false;
};
// Convenience: can user do `action` on `section` at ANY accessible site?
// Used for bulk operations (CSV export, import) where the button isn't tied
// to a specific site.
const canAnySite = (user, section, action) => {
  if(!user) return false;
  if(user.role === "admin") return true;
  if(user.site === "All Sites") {
    return ["Site 1","Site 2","Site 3"].some(s => can(user, section, s, action));
  }
  return can(user, section, user.site, action);
};
const DEFAULT_ZONES        = ["Zone A","Zone B","Zone C","Warehouse","Office","Tank Farm","Panel Room","Site Gate","Parking","Canteen"];
const DEFAULT_OBS_TYPES    = ["Unsafe Act","Unsafe Condition","Near Miss","Good Practice","Environmental","Security"];
const DEFAULT_ACTIONS      = ["Stop Work","Verbal Warning","Written Warning","Corrective Action Issued","Praised/Commended","Referred to Supervisor","No Action Required"];
const DEFAULT_OBS_SEVERITY = ["High","Medium","Low","Positive"];
const DEFAULT_NCR_CATS     = ["PPE","Electrical","Fire Safety","Housekeeping","Chemical","Working at Height","Permit to Work","Environmental","Excavation","Lifting Operations"];
const DEFAULT_NCR_SEVERITY = ["Critical","Major","Minor"];
const DEFAULT_NCR_STATUS   = ["Open","In Progress","Overdue","Closed"];
const DEFAULT_RISK_CATS    = ["Physical","Chemical","Electrical","Ergonomic","Fire","Transport","Biological","Mechanical"];
const DEFAULT_RISK_STATUS  = ["Active","Under Review","Closed"];
const DEFAULT_EQUIP_STATUS = ["Active","Under Maintenance","Out of Service","Mobilizing","Demobilized"];
const DEFAULT_MP_STATUS    = ["Active","On Leave","Terminated","Demobilized"];
// ── SITES ─────────────────────────────────────────────────────────────────────
const SITES = [
  { id:"Site 1", prefix:"01", name:"Palm1 Al-Ahsa Project"    },
  { id:"Site 2", prefix:"02", name:"Palm2 Al-Madinah Project"  },
  { id:"Site 3", prefix:"03", name:"Site 3"                    },
];
const SITE_IDS    = SITES.map(s=>s.id);
const sitePrefix  = (siteId) => (SITES.find(s=>s.id===siteId)||SITES[0]).prefix;
const siteName    = (siteId) => (SITES.find(s=>s.id===siteId)||SITES[0]).name;

const INIT_MANUAL_STATS = {daysLTI:142,manpower:518,manhoursWeek:31140,manhoursMonth:237108,manhoursYear:402248,manhoursProject:1830112,safetyOfficers:12,firstAiders:10,tbtAttendees:2295};
const MONTHS = ["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"];
const KPI_COLORS_PALETTE = ["#14b8a6","#ef4444","#f97316","#3b82f6","#6366f1","#a855f7","#ec4899","#eab308","#22c55e","#64748b","#06b6d4","#f43f5e","#84cc16","#fb923c","#818cf8"];

// ── MANUAL-STAT FIELD DEFINITIONS ────────────────────────────────────────────
// The "Edit Stats" form in Overview and each SiteDashboard used to duplicate
// this list; same for the "Project Statistics" read-only tile grid. Now both
// components share these definitions. Keep `key` in sync with INIT_MANUAL_STATS.
// The tile/label color is read via C[colorKey] at render time so themes work.
const MANUAL_STAT_FIELDS = [
  {key:"daysLTI",         label:"Days Without LTI"},
  {key:"manpower",        label:"Manpower"},
  {key:"manhoursWeek",    label:"Man-hours (Week)"},
  {key:"manhoursMonth",   label:"Man-hours (Month)"},
  {key:"manhoursYear",    label:"Man-hours (Year)"},
  {key:"manhoursProject", label:"Man-hours (Project)"},
  {key:"safetyOfficers",  label:"Safety Officers"},
  {key:"firstAiders",     label:"First Aiders"},
  {key:"tbtAttendees",    label:"TBT Attendees"},
];
// Project Statistics tile config — `format` says whether to .toLocaleString()
// the value (for counts with thousands separators) or leave it plain.
const PROJECT_STAT_TILES = [
  {key:"manpower",        label:"👷 Manpower",             colorKey:"purple", format:"n"},
  {key:"manhoursWeek",    label:"⏱ Man-hours (Week)",      colorKey:"teal",   format:"n"},
  {key:"manhoursMonth",   label:"📅 Man-hours (Month)",    colorKey:"blue",   format:"n"},
  {key:"manhoursYear",    label:"📆 Man-hours (Year)",     colorKey:"indigo", format:"n"},
  {key:"manhoursProject", label:"🏗 Man-hours (Project)",  colorKey:"green",  format:"n"},
  {key:"safetyOfficers",  label:"👮 Safety Officers",      colorKey:"blue",   format:"raw"},
  {key:"firstAiders",     label:"🏥 First Aiders",         colorKey:"orange", format:"raw"},
  {key:"tbtAttendees",    label:"📢 TBT Attendees",        colorKey:"teal",   format:"n"},
];

// ── STATIC DEFAULTS (used only if Firestore has no saved data) ────────────────
const DEFAULT_KPI_DATA = [
  {label:"TRIR",value:0.42,target:0.5,unit:"",trend:-8,good:"low"},
  {label:"LTIR",value:0.12,target:0.2,unit:"",trend:-15,good:"low"},
  {label:"Near Miss",value:14,target:20,unit:"/mo",trend:5,good:"low"},
  {label:"Observations",value:312,target:280,unit:"/mo",trend:11,good:"high"},
  {label:"Training %",value:94,target:95,unit:"%",trend:2,good:"high"},
  {label:"Welfare Score",value:87,target:85,unit:"%",trend:3,good:"high"},
];
const DEFAULT_RADAR_DATA = [
  {subject:"PPE Compliance",A:88},{subject:"Housekeeping",A:92},
  {subject:"Permit to Work",A:79},{subject:"Training",A:94},
  {subject:"Emergency Prep",A:85},{subject:"Welfare",A:87},
];
const DEFAULT_MONTHLY_TREND = [
  {month:"Oct",incidents:3,nearMiss:18,observations:240,ncrOpen:8,welfare:78},
  {month:"Nov",incidents:2,nearMiss:15,observations:265,ncrOpen:6,welfare:80},
  {month:"Dec",incidents:4,nearMiss:22,observations:210,ncrOpen:9,welfare:75},
  {month:"Jan",incidents:1,nearMiss:12,observations:290,ncrOpen:5,welfare:82},
  {month:"Feb",incidents:2,nearMiss:16,observations:305,ncrOpen:7,welfare:85},
  {month:"Mar",incidents:1,nearMiss:14,observations:312,ncrOpen:5,welfare:87},
];
const DEFAULT_WELFARE_ITEMS = [
  {category:"Rest Facilities",score:88,status:"Good"},
  {category:"Potable Water",score:95,status:"Excellent"},
  {category:"Sanitation",score:82,status:"Good"},
  {category:"First Aid",score:91,status:"Excellent"},
  {category:"Mental Health",score:76,status:"Needs Attention"},
  {category:"Heat Stress Mgmt",score:84,status:"Good"},
];
const INIT_KPI_ITEMS = ["TRIR","LTIR","Near Miss Rate","Observation Rate","Training %","Welfare Score"];
const INIT_PCI_ITEMS = ["PPE Compliance","Housekeeping","Permit to Work","Emergency Preparedness","Toolbox Talks","Safety Inspections"];
const buildEmptyMonthRow = () => Object.fromEntries(MONTHS.map(m=>[m,""]));
const buildDefaultKpiTable = (items) => { const o={}; items.forEach(k=>{o[k]=buildEmptyMonthRow();}); return o; };

const WEEKLY_DATA = {
  company:"DAN Company",dept:"Delivery Management Department",
  division:"Health, Safety, Security & Environment",
  dateFrom:"Mar 27",dateTo:"Apr 02, 2026",weekNo:14,
  project:"THE PALM AL-AHSA PROJECT",
  contractor:"AL-TAMIMI CONTRACTING",consultant:"KHATIB AND ALAMI",
  rows:[
    {no:1, group:"Incidents",   desc:"Fatality On Job (FAT)",                              value:"0",        highlight:false},
    {no:2, group:"Incidents",   desc:"Lost Time Injury/Illness Report (LTI)",               value:"0",        highlight:false},
    {no:3, group:"Incidents",   desc:"Restricted Duty Incident (RDI)",                      value:"0",        highlight:false},
    {no:4, group:"Incidents",   desc:"Medical Treatment Case (MTC)",                        value:"0",        highlight:false},
    {no:5, group:"Incidents",   desc:"First Aid Injury",                                    value:"0",        highlight:false},
    {no:6, group:"Incidents",   desc:"Motor Vehicle Accident (MVA)",                        value:"0",        highlight:false},
    {no:7, group:"Incidents",   desc:"Motor Vehicle Accident Fatality (MVA Fat)",           value:"0",        highlight:false},
    {no:8, group:"Incidents",   desc:"Near Miss Report",                                    value:"0",        highlight:false},
    {no:9, group:"Incidents",   desc:"Off-Job Injury",                                      value:"0",        highlight:false},
    {no:10,group:"Incidents",   desc:"Incidents or Damage To Property (IDTP)",              value:"0",        highlight:false},
    {no:11,group:"Incidents",   desc:"Fire",                                                value:"0",        highlight:false},
    {no:12,group:"Incidents",   desc:"Incidents Involving Damage to DAN Equipment/Vehicle", value:"0",        highlight:false},
    {no:13,group:"Incidents",   desc:"Crane, Heavy Equipment & Manlift Accidents",          value:"0",        highlight:false},
    {no:14,group:"Incidents",   desc:"Environmental Incidents",                             value:"0",        highlight:false},
    {no:15,group:"Observations",desc:"Positive Safety Observations",                       value:"25",       highlight:true,color:"green"},
    {no:16,group:"Observations",desc:"Negative Safety Observations",                       value:"117",      highlight:true,color:"orange"},
    {no:17,group:"HSE Activity",desc:"Safety Meeting",                                      value:"1",        highlight:false},
    {no:18,group:"HSE Activity",desc:"HSE Management Walkthrough",                          value:"0",        highlight:false},
    {no:19,group:"HSE Activity",desc:"HSE Weekly Walkthrough",                              value:"1",        highlight:false},
    {no:20,group:"HSE Activity",desc:"HSE Training/Certification",                          value:"1 Session / 18 Attendees",highlight:true,color:"blue"},
    {no:21,group:"HSE Activity",desc:"Emergency Drills",                                    value:"0",        highlight:false},
    {no:22,group:"HSE Activity",desc:"Safety Induction",                                    value:"1 Session / 2 Attendees",highlight:false},
    {no:23,group:"HSE Activity",desc:"TBT (Toolbox Talk) — 2,295 Attendees",               value:"Emergency response, Housekeeping, PPE awareness, Manual Handling, Safety signages, Lifting hazards, Hand tools, Working at heights, Full body harness, Excavation safety, Electrical safety",highlight:true,color:"teal",wide:true},
    {no:24,group:"Manpower",    desc:"Manpower (Actual Physical Head Count)",               value:"518",      highlight:true,color:"purple"},
    {no:25,group:"Manhours",    desc:"Construction Man-hours during The Week",              value:"31,140",   highlight:false},
    {no:26,group:"Manhours",    desc:"Safe Man-hours this Month",                           value:"237,108",  highlight:false},
    {no:27,group:"Manhours",    desc:"Safe Man-Hours this Year",                            value:"402,248",  highlight:false},
    {no:28,group:"Manhours",    desc:"Safe Man-hours Project to Date",                      value:"1,830,112",highlight:true,color:"green"},
    {no:29,group:"HSE Team",    desc:"Main Contractor: HSE Manager/Deputy",                 value:"1",        highlight:false},
    {no:30,group:"HSE Team",    desc:"Main Contractor: Safety Supervisors/Superintendent",  value:"0",        highlight:false},
    {no:31,group:"HSE Team",    desc:"Main Contractor: Safety Officers/Inspectors",         value:"12",       highlight:true,color:"blue"},
    {no:32,group:"HSE Team",    desc:"Main Contractor: HSE Saudis",                         value:"1",        highlight:false},
    {no:33,group:"HSE Team",    desc:"Main Contractor: Nurse/Doctor",                       value:"1",        highlight:false},
    {no:34,group:"HSE Team",    desc:"Main Contractor: First Aiders",                       value:"10",       highlight:false},
    {no:35,group:"HSE Team",    desc:"Main Contractor: Environmental Coordinator",          value:"1",        highlight:false},
  ],
};
const GROUP_COLORS = {Incidents:"#ef4444",Observations:"#f97316","HSE Activity":"#3b82f6",Manpower:"#a855f7",Manhours:"#14b8a6","HSE Team":"#6366f1"};

// ── FIRESTORE SETTINGS HELPERS ────────────────────────────────────────────────
// All editable dashboard data lives in Firestore under "settings/{docId}"
const saveSettings = async (partial, retries=2) => {
  if(!partial||typeof partial!=="object"){ console.warn("[HSSE] saveSettings: invalid payload"); return; }
  for(let attempt=0; attempt<=retries; attempt++){
    try{
      const clean = sanitiseRecord(partial);
      await setDoc(doc(db,"settings","dashboardData"), clean, {merge:true});
      return;
    }catch(e){
      console.error(`[HSSE] saveSettings attempt ${attempt+1} failed:`,e.code||e.message);
      if(attempt===retries){ console.error("[HSSE] saveSettings permanently failed after retries"); throw e; }
      await new Promise(r=>setTimeout(r,600*Math.pow(2,attempt))); // exponential back-off
    }
  }
};

// ── HELPERS ───────────────────────────────────────────────────────────────────
const fbAdd   = async (col,data) => {
  if(!col||!data||typeof data!=="object"){
    console.error("[HSSE] fbAdd: invalid arguments",col,data); return;
  }
  const {_docId,...rest} = data;
  const clean = sanitiseRecord(rest);
  // Remove undefined values — Firestore rejects them
  Object.keys(clean).forEach(k=>clean[k]===undefined && delete clean[k]);
  try{ await addDoc(collection(db,col),clean); }
  catch(e){
    // Surface the failure — silent catches were making saves appear to succeed
    // while the record never landed in Neon (auth expiry, CSP, 4xx, etc.).
    console.error(`[HSSE] fbAdd(${col}) failed:`,e);
    try{ window.alert(`⚠️ Save failed for ${col}: ${e?.message||"Unknown error"}.\nPlease check your connection and try again. If the issue persists, log out and back in.`); }catch{}
    throw e;
  }
};
const fbDel   = async (col,item) => {
  if(!item?._docId){ console.warn("[HSSE] fbDel: missing _docId for",col); return; }
  try{ await deleteDoc(doc(db,col,item._docId)); }
  catch(e){ console.error(`[HSSE] fbDel(${col}) failed:`,e); throw e; }
};
const fbDelId = async (col,id) => {
  if(!id){ console.warn("[HSSE] fbDelId: missing id for",col); return; }
  try{ await deleteDoc(doc(db,col,id)); }
  catch(e){ console.error(`[HSSE] fbDelId(${col}) failed:`,e); throw e; }
};
const riskScore = r => {
  const l = Math.min(5, Math.max(1, Number(r?.likelihood)||1));
  const i = Math.min(5, Math.max(1, Number(r?.impact)||1));
  return l * i;
};
const riskColor = (s,C) => s>=15?C.red:s>=8?C.orange:s>=4?C.yellow:C.green;
const riskLabel = s => s>=15?"CRITICAL":s>=8?"HIGH":s>=4?"MEDIUM":"LOW";
const sevColor  = (s,C) => ({Critical:C.red,Major:C.orange,Minor:C.yellow,Positive:C.green,High:C.red,Medium:C.orange,Low:C.yellow}[s]||C.muted);
const stColor   = (s,C) => ({Open:C.red,Overdue:C.red,"In Progress":C.orange,"Under Review":C.blue,Closed:C.green,Active:C.green,Expired:C.red,Scheduled:C.blue,Valid:C.green,"Expiring Soon":C.orange}[s]||C.muted);
const genDateStamp = () => {
  const n=new Date();
  const dd=String(n.getDate()).padStart(2,"0");
  const mm=String(n.getMonth()+1).padStart(2,"0");
  const yy=String(n.getFullYear()).slice(2);
  return dd+mm+yy;
};
const genObsId = (seq, site="Site 1") => `${sitePrefix(site)}-DAN-SOR-HSE-${genDateStamp()}-${String(seq).padStart(4,"0")}`;
const genNcrId = (seq, site="Site 1") => `${sitePrefix(site)}-DAN-NCR-HSE-${genDateStamp()}-${String(seq).padStart(4,"0")}`;
// ── PHOTO UPLOAD — Firebase Storage with ImgBB fallback ─────────────────────
// Tries Firebase Storage first (permanent, secure, organised by user).
// Falls back to ImgBB automatically if Storage isn't enabled yet.
// Old ImgBB URLs on existing records continue to work unchanged.
const uploadPhoto = async (file) => {
  if(!file) return null;
  // Use ImgBB for reliable photo hosting — no Firebase Storage setup required
  try{
    const fd = new FormData();
    fd.append("image", file);
    const imgbbKey = process.env.REACT_APP_IMGBB_KEY || "1dc5175b79261627f8d404ba6fced251"; // Set REACT_APP_IMGBB_KEY in .env.local
    const res  = await fetch(`https://api.imgbb.com/1/upload?key=${imgbbKey}`,{method:"POST",body:fd});
    const data = await res.json();
    if(data.success) return data.data.url;
    throw new Error(data.error?.message||"ImgBB upload failed");
  }catch(e){
    console.error("Photo upload failed:",e);
    throw new Error("Photo upload failed: "+e.message);
  }
};
// ── INPUT SANITISATION ───────────────────────────────────────────────────────
const sanitise = (v, maxLen=2000) => {
  if(v===null||v===undefined) return v;
  if(typeof v==="string") return v.trim().slice(0,maxLen);
  if(typeof v==="number") return isFinite(v)?v:0;
  return v;
};
const sanitiseRecord = (obj) => {
  if(!obj||typeof obj!=="object") return {};
  const out={};
  for(const [k,v] of Object.entries(obj)){
    if(k.startsWith("__")) continue; // skip internal keys
    out[k] = sanitise(v);
  }
  return out;
};

const exportCSV = (data, filename) => {
  if(!data||!data.length){ console.warn("[HSSE] exportCSV: no data to export"); return; }
  try{
    const keys = Object.keys(data[0]).filter(k=>k!=="id"&&k!=="_docId"&&k!=="observerId");
    const BOM  = "\uFEFF"; // UTF-8 BOM for Excel Arabic/special char support
    const csv  = BOM + [
      keys.join(","),
      ...data.map(r=>keys.map(k=>`"${(r[k]||"").toString().replace(/"/g,'""')}"`).join(","))
    ].join("\n");
    const url = URL.createObjectURL(new Blob([csv],{type:"text/csv;charset=utf-8;"}));
    const a   = document.createElement("a");
    a.href=url; a.download=(filename||"export")+".csv"; a.click();
    setTimeout(()=>URL.revokeObjectURL(url), 1000); // deferred revoke
  }catch(e){ console.error("[HSSE] exportCSV failed:",e); }
};

// ── UI ATOMS ──────────────────────────────────────────────────────────────────
const Badge = ({label,color}) => (
  <span style={{background:color+"22",color,border:`1px solid ${color}44`,fontSize:11,fontWeight:700,padding:"2px 8px",borderRadius:999,textTransform:"uppercase",letterSpacing:1,whiteSpace:"nowrap"}}>{label}</span>
);
const Btn = ({onClick,color,children,disabled,style={}}) => (
  <button onClick={onClick} disabled={disabled}
    style={{background:disabled?"#33415555":color,color:"#fff",border:"none",borderRadius:8,padding:"8px 14px",fontWeight:700,fontSize:13,cursor:disabled?"not-allowed":"pointer",display:"flex",alignItems:"center",gap:6,opacity:disabled?0.5:1,...style}}>
    {children}
  </button>
);
const Modal = ({title,onClose,children,C,wide=false}) => (
  <div style={{position:"fixed",inset:0,background:"rgba(0,0,0,0.75)",zIndex:1000,display:"flex",alignItems:"center",justifyContent:"center",padding:16}}>
    <div style={{background:C.card,border:`1px solid ${C.border}`,borderRadius:16,padding:24,width:"100%",maxWidth:wide?780:560,maxHeight:"92vh",overflowY:"auto"}}>
      <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:20}}>
        <h3 style={{color:C.text,fontWeight:800,fontSize:16,margin:0}}>{title}</h3>
        {onClose&&<button onClick={onClose} style={{color:"#94a3b8",background:"none",border:"none",cursor:"pointer"}}><X size={20}/></button>}
      </div>
      {children}
    </div>
  </div>
);
const Field = ({label,children,C}) => (
  <div style={{marginBottom:12}}>
    <label style={{display:"block",fontSize:12,color:C.sub,marginBottom:4,fontWeight:600}}>{label}</label>
    {children}
  </div>
);
const Inp = ({C,...p}) => <input {...p} style={{width:"100%",background:C.bg,border:`1px solid ${C.border}`,borderRadius:8,padding:"8px 12px",color:C.text,fontSize:13,outline:"none",boxSizing:"border-box"}}/>;
const Sel = ({C,children,...p}) => <select {...p} style={{width:"100%",background:C.bg,border:`1px solid ${C.border}`,borderRadius:8,padding:"8px 12px",color:C.text,fontSize:13,outline:"none",boxSizing:"border-box"}}>{children}</select>;
const Txa = ({C,...p}) => <textarea {...p} style={{width:"100%",background:C.bg,border:`1px solid ${C.border}`,borderRadius:8,padding:"8px 12px",color:C.text,fontSize:13,outline:"none",resize:"vertical",boxSizing:"border-box"}}/>;
const Th  = ({C,children,style={}}) => <th style={{textAlign:"left",fontSize:11,color:C.muted,textTransform:"uppercase",letterSpacing:1,padding:"10px 14px",whiteSpace:"nowrap",borderBottom:`1px solid ${C.border}`,background:C.bg,...style}}>{children}</th>;
const Td  = ({C,children,style={}}) => <td style={{padding:"9px 14px",fontSize:13,color:C.sub,borderBottom:`1px solid ${C.border}22`,...style}}>{children}</td>;
const TableCard = ({title,action,children,C}) => (
  <div style={{background:C.card,border:`1px solid ${C.border}`,borderRadius:16,overflow:"hidden"}}>
    <div style={{padding:"14px 18px",borderBottom:`1px solid ${C.border}`,display:"flex",justifyContent:"space-between",alignItems:"center",flexWrap:"wrap",gap:8}}>
      <span style={{color:C.text,fontWeight:700,fontSize:14}}>{title}</span>{action}
    </div>
    <div style={{overflowX:"auto"}}>{children}</div>
  </div>
);
const KPICard = ({kpi,C}) => {
  const safeTarget = kpi.target||1;
  const pct  = Math.min(100, Math.round((kpi.value / safeTarget) * 100));
  const good = kpi.good==="high" ? kpi.value>=kpi.target : kpi.value<=kpi.target;
  const col  = good ? C.green : C.orange;
  // Trend direction: for "low is better" KPIs (TRIR, LTIR), going down is good
  const trendGood = kpi.good==="low" ? kpi.trend<=0 : kpi.trend>=0;
  const trendCol  = trendGood ? C.green : C.red;
  return(
    <div style={{background:C.card,border:`1px solid ${col}44`,borderRadius:14,padding:18,display:"flex",flexDirection:"column",gap:8,height:"100%",boxSizing:"border-box"}}>
      <div style={{display:"flex",justifyContent:"space-between",alignItems:"flex-start",gap:4}}>
        <span style={{fontSize:11,color:C.muted,textTransform:"uppercase",letterSpacing:1,fontWeight:700,lineHeight:1.3,flex:1}}>{kpi.label}</span>
        <div style={{display:"flex",alignItems:"center",gap:3,flexShrink:0}}>
          {kpi.computed&&<span style={{fontSize:9,background:C.teal+"22",color:C.teal,padding:"1px 5px",borderRadius:99,fontWeight:700}}>LIVE</span>}
          <span style={{color:trendCol,fontSize:11,fontWeight:700,display:"flex",alignItems:"center",gap:1}}>
            {kpi.trend>0?<ArrowUp size={10}/>:<ArrowDown size={10}/>}{Math.abs(kpi.trend||0)}%
          </span>
        </div>
      </div>
      <div style={{display:"flex",alignItems:"flex-end",gap:4,marginTop:2}}>
        <span style={{fontSize:28,fontWeight:900,color:C.text,lineHeight:1}}>{kpi.value}</span>
        <span style={{fontSize:12,color:C.sub,marginBottom:3,fontWeight:600}}>{kpi.unit}</span>
      </div>
      <div style={{height:6,borderRadius:99,background:C.border}}>
        <div style={{width:`${pct}%`,background:col,height:6,borderRadius:99,transition:"width 0.4s ease"}}/>
      </div>
      <div style={{display:"flex",justifyContent:"space-between",fontSize:11,color:C.muted,marginTop:2}}>
        <span>Target: <strong style={{color:C.sub}}>{kpi.target}{kpi.unit}</strong></span>
        <span style={{color:col,fontWeight:700}}>{good?"✓ On Track":"⚠ Attention"}</span>
      </div>
    </div>
  );
};
const StatBox = ({label,value,color,icon:Icon,sub,C}) => (
  <div style={{background:C.card,border:`1px solid ${color}33`,borderRadius:14,padding:18}}>
    <div style={{display:"flex",justifyContent:"space-between",alignItems:"flex-start",marginBottom:10}}>
      <div style={{background:color+"22",padding:8,borderRadius:9}}><Icon size={18} style={{color}}/></div>
      <span style={{color,fontSize:24,fontWeight:900}}>{value}</span>
    </div>
    <div style={{color:C.text,fontWeight:600,fontSize:13}}>{label}</div>
    {sub&&<div style={{color:C.muted,fontSize:11,marginTop:3}}>{sub}</div>}
  </div>
);
const RiskMatrix = ({risks,C}) => {
  const cells=[];
  for(let i=5;i>=1;i--) for(let j=1;j<=5;j++){
    const score=i*j,items=risks.filter(r=>r.likelihood===j&&r.impact===i);
    cells.push(<div key={`${i}-${j}`} style={{background:riskColor(score,C)+"33",border:`1px solid ${riskColor(score,C)}55`,borderRadius:5,aspectRatio:"1",display:"flex",alignItems:"center",justifyContent:"center",position:"relative",minHeight:38,fontSize:12,fontWeight:700,color:riskColor(score,C)}}>
      {score}{items.map(r=><span key={r.id} title={r.hazard} style={{position:"absolute",top:1,right:1,background:riskColor(score,C),color:"#fff",fontSize:7,borderRadius:3,padding:"1px 2px"}}>{(r.id||"").replace("R-","")}</span>)}
    </div>);
  }
  return(<div>
    <div style={{display:"flex",gap:3,paddingLeft:22,marginBottom:3}}>{["1","2","3","4","5"].map(l=><div key={l} style={{flex:1,textAlign:"center",fontSize:10,color:C.muted}}>{l}</div>)}</div>
    <div style={{display:"flex",gap:6}}>
      <div style={{display:"flex",flexDirection:"column",justifyContent:"space-around",fontSize:10,color:C.muted,width:16}}>{["5","4","3","2","1"].map(l=><div key={l}>{l}</div>)}</div>
      <div style={{display:"grid",gridTemplateColumns:"repeat(5,1fr)",gap:3,flex:1}}>{cells}</div>
    </div>
    <div style={{textAlign:"center",fontSize:10,color:C.muted,marginTop:5}}>← Likelihood | Impact ↑</div>
    <div style={{display:"flex",gap:10,marginTop:6,flexWrap:"wrap"}}>{[["LOW",C.green],["MEDIUM",C.yellow],["HIGH",C.orange],["CRITICAL",C.red]].map(([l,c])=>(
      <div key={l} style={{display:"flex",alignItems:"center",gap:3,fontSize:10}}><div style={{width:8,height:8,background:c,borderRadius:2}}/><span style={{color:c}}>{l}</span></div>
    ))}</div>
  </div>);
};
const PhotoBox = ({id,preview,onSelect,onRemove,label,C}) => (
  <Field label={label} C={C}>
    <div style={{border:`2px dashed ${C.border}`,borderRadius:10,padding:12,textAlign:"center",cursor:"pointer",background:C.bg}} onClick={()=>document.getElementById(id).click()}>
      {preview?<img src={preview} alt="preview" style={{maxHeight:120,borderRadius:8,objectFit:"cover"}}/>:
        <div style={{color:C.muted,fontSize:13}}><div style={{fontSize:24,marginBottom:4}}>📷</div>Click to upload photo</div>}
    </div>
    <input id={id} type="file" accept="image/*" onChange={onSelect} style={{display:"none"}}/>
    {preview&&<button onClick={onRemove} style={{background:"none",border:"none",color:C.red,fontSize:12,cursor:"pointer",marginTop:4}}>✕ Remove</button>}
  </Field>
);

// ── SAVING INDICATOR ──────────────────────────────────────────────────────────
const SavingBadge = ({saving,C}) => saving?(
  <span style={{background:C.teal+"22",border:`1px solid ${C.teal}44`,color:C.teal,fontSize:11,fontWeight:700,padding:"3px 10px",borderRadius:99,display:"flex",alignItems:"center",gap:5}}>
    <span style={{width:6,height:6,borderRadius:"50%",background:C.teal,display:"inline-block",animation:"pulse 1s infinite"}}/>Saving…
  </span>
):null;

// ── SHARED PRIMITIVES — replace inlined style blocks across the app ──────────
// Card: standard card wrapper used by almost every panel. `accent` tints the
// border (e.g. edit panels use C.blue+"44"); `pad` overrides default padding.
const Card = ({C,accent,pad=18,style={},children,...p}) => (
  <div {...p} style={{background:C.card,border:`1px solid ${accent||C.border}`,borderRadius:14,padding:pad,...style}}>
    {children}
  </div>
);
// SectionTitle: the standard <h3> used at the top of every panel.
const SectionTitle = ({C,children,style={}}) => (
  <h3 style={{color:C.text,fontWeight:700,margin:"0 0 14px",fontSize:14,...style}}>{children}</h3>
);
// Shared Recharts tooltip style — matches the card look in every chart.
const chartTooltip = (C) => ({background:C.card,border:`1px solid ${C.border}`,borderRadius:8});
// StatPill: the small colored tile used by NCR counts, Observation counts,
// Alert summary strips. The "22" alpha on bg + "44" on border is the standard.
const StatPill = ({label,value,color,C}) => (
  <div style={{background:color+"22",border:`1px solid ${color}44`,borderRadius:10,padding:14,textAlign:"center"}}>
    <div style={{color,fontSize:22,fontWeight:900}}>{value}</div>
    <div style={{color:C.sub,fontSize:11}}>{label}</div>
  </div>
);
// PillGrid: the auto-fit grid wrapper around StatPills (lets callers skip the
// wrapping <div style={{display:"grid",...}}/>).
const PillGrid = ({minWidth=130,gap=10,children}) => (
  <div style={{display:"grid",gridTemplateColumns:`repeat(auto-fit,minmax(${minWidth}px,1fr))`,gap}}>{children}</div>
);

// ── ManualStatsEditor: the "Edit Manual Stats" number-input grid ─────────────
// Shared between Overview and SiteDashboard. Renders 9 number inputs driven by
// MANUAL_STAT_FIELDS so both call sites stay in lockstep.
const ManualStatsEditor = ({draft,setDraft,C,minWidth=200}) => (
  <div style={{display:"grid",gridTemplateColumns:`repeat(auto-fit,minmax(${minWidth}px,1fr))`,gap:12}}>
    {MANUAL_STAT_FIELDS.map(({key,label})=>(
      <Field key={key} label={label} C={C}>
        <Inp C={C} type="number" value={draft[key]||0}
          onChange={e=>setDraft(p=>({...p,[key]:Number(e.target.value)}))}/>
      </Field>
    ))}
  </div>
);
// ── ProjectStatsGrid: the read-only "Project Statistics" tile row ────────────
// Shared between Overview and SiteDashboard. Values pulled from a manualStats
// object by key; colors resolved via C[colorKey] for theme-awareness.
const ProjectStatsGrid = ({stats,C,minWidth=190}) => (
  <div style={{display:"grid",gridTemplateColumns:`repeat(auto-fit,minmax(${minWidth}px,1fr))`,gap:10}}>
    {PROJECT_STAT_TILES.map(({key,label,colorKey,format})=>{
      const c = C[colorKey] || C.muted;
      const raw = stats?.[key] || 0;
      const v = format==="n" ? raw.toLocaleString() : raw;
      return (
        <div key={key} style={{background:c+"11",border:`1px solid ${c}33`,borderRadius:10,padding:"12px 16px",display:"flex",justifyContent:"space-between",alignItems:"center"}}>
          <span style={{color:C.sub,fontSize:12}}>{label}</span>
          <span style={{color:c,fontWeight:800,fontSize:15}}>{v}</span>
        </div>
      );
    })}
  </div>
);

// ── DATE HELPERS — shared between Overview, KPITrendChart, etc. ──────────────
// Builds a list of the last N months (default 6) as {yr, mo, label} so each
// consumer can run its own filter over observations/NCRs/incidents without
// re-implementing the Date math. The returned items expose an `inMonth(dateStr)`
// predicate that safely handles null, empty, and invalid date inputs.
const buildMonthWindow = (n=6) => {
  const months = [];
  for(let i=n-1; i>=0; i--){
    const d = new Date(); d.setDate(1); d.setMonth(d.getMonth()-i);
    const yr = d.getFullYear(), mo = d.getMonth();
    const label = d.toLocaleString("default",{month:"short"});
    months.push({
      yr, mo, label, month: label,
      inMonth: (dateStr) => {
        if(!dateStr) return false;
        const p = new Date(dateStr);
        return !isNaN(p) && p.getFullYear()===yr && p.getMonth()===mo;
      },
    });
  }
  return months;
};

// ── DATA HELPERS — per-site filters used by Overview + SiteDashboard ─────────
const bySite = (rows, siteId) => (rows||[]).filter(r => r.site === siteId);
// Today's date in YYYY-MM-DD — was inlined as 5+ variants of new Date()+padStart
const todayStr = () => {
  const n = new Date();
  return `${n.getFullYear()}-${String(n.getMonth()+1).padStart(2,"0")}-${String(n.getDate()).padStart(2,"0")}`;
};
const nowTimeStr = () => {
  const n = new Date();
  return `${String(n.getHours()).padStart(2,"0")}:${String(n.getMinutes()).padStart(2,"0")}`;
};

// ── KPI TREND CHART — live from Firebase obs, ncr, incidents ─────────────────
// Builds 6-month rolling window from actual Firestore records.
// Data sources:
//   observations  → obs count, near miss, good practice
//   ncr           → open NCRs
//   incidents     → incidents register (INJ/MVA/FAC/LTI etc.)
// IMPORTANT: incidents and observations are SEPARATE collections.
// The chart never substitutes observations for incidents — 0 is shown as 0.
const KPITrendChart = ({obs, ncr, incidents, C}) => {
  const trendData = useMemo(()=>buildMonthWindow(6).map(m=>{
    const monthObs = obs.filter(o=>m.inMonth(o.date));
    const monthNcr = ncr.filter(n=>m.inMonth(n.date||n.created_at));
    const monthIncidents = (incidents||[]).filter(inc=>m.inMonth(inc.date));
    const damCode = (inc) => (inc.damInjEnv||"").toUpperCase().trim();
    return {
      month:        m.label,
      observations: monthObs.length,
      nearMiss:     monthObs.filter(o=>o.type==="Near Miss").length,
      incidents:    monthIncidents.length,
      injuries:     monthIncidents.filter(inc=>["INJ","FAC","MTC","LTI","RWC"].includes(damCode(inc))).length,
      mva:          monthIncidents.filter(inc=>damCode(inc)==="MVA").length,
      ncrOpen:      monthNcr.filter(n=>n.status!=="Closed").length,
      positiveObs:  monthObs.filter(o=>o.type==="Good Practice").length,
    };
  }),[obs, ncr, incidents]);

  const hasObs = obs.length > 0;
  const hasInc = (incidents||[]).length > 0;
  const hasNcr = ncr.length > 0;

  return(
    <Card C={C}>
      <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:14,flexWrap:"wrap",gap:8}}>
        <SectionTitle C={C} style={{margin:0}}>6-Month KPI Trend</SectionTitle>
        <div style={{display:"flex",alignItems:"center",gap:10,flexWrap:"wrap"}}>
          {[["Obs",hasObs,C.teal],["Incidents",hasInc,C.red],["NCR",hasNcr,C.indigo]].map(([lbl,active,col])=>(
            <div key={lbl} style={{display:"flex",alignItems:"center",gap:4}}>
              <div style={{width:6,height:6,borderRadius:"50%",background:active?col:C.muted}}/>
              <span style={{fontSize:10,color:active?col:C.muted,fontWeight:600}}>{lbl} {active?"✓":"empty"}</span>
            </div>
          ))}
        </div>
      </div>
      <ResponsiveContainer width="100%" height={240}>
        <LineChart data={trendData}>
          <CartesianGrid strokeDasharray="3 3" stroke={C.border}/>
          <XAxis dataKey="month" tick={{fill:C.muted,fontSize:11}}/>
          <YAxis tick={{fill:C.muted,fontSize:11}} allowDecimals={false}/>
          <Tooltip contentStyle={chartTooltip(C)} formatter={(value, name) => [value, name]}/>
          <Legend/>
          <Line type="monotone" dataKey="observations" name="Observations" stroke={C.teal}   strokeWidth={2} dot={{r:3}}/>
          <Line type="monotone" dataKey="incidents"    name="Incidents"    stroke={C.red}    strokeWidth={2} dot={{r:3}}/>
          <Line type="monotone" dataKey="nearMiss"     name="Near Miss"    stroke={C.yellow} strokeWidth={2} dot={{r:3}}/>
          <Line type="monotone" dataKey="ncrOpen"      name="Open NCRs"   stroke={C.indigo} strokeWidth={2} dot={{r:3}} strokeDasharray="4 2"/>
        </LineChart>
      </ResponsiveContainer>
      {!hasInc&&(
        <div style={{marginTop:10,padding:"8px 14px",background:C.orange+"11",border:`1px solid ${C.orange}33`,borderRadius:8,fontSize:11,color:C.orange}}>
          ⚠️ Incident register is empty — log incidents via the Weekly → Incident Register section to populate this chart.
        </div>
      )}
    </Card>
  );
};

// ── KPI DASHBOARD ─────────────────────────────────────────────────────────────
// TRIR and LTIR are AUTO-COMPUTED from live incidents + manualStats manhours.
// Formula: TRIR = (recordable incidents × 200,000) / total manhours
//          LTIR = (LTI incidents       × 200,000) / total manhours
// All other KPIs remain manually editable via "Edit KPIs".
const KPIDashboard = ({userRole,kpis,setKpis,radarData,setRadarData,obs=[],ncr=[],incidents=[],manualStats={},C}) => {
  const [editKpi,setEditKpi]   = useState(false);
  const [editRadar,setEditRadar] = useState(false);
  const [draft,setDraft]       = useState(kpis);
  const [draftRadar,setDraftRadar] = useState(radarData);
  const [showAddKpi,setShowAddKpi] = useState(false);
  const [newKpi,setNewKpi]     = useState({label:"",value:0,target:0,unit:"",trend:0,good:"high"});
  const [saving,setSaving]     = useState(false);

  useEffect(()=>{ if(!editKpi) setDraft(kpis); },[kpis, editKpi]);
  // eslint-disable-next-line no-unused-vars
  useEffect(()=>{ if(!editRadar) setDraftRadar(radarData); },[radarData, editRadar]);

  // ── Auto-compute TRIR and LTIR from live data ─────────────────────────────
  const computedKpis = useMemo(()=>{
    // Man-hours: use project total, fall back to year, then monthly×12
    // NEVER fall back to 1 — that would give absurd TRIR values
    const manhours = (
      Number(manualStats?.manhoursProject) ||
      Number(manualStats?.manhoursYear)    ||
      Number(manualStats?.manhoursMonth) * 12 ||
      0   // 0 means "not configured yet" — show 0 for TRIR/LTIR
    );

    // Recordable incidents: INJ, FAC, MTC, LTI, RWC (any bodily harm)
    const recordable = incidents.filter(i=>
      ["INJ","FAC","MTC","LTI","RWC"].includes((i.damInjEnv||"").toUpperCase().trim())
    ).length;
    // Lost Time Injuries only
    const lti = incidents.filter(i=>
      (i.damInjEnv||"").toUpperCase().trim()==="LTI"
    ).length;
    // Near misses from observations
    const nearMissCount = obs.filter(o=>o.type==="Near Miss").length;
    // Observations this month
    const now = new Date();
    const obsThisMonth = obs.filter(o=>{
      const d = new Date(o.date);
      return !isNaN(d) && d.getFullYear()===now.getFullYear() && d.getMonth()===now.getMonth();
    }).length;

    // TRIR = (Recordable × 200,000) ÷ manhours  — only if manhours > 10,000
    // Guard: if manhours < 10,000 it means it hasn't been entered yet — show 0
    const trir = manhours >= 10000 ? Math.round((recordable * 200000 / manhours) * 100) / 100 : 0;
    const ltir = manhours >= 10000 ? Math.round((lti        * 200000 / manhours) * 100) / 100 : 0;

    // Merge computed values into kpis array — replace TRIR and LTIR values only
    return kpis.map(k=>{
      if(k.label==="TRIR")     return {...k, value:trir,  computed:true};
      if(k.label==="LTIR")     return {...k, value:ltir,  computed:true};
      if(k.label==="Near Miss")return {...k, value:nearMissCount, computed:true};
      if(k.label==="Observations") return {...k, value:obsThisMonth||obs.length, computed:true};
      return k;
    });
  },[kpis, incidents, obs, manualStats]);

  const saveKpi=async()=>{
    setSaving(true);
    setKpis(draft);
    await saveSettings({kpis:draft});
    setSaving(false);setEditKpi(false);setShowAddKpi(false);
  };
  const cancelKpi=()=>{setDraft(kpis);setEditKpi(false);setShowAddKpi(false);};
  const saveRadar=async()=>{
    setSaving(true);
    setRadarData(draftRadar);
    await saveSettings({radarData:draftRadar});
    setSaving(false);setEditRadar(false);
  };
  const deleteKpiCard=(idx)=>setDraft(p=>p.filter((_,i)=>i!==idx));
  const addKpiCard=()=>{
    if(!newKpi.label.trim()) return;
    setDraft(p=>[...p,{...newKpi,value:Number(newKpi.value),target:Number(newKpi.target),trend:Number(newKpi.trend)}]);
    setNewKpi({label:"",value:0,target:0,unit:"",trend:0,good:"high"});
    setShowAddKpi(false);
  };

  return(
    <div style={{display:"flex",flexDirection:"column",gap:16}}>

      {/* ── Live computation notice ── */}
      <div style={{background:C.teal+"11",border:`1px solid ${C.teal}33`,borderRadius:10,padding:"10px 16px",display:"flex",alignItems:"center",gap:10,flexWrap:"wrap"}}>
        <div style={{width:7,height:7,borderRadius:"50%",background:incidents.length>0?C.green:C.yellow,flexShrink:0}}/>
        <span style={{fontSize:12,color:C.teal,fontWeight:600}}>
          TRIR & LTIR auto-computed from live incident register
          {incidents.length>0
            ? ` — ${incidents.length} incidents · ${(Number(manualStats?.manhoursProject)||0).toLocaleString()} project manhours`
            : " — import your incident register to activate"}
        </span>
      </div>

      {/* ── KPI Cards header ── */}
      <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",flexWrap:"wrap",gap:8}}>
        <h3 style={{color:C.text,fontWeight:700,margin:0,fontSize:15}}>KPI Performance</h3>
        <div style={{display:"flex",gap:8,alignItems:"center"}}>
          <SavingBadge saving={saving} C={C}/>
          {(userRole==="admin"||userRole==="editor")&&(editKpi
            ?<><Btn onClick={saveKpi} color={C.green}><Save size={14}/>Save KPIs</Btn><Btn onClick={cancelKpi} color={C.muted} style={{background:C.border}}>Cancel</Btn></>
            :<Btn onClick={()=>{setDraft(kpis);setEditKpi(true);}} color={C.blue}><Edit2 size={14}/>Edit KPIs</Btn>)}
        </div>
      </div>

      {editKpi?(
        <div style={{background:C.card,border:`1px solid ${C.blue}44`,borderRadius:14,padding:20}}>
          <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:16}}>
            <h3 style={{color:C.text,fontWeight:700,margin:0,fontSize:14}}>✏️ Edit KPI Cards</h3>
            <Btn onClick={()=>setShowAddKpi(s=>!s)} color={C.teal}><Plus size={14}/>{showAddKpi?"Cancel Add":"Add KPI"}</Btn>
          </div>
          {showAddKpi&&(
            <div style={{background:C.bg,border:`1px solid ${C.teal}44`,borderRadius:10,padding:14,marginBottom:16}}>
              <div style={{color:C.teal,fontWeight:700,fontSize:13,marginBottom:10}}>➕ New KPI Card</div>
              <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fit,minmax(150px,1fr))",gap:8}}>
                <Field label="Label *" C={C}><Inp C={C} placeholder="e.g. Fatality Rate" value={newKpi.label} onChange={e=>setNewKpi(p=>({...p,label:e.target.value}))}/></Field>
                <Field label="Current Value" C={C}><Inp C={C} type="number" value={newKpi.value} onChange={e=>setNewKpi(p=>({...p,value:e.target.value}))}/></Field>
                <Field label="Target" C={C}><Inp C={C} type="number" value={newKpi.target} onChange={e=>setNewKpi(p=>({...p,target:e.target.value}))}/></Field>
                <Field label="Unit (optional)" C={C}><Inp C={C} placeholder="%, /mo …" value={newKpi.unit} onChange={e=>setNewKpi(p=>({...p,unit:e.target.value}))}/></Field>
                <Field label="Trend %" C={C}><Inp C={C} type="number" value={newKpi.trend} onChange={e=>setNewKpi(p=>({...p,trend:e.target.value}))}/></Field>
                <Field label="Good Direction" C={C}>
                  <Sel C={C} value={newKpi.good} onChange={e=>setNewKpi(p=>({...p,good:e.target.value}))}>
                    <option value="low">Low is better</option><option value="high">High is better</option>
                  </Sel>
                </Field>
              </div>
              <Btn onClick={addKpiCard} color={C.teal} style={{marginTop:10}}><Plus size={14}/>Add KPI Card</Btn>
            </div>
          )}
          <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fit,minmax(280px,1fr))",gap:16}}>
            {draft.map((kpi,i)=>(
              <div key={kpi.label+i} style={{background:C.bg,borderRadius:10,padding:14}}>
                <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:10}}>
                  <div style={{color:C.teal,fontWeight:700,fontSize:13}}>{kpi.label||"New KPI"}</div>
                  {kpi.label!=="TRIR"&&kpi.label!=="LTIR"&&kpi.label!=="Near Miss"&&kpi.label!=="Observations"
                    ?<button onClick={()=>deleteKpiCard(i)} style={{background:C.red+"22",border:`1px solid ${C.red}44`,color:C.red,borderRadius:6,padding:"3px 8px",cursor:"pointer",fontSize:11,fontWeight:700,display:"flex",alignItems:"center",gap:3}}><Trash2 size={11}/>Delete</button>
                    :<span style={{background:C.teal+"22",color:C.teal,fontSize:10,padding:"2px 8px",borderRadius:99,fontWeight:700}}>Auto-computed</span>
                  }
                </div>
                <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:8}}>
                  <Field label="Label" C={C}><Inp C={C} value={draft[i].label} onChange={e=>setDraft(p=>p.map((k,j)=>j===i?{...k,label:e.target.value}:k))}/></Field>
                  <Field label="Unit" C={C}><Inp C={C} value={draft[i].unit} onChange={e=>setDraft(p=>p.map((k,j)=>j===i?{...k,unit:e.target.value}:k))}/></Field>
                  <Field label="Target" C={C}><Inp C={C} type="number" value={draft[i].target} onChange={e=>setDraft(p=>p.map((k,j)=>j===i?{...k,target:Number(e.target.value)}:k))}/></Field>
                  <Field label="Trend %" C={C}><Inp C={C} type="number" value={draft[i].trend} onChange={e=>setDraft(p=>p.map((k,j)=>j===i?{...k,trend:Number(e.target.value)}:k))}/></Field>
                  <Field label="Good Direction" C={C}>
                    <Sel C={C} value={draft[i].good} onChange={e=>setDraft(p=>p.map((k,j)=>j===i?{...k,good:e.target.value}:k))}>
                      <option value="low">Low is better</option><option value="high">High is better</option>
                    </Sel>
                  </Field>
                  {(kpi.label==="TRIR"||kpi.label==="LTIR")&&(
                    <div style={{gridColumn:"1/-1",background:C.teal+"11",borderRadius:8,padding:"8px 10px",fontSize:11,color:C.teal}}>
                      ℹ️ Value auto-computed from incidents + manhours. Edit Target only.
                    </div>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>
      ):(
        /* ── KPI Cards grid — equal width, aligned ── */
        <div style={{display:"grid",gridTemplateColumns:"repeat(3,1fr)",gap:14}}>
          {computedKpis.map(k=><KPICard key={k.label} kpi={k} C={C}/>)}
        </div>
      )}

      {/* Trend Chart */}
      <KPITrendChart obs={obs} ncr={ncr} incidents={incidents} C={C}/>

      {/* Radar */}
      <div style={{background:C.card,border:`1px solid ${C.border}`,borderRadius:14,padding:18}}>
        <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:14,flexWrap:"wrap",gap:8}}>
          <h3 style={{color:C.text,fontWeight:700,margin:0}}>HSSE Performance Radar</h3>
          {(userRole==="admin"||userRole==="editor")&&(editRadar
            ?<><Btn onClick={saveRadar} color={C.green}><Save size={14}/>Save Radar</Btn><Btn onClick={()=>{setDraftRadar(radarData);setEditRadar(false);}} color={C.muted} style={{background:C.border}}>Cancel</Btn></>
            :<Btn onClick={()=>{setDraftRadar(radarData);setEditRadar(true);}} color={C.blue}><Edit2 size={14}/>Edit Radar</Btn>)}
        </div>
        {editRadar&&(
          <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fit,minmax(200px,1fr))",gap:12,marginBottom:16}}>
            {draftRadar.map((item,i)=>(
              <div key={item.subject} style={{background:C.bg,borderRadius:10,padding:12}}>
                <div style={{color:C.sub,fontSize:12,marginBottom:6,fontWeight:600}}>{item.subject}</div>
                <div style={{display:"flex",alignItems:"center",gap:8}}>
                  <Inp C={C} type="number" min={0} max={100} value={draftRadar[i].A} onChange={e=>setDraftRadar(p=>p.map((r,j)=>j===i?{...r,A:Number(e.target.value)}:r))}/>
                  <span style={{color:C.muted,fontSize:12,whiteSpace:"nowrap"}}>/ 100</span>
                </div>
                <div style={{height:4,borderRadius:99,background:C.border,marginTop:8}}>
                  <div style={{width:`${draftRadar[i].A}%`,background:draftRadar[i].A>=80?C.green:draftRadar[i].A>=60?C.yellow:C.red,height:4,borderRadius:99}}/>
                </div>
              </div>
            ))}
          </div>
        )}
        <ResponsiveContainer width="100%" height={280}>
          <RadarChart data={editRadar?draftRadar:radarData}>
            <PolarGrid stroke={C.border}/>
            <PolarAngleAxis dataKey="subject" tick={{fill:C.sub,fontSize:11}}/>
            <PolarRadiusAxis domain={[0,100]} tick={{fill:C.muted,fontSize:10}}/>
            <Radar name="Score" dataKey="A" stroke={C.teal} fill={C.teal} fillOpacity={0.3}/>
            <Tooltip contentStyle={chartTooltip(C)}/>
          </RadarChart>
        </ResponsiveContainer>
      </div>

      {/* KPI Summary Table */}
      <TableCard title="KPI Summary" C={C}>
        <table style={{width:"100%",borderCollapse:"collapse"}}>
          <thead><tr>{["KPI","Current Value","Target","Unit","Trend","Status","Source"].map(h=><Th key={h} C={C}>{h}</Th>)}</tr></thead>
          <tbody>
            {computedKpis.map(k=>{
              const good=k.good==="high"?k.value>=k.target:k.value<=k.target;
              return(
                <tr key={k.label} onMouseEnter={e=>e.currentTarget.style.background=C.border+"33"} onMouseLeave={e=>e.currentTarget.style.background="transparent"}>
                  <Td C={C} style={{color:C.text,fontWeight:600}}>{k.label}</Td>
                  <Td C={C} style={{color:C.text,fontWeight:700,fontSize:15}}>{k.value}{k.unit}</Td>
                  <Td C={C}>{k.target}{k.unit}</Td>
                  <Td C={C}>{k.unit||"—"}</Td>
                  <Td C={C}><span style={{color:k.trend>0?C.green:C.red,fontWeight:700,display:"flex",alignItems:"center",gap:3}}>{k.trend>0?<ArrowUp size={13}/>:<ArrowDown size={13}/>}{Math.abs(k.trend)}%</span></Td>
                  <Td C={C}><Badge label={good?"On Track":"Attention"} color={good?C.green:C.orange}/></Td>
                  <Td C={C}><span style={{fontSize:10,color:k.computed?C.teal:C.muted,fontWeight:600}}>{k.computed?"🔄 Live":"✏️ Manual"}</span></Td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </TableCard>
    </div>
  );
};


// ── LOGIN ─────────────────────────────────────────────────────────────────────
// ── ERROR BOUNDARY — catches render crashes and shows a recovery screen ────────
class ErrorBoundary extends React.Component {
  constructor(props){ super(props); this.state={hasError:false,error:null}; }
  static getDerivedStateFromError(error){ return {hasError:true,error}; }
  componentDidCatch(error,info){
    console.error("[HSSE] Render error:",error);
    console.error("[HSSE] Component stack:",info?.componentStack);
  }
  render(){
    if(this.state.hasError){
      return(
        <div style={{minHeight:"100vh",background:"#0f172a",display:"flex",alignItems:"center",justifyContent:"center",fontFamily:"Inter,sans-serif",padding:24}}>
          <div style={{background:"#1e293b",border:"1px solid #ef444444",borderRadius:16,padding:32,maxWidth:480,width:"100%",textAlign:"center"}}>
            <div style={{fontSize:40,marginBottom:16}}>⚠️</div>
            <h2 style={{color:"#ef4444",fontWeight:700,fontSize:18,margin:"0 0 12px"}}>Something went wrong</h2>
            <p style={{color:"#94a3b8",fontSize:13,marginBottom:20,lineHeight:1.7}}>
              An unexpected error occurred. Your data is safe — this is a display error only.
            </p>
            <div style={{background:"#0f172a",borderRadius:8,padding:12,marginBottom:20,textAlign:"left"}}>
              <code style={{color:"#f87171",fontSize:11,wordBreak:"break-all"}}>{this.state.error?.message||"Unknown error"}</code>
            </div>
            <button onClick={()=>window.location.reload()}
              style={{background:"linear-gradient(135deg,#14b8a6,#6366f1)",color:"#fff",border:"none",borderRadius:10,padding:"12px 24px",fontWeight:700,fontSize:14,cursor:"pointer"}}>
              Reload Application
            </button>
          </div>
        </div>
      );
    }
    return this.props.children;
  }
}

const Login = ({C}) => {
  const [email,setEmail]=useState("");
  const [pass,setPass]=useState("");
  const [err,setErr]=useState("");
  const [loading,setLoading]=useState(false);
  const [showPass,setShowPass]=useState(false);
  const [failCount,setFailCount]=useState(0);
  const [lockUntil,setLockUntil]=useState(0);

  const submit=async()=>{
    // Client-side rate limiting: lock after 5 failures for 30 seconds
    if(Date.now()<lockUntil){
      const secs=Math.ceil((lockUntil-Date.now())/1000);
      setErr(`Too many failed attempts. Please wait ${secs} seconds.`);
      return;
    }
    if(!email.trim()||!pass){setErr("Please enter your email and password.");return;}
    setLoading(true);setErr("");
    try{
      await signInWithEmailAndPassword(auth,email.trim(),pass);
      setFailCount(0); // reset on success
    }catch(e){
      const newCount=failCount+1;
      setFailCount(newCount);
      if(newCount>=5) setLockUntil(Date.now()+30000); // 30-second lockout
      const msg={
        "auth/invalid-credential":"Incorrect email or password.",
        "auth/user-not-found":"No account found with this email.",
        "auth/wrong-password":"Incorrect password.",
        "auth/too-many-requests":"Too many attempts. Please wait a few minutes and try again.",
        "auth/user-disabled":"This account has been disabled. Contact your administrator.",
        "auth/network-request-failed":"Network error. Check your connection and try again.",
      };
      setErr(msg[e.code]||"Login failed. Please try again.");
      console.warn("[HSSE] Login failure:",e.code,"attempt",newCount);
    }finally{setLoading(false);}
  };

  return(
    <div style={{minHeight:"100vh",background:"#0f172a",display:"flex",alignItems:"center",justifyContent:"center",fontFamily:"Inter,sans-serif",padding:16}}>
      <div style={{background:"#1e293b",border:"1px solid #334155",borderRadius:20,padding:40,width:"100%",maxWidth:400,boxShadow:"0 20px 60px rgba(0,0,0,0.5)"}}>

        {/* Logo */}
        <div style={{textAlign:"center",marginBottom:28}}>
          <div style={{display:"flex",justifyContent:"center",marginBottom:14}}><DanLogo size={100}/></div>
          <h1 style={{color:"#e2e8f0",fontWeight:900,fontSize:22,margin:0}}>DAN Company</h1>
          <p style={{color:"#14b8a6",fontSize:13,marginTop:4,fontWeight:600}}>HSSE Management System</p>
        </div>

        {/* Email */}
        <div style={{marginBottom:12}}>
          <label style={{display:"block",fontSize:12,color:"#94a3b8",marginBottom:4,fontWeight:600}}>Email Address</label>
          <div style={{position:"relative"}}>
            <Mail size={14} style={{position:"absolute",left:12,top:"50%",transform:"translateY(-50%)",color:"#64748b"}}/>
            <input type="email" placeholder="your@email.com" value={email}
              onChange={e=>setEmail(e.target.value)}
              onKeyDown={e=>e.key==="Enter"&&submit()}
              style={{width:"100%",background:"#0f172a",border:"1px solid #334155",borderRadius:8,padding:"9px 12px 9px 36px",color:"#e2e8f0",fontSize:13,outline:"none",boxSizing:"border-box"}}/>
          </div>
        </div>

        {/* Password */}
        <div style={{marginBottom:20}}>
          <label style={{display:"block",fontSize:12,color:"#94a3b8",marginBottom:4,fontWeight:600}}>Password</label>
          <div style={{position:"relative"}}>
            <Lock size={14} style={{position:"absolute",left:12,top:"50%",transform:"translateY(-50%)",color:"#64748b"}}/>
            <input type={showPass?"text":"password"} placeholder="Enter your password" value={pass}
              onChange={e=>setPass(e.target.value)}
              onKeyDown={e=>e.key==="Enter"&&submit()}
              style={{width:"100%",background:"#0f172a",border:"1px solid #334155",borderRadius:8,padding:"9px 36px 9px 36px",color:"#e2e8f0",fontSize:13,outline:"none",boxSizing:"border-box"}}/>
            <button onClick={()=>setShowPass(p=>!p)}
              style={{position:"absolute",right:10,top:"50%",transform:"translateY(-50%)",background:"none",border:"none",cursor:"pointer",color:"#64748b",padding:2}}>
              {showPass?<Eye size={14}/>:<Lock size={14}/>}
            </button>
          </div>
        </div>

        {err&&<div style={{color:"#ef4444",fontSize:12,marginBottom:12,background:"#ef444411",padding:"8px 12px",borderRadius:8}}>{err}</div>}

        {/* Sign In button */}
        <button onClick={submit} disabled={loading}
          style={{width:"100%",background:"linear-gradient(135deg,#14b8a6,#6366f1)",color:"#fff",border:"none",borderRadius:10,padding:13,fontWeight:700,fontSize:14,cursor:loading?"not-allowed":"pointer",opacity:loading?0.7:1,display:"flex",alignItems:"center",justifyContent:"center",gap:8}}>
          {loading?<><span style={{width:16,height:16,borderRadius:"50%",border:"2px solid #fff",borderTopColor:"transparent",display:"inline-block",animation:"spin 0.8s linear infinite"}}/>Signing in...</>:"Sign In"}
        </button>

        <div style={{marginTop:20,padding:10,background:"#0f172a",borderRadius:8,fontSize:11,color:"#64748b",textAlign:"center"}}>
          🔒 Secured by Neon PostgreSQL
        </div>
      </div>
    </div>
  );
};

// ── CHANGE PASSWORD ───────────────────────────────────────────────────────────
const ChangePasswordModal = ({onClose,mustChange,C}) => {
  const [newPass,setNewPass]=useState(""),[confirm,setConfirm]=useState(""),[err,setErr]=useState(""),[success,setSuccess]=useState(false);
  const save=async()=>{
    if(newPass.length<6){setErr("Password must be at least 6 characters.");return;}
    if(newPass!==confirm){setErr("Passwords do not match.");return;}
    // Validate password strength: at least one uppercase, one number
    if(!/[A-Z]/.test(newPass)&&!/[0-9]/.test(newPass)){
      setErr("Password should contain at least one uppercase letter or number for security.");
      return;
    }
    try{
      // Neon: updatePassword calls /auth/change-password endpoint
      // which sets must_change_password=FALSE in DB automatically
      await updatePassword(auth.currentUser, newPass);
      setSuccess(true);
      setTimeout(()=>onClose(), 1500);
    }catch(e){
      if(e.code==="auth/requires-recent-login"){
        setErr("For security, please log out and log back in before changing your password.");
      } else if(e.code==="auth/weak-password"){
        setErr("Password is too weak. Use at least 6 characters with numbers or uppercase.");
      } else {
        setErr("Failed to update password: "+e.message);
      }
      console.error("[HSSE] Password change failed:",e.code);
    }
  };
  return(
    <Modal title={mustChange?"🔑 Set Your New Password":"Change Password"} onClose={mustChange?null:onClose} C={C}>
      {mustChange&&<div style={{background:C.orange+"22",border:`1px solid ${C.orange}44`,borderRadius:10,padding:12,marginBottom:16,fontSize:13,color:C.orange}}>⚠️ You must set a new password before continuing.</div>}
      {success?(
        <div style={{textAlign:"center",padding:20}}><div style={{fontSize:40,marginBottom:8}}>✅</div><div style={{color:C.green,fontWeight:700}}>Password updated!</div></div>
      ):(
        <>
          <Field label="New Password" C={C}><Inp C={C} type="password" placeholder="Min 6 characters" value={newPass} onChange={e=>setNewPass(e.target.value)}/></Field>
          <Field label="Confirm Password" C={C}><Inp C={C} type="password" placeholder="Repeat new password" value={confirm} onChange={e=>setConfirm(e.target.value)}/></Field>
          {err&&<div style={{color:C.red,fontSize:12,marginBottom:12,background:C.red+"11",padding:"8px 12px",borderRadius:8}}>{err}</div>}
          <Btn onClick={save} color={C.teal} style={{width:"100%",justifyContent:"center",marginTop:4}}>Update Password</Btn>
        </>
      )}
    </Modal>
  );
};

// ── OBS DETAIL MODAL ──────────────────────────────────────────────────────────
const ObsDetail = ({obs,onClose,C}) => (
  <Modal title={`Observation — ${obs.id}`} onClose={onClose} C={C} wide={true}>
    <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:16}}>
      <div style={{display:"flex",flexDirection:"column",gap:12}}>
        <div style={{background:C.bg,borderRadius:10,padding:14}}>
          <div style={{fontSize:11,color:C.muted,marginBottom:8,fontWeight:700,textTransform:"uppercase",letterSpacing:1}}>Observation Info</div>
          {obs.source==="historical"&&(
            <div style={{background:C.indigo+"18",border:`1px solid ${C.indigo}44`,borderRadius:8,padding:"7px 12px",marginBottom:10,display:"flex",alignItems:"center",gap:7}}>
              <span style={{fontSize:14}}>📥</span>
              <div>
                <div style={{color:C.indigo,fontSize:11,fontWeight:700}}>Historical Record</div>
                <div style={{color:C.muted,fontSize:10}}>Imported from Excel · Report Ref: {obs.reportRef||"—"}</div>
              </div>
            </div>
          )}
          {[["ID",obs.id,C.teal],["Date",obs.date,null],["Time",obs.time,null],["Site",obs.site,null],["Zone",obs.area,null],["Observer",obs.observer,C.blue]].map(([l,v,c])=>(
            <div key={l} style={{display:"flex",justifyContent:"space-between",padding:"6px 0",borderBottom:`1px solid ${C.border}33`}}>
              <span style={{color:C.muted,fontSize:12}}>{l}</span>
              <span style={{color:c||C.text,fontWeight:600,fontSize:12,fontFamily:l==="ID"?"monospace":"inherit"}}>{v}</span>
            </div>
          ))}
        </div>
        <div style={{background:C.bg,borderRadius:10,padding:14}}>
          <div style={{fontSize:11,color:C.muted,marginBottom:8,fontWeight:700,textTransform:"uppercase",letterSpacing:1}}>Classification</div>
          {[["Type",obs.type],["Severity",obs.severity],["Action Required",obs.action],["Status",obs.status]].map(([l,v])=>(
            <div key={l} style={{display:"flex",justifyContent:"space-between",alignItems:"center",padding:"6px 0",borderBottom:`1px solid ${C.border}33`}}>
              <span style={{color:C.muted,fontSize:12}}>{l}</span>
              {l==="Severity"?<Badge label={v} color={sevColor(v,C)}/>:l==="Status"?<Badge label={v} color={stColor(v,C)}/>:<span style={{color:C.text,fontWeight:600,fontSize:12}}>{v}</span>}
            </div>
          ))}
        </div>
        {obs.status==="Closed"&&(
          <div style={{background:C.green+"11",border:`1px solid ${C.green}33`,borderRadius:10,padding:14}}>
            <div style={{fontSize:11,color:C.green,marginBottom:6,fontWeight:700}}>✅ CLOSEOUT INFO</div>
            <div style={{color:C.text,fontSize:13,fontWeight:600}}>{obs.closeDate} at {obs.closeTime}</div>
          </div>
        )}
      </div>
      <div style={{display:"flex",flexDirection:"column",gap:12}}>
        <div style={{background:C.bg,borderRadius:10,padding:14}}>
          <div style={{fontSize:11,color:C.muted,marginBottom:8,fontWeight:700,textTransform:"uppercase",letterSpacing:1}}>Description</div>
          <p style={{color:C.text,fontSize:13,lineHeight:1.7,margin:0}}>{obs.desc||"No description."}</p>
        </div>
        {obs.openPhoto&&(<div style={{background:C.bg,borderRadius:10,padding:14}}><div style={{fontSize:11,color:C.muted,marginBottom:8,fontWeight:700,textTransform:"uppercase",letterSpacing:1}}>📸 Opening Photo</div><img src={obs.openPhoto} alt="opening" style={{width:"100%",borderRadius:8,objectFit:"cover",maxHeight:200}}/></div>)}
        {obs.closePhoto&&(<div style={{background:C.green+"11",border:`1px solid ${C.green}33`,borderRadius:10,padding:14}}><div style={{fontSize:11,color:C.green,marginBottom:8,fontWeight:700,textTransform:"uppercase",letterSpacing:1}}>📸 Closeout Photo</div><img src={obs.closePhoto} alt="closeout" style={{width:"100%",borderRadius:8,objectFit:"cover",maxHeight:200}}/></div>)}
        {!obs.openPhoto&&!obs.closePhoto&&(<div style={{background:C.bg,borderRadius:10,padding:14,textAlign:"center",color:C.muted,fontSize:13}}>No photos attached</div>)}
      </div>
    </div>
  </Modal>
);

// ── OBS FORM ──────────────────────────────────────────────────────────────────
const ObsForm = ({user,zones,obsTypes,actionsList,obsSeverity,obsCount,onSubmit,onClose,C}) => {
  const today   = todayStr();
  const nowTime = nowTimeStr();
  const defaultSite=user.site==="All Sites"?"Site 1":user.site;
  const [form,setForm]=useState({date:today,time:nowTime,area:zones[0]||"",type:obsTypes[0]||"",severity:(obsSeverity||DEFAULT_OBS_SEVERITY)[0]||"High",action:actionsList[0]||"",status:"Open",desc:"",site:defaultSite});
  // ID is computed from current site so it updates when user changes site
  const newId=genObsId(obsCount+1, form.site);
  const [photo,setPhoto]=useState(null),[preview,setPreview]=useState(null),[uploading,setUploading]=useState(false);

  // ── AI REVIEW STATE ───────────────────────────────────────────────────────
  const [aiFlags,setAiFlags]=useState(null);   // array of {level, msg} or null
  const [aiLoading,setAiLoading]=useState(false);
  const aiTimerRef=useRef(null);

  const set=(k,v)=>setForm(p=>({...p,[k]:v}));
  const handlePhoto=e=>{const f=e.target.files[0];if(!f)return;setPhoto(f);setPreview(URL.createObjectURL(f));};

  // ── LIVE AI ANALYSIS — fires 1.5s after user stops typing ────────────────
  const handleDescChange = (e) => {
    const val = e.target.value;
    set("desc", val);
    if(aiTimerRef.current) clearTimeout(aiTimerRef.current);
    if(val.trim().length < 20) { setAiFlags(null); return; }
    aiTimerRef.current = setTimeout(()=>runAiReview(val, form), 1500);
  };

  const runAiReview = async (desc, currentForm) => {
    setAiLoading(true);
    try {
      const res = await fetch("https://api.anthropic.com/v1/messages", {
        method:"POST",
        headers:{"Content-Type":"application/json"},
        body: JSON.stringify({
          model: "claude-sonnet-4-20250514",
          max_tokens: 400,
          system: `You are an HSSE (Health, Safety, Security & Environment) expert reviewing a site observation report for quality and completeness. Your job is to flag issues ONLY — do not suggest or auto-fill values. Be concise. Respond ONLY with a JSON array of flags, no preamble, no markdown. Each flag: {"level":"warning"|"info", "msg":"short flag message"}. Return [] if nothing is wrong. Flag these issues if present: 1) Description is too vague (no specific hazard, location or detail), 2) No consequence mentioned (what could go wrong), 3) Severity seems mismatched (e.g. description sounds critical but severity is Low), 4) Good Practice observation has severity High/Medium set, 5) Description is too short to be useful (under 2 sentences), 6) Missing WHO is affected. Current severity: "${currentForm.severity}", current type: "${currentForm.type}".`,
          messages:[{role:"user", content:`Observation description: "${desc}"`}]
        })
      });
      const data = await res.json();
      const text = data.content?.[0]?.text || "[]";
      const clean = text.replace(/```json|```/g,"").trim();
      const flags = JSON.parse(clean);
      setAiFlags(Array.isArray(flags) && flags.length > 0 ? flags : null);
    } catch(err) {
      console.warn("AI review failed:", err);
      setAiFlags(null);
    } finally {
      setAiLoading(false);
    }
  };

  // Re-run AI if severity or type changes while desc is filled
  useEffect(()=>{
    if(form.desc.trim().length >= 20) {
      if(aiTimerRef.current) clearTimeout(aiTimerRef.current);
      aiTimerRef.current = setTimeout(()=>runAiReview(form.desc, form), 800);
    }
  },[form.severity, form.type, form.desc, form]);

  const submit=async()=>{
    if(!form.area||!form.desc)return;
    setUploading(true);
    try{
      let photoUrl=null;if(photo)photoUrl=await uploadPhoto(photo);
      // Await onSubmit so that if fbAdd throws, we keep the modal open and
      // don't misleadingly close it after a silent persistence failure.
      await onSubmit({...form,id:newId,seqNum:obsCount+1,observer:user.name,observerId:user.uid,openPhoto:photoUrl||"",closePhoto:"",closeDate:"",closeTime:""});
      onClose();
    }catch(e){
      console.error(e);
      // fbAdd already surfaced an alert; leave the modal open so the user
      // can retry without re-entering data.
    }finally{setUploading(false);}
  };

  return(
    <Modal title="Log New Observation" onClose={onClose} C={C}>
      <div style={{background:C.teal+"22",border:`1px solid ${C.teal}44`,borderRadius:10,padding:"10px 14px",marginBottom:12,display:"flex",justifyContent:"space-between",alignItems:"center",flexWrap:"wrap",gap:8}}>
        <div style={{display:"flex",alignItems:"center",gap:10}}>
          <UserCheck size={16} style={{color:C.teal}}/>
          <div><div style={{fontSize:12,color:C.teal,fontWeight:700}}>Observer Auto-Detected</div>
          <div style={{fontSize:13,color:C.text,fontWeight:600}}>{user.name} · {siteName(form.site)}</div></div>
        </div>
        <div style={{background:C.card,borderRadius:8,padding:"4px 10px"}}>
          <div style={{fontSize:9,color:C.muted}}>Observation ID</div>
          <div style={{fontSize:10,color:C.teal,fontFamily:"monospace",fontWeight:700}}>{newId}</div>
        </div>
      </div>
      <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:12}}>
        <Field label="Date" C={C}><Inp C={C} type="date" value={form.date} onChange={e=>set("date",e.target.value)}/></Field>
        <Field label="Time" C={C}><Inp C={C} type="time" value={form.time} onChange={e=>set("time",e.target.value)}/></Field>
        <Field label="Site" C={C}><Sel C={C} value={form.site} onChange={e=>set("site",e.target.value)}>{SITES.map(s=><option key={s.id} value={s.id}>{s.name}</option>)}</Sel></Field>
        <Field label="Zone / Area" C={C}><Sel C={C} value={form.area} onChange={e=>set("area",e.target.value)}>{zones.map(z=><option key={z}>{z}</option>)}</Sel></Field>
        <Field label="Type" C={C}><Sel C={C} value={form.type} onChange={e=>set("type",e.target.value)}>{obsTypes.map(t=><option key={t}>{t}</option>)}</Sel></Field>
        <Field label="Severity" C={C}><Sel C={C} value={form.severity} onChange={e=>set("severity",e.target.value)}>{(obsSeverity||DEFAULT_OBS_SEVERITY).map(s=><option key={s}>{s}</option>)}</Sel></Field>
        <Field label="Action Required" C={C}><Sel C={C} value={form.action} onChange={e=>set("action",e.target.value)}>{actionsList.map(a=><option key={a}>{a}</option>)}</Sel></Field>
        <Field label="Status" C={C}><Sel C={C} value={form.status} onChange={e=>set("status",e.target.value)}>{["Open","Under Review","Closed"].map(s=><option key={s}>{s}</option>)}</Sel></Field>
      </div>

      {/* Description with live AI monitoring */}
      <Field label="Description" C={C}>
        <div style={{position:"relative"}}>
          <Txa C={C} rows={3} placeholder="Describe the observation in detail..." value={form.desc} onChange={handleDescChange}
            style={{borderColor: aiFlags&&aiFlags.length>0 ? C.orange : undefined}}/>
          {aiLoading&&(
            <div style={{position:"absolute",top:8,right:10,display:"flex",alignItems:"center",gap:5,background:C.card,borderRadius:6,padding:"2px 8px",border:`1px solid ${C.border}`}}>
              <div style={{width:8,height:8,borderRadius:"50%",border:`2px solid ${C.teal}`,borderTopColor:"transparent",animation:"spin 0.8s linear infinite"}}/>
              <span style={{fontSize:10,color:C.muted}}>AI reviewing...</span>
            </div>
          )}
        </div>
      </Field>

      {/* AI Flag Panel — only shows if flags exist */}
      {aiFlags&&aiFlags.length>0&&(
        <div style={{background:C.orange+"11",border:`1px solid ${C.orange}33`,borderRadius:10,padding:"10px 14px",marginTop:-8,marginBottom:4}}>
          <div style={{display:"flex",alignItems:"center",gap:6,marginBottom:8}}>
            <AlertTriangle size={13} style={{color:C.orange,flexShrink:0}}/>
            <span style={{fontSize:11,color:C.orange,fontWeight:700,textTransform:"uppercase",letterSpacing:0.5}}>AI Quality Check</span>
            <span style={{fontSize:10,color:C.muted,marginLeft:"auto"}}>Review before submitting</span>
          </div>
          <div style={{display:"flex",flexDirection:"column",gap:6}}>
            {aiFlags.map((flag,i)=>(
              <div key={i} style={{display:"flex",alignItems:"flex-start",gap:8}}>
                <div style={{width:6,height:6,borderRadius:"50%",background:flag.level==="warning"?C.orange:C.blue,flexShrink:0,marginTop:4}}/>
                <span style={{fontSize:12,color:flag.level==="warning"?C.text:C.sub,lineHeight:1.5}}>{flag.msg}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* All clear message */}
      {aiFlags&&aiFlags.length===0&&form.desc.trim().length>=20&&(
        <div style={{background:C.green+"11",border:`1px solid ${C.green}33`,borderRadius:10,padding:"8px 14px",marginTop:-8,display:"flex",alignItems:"center",gap:6}}>
          <span style={{color:C.green,fontSize:12}}>✓</span>
          <span style={{fontSize:12,color:C.green,fontWeight:600}}>Description looks complete and clear</span>
        </div>
      )}

      <PhotoBox id="obsPhotoInput" preview={preview} onSelect={handlePhoto} onRemove={()=>{setPhoto(null);setPreview(null);}} label="📸 Opening Photo" C={C}/>
      <Btn onClick={submit} color={C.teal} disabled={uploading} style={{marginTop:8,width:"100%",justifyContent:"center"}}>{uploading?"Uploading...":"Submit Observation"}</Btn>
    </Modal>
  );
};

// ── CLOSEOUT MODAL ────────────────────────────────────────────────────────────
const CloseoutModal = ({obs,onClose,C}) => {
  const [closeDate,setCloseDate]=useState(todayStr()),[closeTime,setCloseTime]=useState(nowTimeStr());
  const [photo,setPhoto]=useState(null),[preview,setPreview]=useState(obs.closePhoto||null),[uploading,setUploading]=useState(false);
  const handlePhoto=e=>{const f=e.target.files[0];if(!f)return;setPhoto(f);setPreview(URL.createObjectURL(f));};
  const save=async()=>{
    setUploading(true);
    try{
      let url=obs.closePhoto||"";if(photo)url=await uploadPhoto(photo);
      await updateDoc(doc(db,"observations",obs._docId),{status:"Closed",closeDate,closeTime,closePhoto:url});
      onClose();
    }catch(e){
      console.error(e);
      try{ window.alert(`⚠️ Close-out did not save: ${e?.message||"Unknown error"}`); }catch{}
    }finally{setUploading(false);}
  };
  return(
    <Modal title="✅ Close Out Observation" onClose={onClose} C={C}>
      <div style={{background:C.bg,border:`1px solid ${C.border}`,borderRadius:10,padding:12,marginBottom:16}}>
        <div style={{fontSize:12,color:C.muted,marginBottom:4}}>ID: <span style={{color:C.teal,fontWeight:700,fontFamily:"monospace"}}>{obs.id}</span></div>
        <div style={{fontSize:13,color:C.text,marginBottom:6}}>{obs.desc}</div>
        <div style={{fontSize:11,color:C.muted}}>Opened: {obs.date} {obs.time} · {obs.observer}</div>
        {obs.openPhoto&&<img src={obs.openPhoto} alt="opening" style={{maxHeight:80,borderRadius:6,objectFit:"cover",marginTop:8}}/>}
      </div>
      <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:12}}>
        <Field label="Closeout Date" C={C}><Inp C={C} type="date" value={closeDate} onChange={e=>setCloseDate(e.target.value)}/></Field>
        <Field label="Closeout Time" C={C}><Inp C={C} type="time" value={closeTime} onChange={e=>setCloseTime(e.target.value)}/></Field>
      </div>
      <PhotoBox id="closePhotoInput" preview={preview} onSelect={handlePhoto} onRemove={()=>{setPhoto(null);setPreview(null);}} label="📸 Closeout Photo" C={C}/>
      <Btn onClick={save} color={C.green} disabled={uploading} style={{marginTop:8,width:"100%",justifyContent:"center"}}>{uploading?"Saving...":"✅ Close Out Observation"}</Btn>
    </Modal>
  );
};

// ── OBSERVATIONS ──────────────────────────────────────────────────────────────
// ── EXCEL IMPORT PREVIEW MODAL ────────────────────────────────────────────────
const ExcelImportModal = ({preview,fileNames,importing,importProgress,existingIds,onConfirm,onClose,C}) => {
  // Auto-deselect duplicates by default
  const [selected,setSelected]=useState(()=>new Set(
    preview.map((_,i)=>i).filter(i=>!existingIds.has(preview[i].id))
  ));
  const toggleRow=i=>setSelected(p=>{const n=new Set(p);n.has(i)?n.delete(i):n.add(i);return n;});
  // eslint-disable-next-line no-unused-vars
  const toggleAll=()=>{
    const newIds=preview.map((_,i)=>i).filter(i=>!existingIds.has(preview[i].id));
    setSelected(selected.size===newIds.length&&[...selected].every(i=>newIds.includes(i))?new Set():new Set(newIds));
  };
  const newCount=preview.filter(r=>!existingIds.has(r.id)).length;
  const dupCount=preview.filter(r=>existingIds.has(r.id)).length;
  const priorityColor=(p,C)=>({High:C.red,Medium:C.orange,Low:C.yellow,"Good Practice":C.green}[p]||C.muted);

  return(
    <div style={{position:"fixed",inset:0,background:"rgba(0,0,0,0.82)",zIndex:1000,display:"flex",alignItems:"center",justifyContent:"center",padding:16}}>
      <div style={{background:C.card,border:`1px solid ${C.border}`,borderRadius:18,padding:24,width:"100%",maxWidth:960,maxHeight:"92vh",overflowY:"auto",boxShadow:"0 24px 60px rgba(0,0,0,0.5)"}}>

        {/* Header */}
        <div style={{display:"flex",justifyContent:"space-between",alignItems:"flex-start",marginBottom:16}}>
          <div>
            <h3 style={{color:C.text,fontWeight:800,fontSize:17,margin:0}}>📥 Import Historical Data from Excel</h3>
            <p style={{color:C.muted,fontSize:12,margin:"5px 0 0"}}>{fileNames.length} file{fileNames.length!==1?"s":""} · {preview.length} observations found across all files</p>
            <div style={{display:"flex",flexWrap:"wrap",gap:4,marginTop:6}}>
              {fileNames.map((fn,i)=>(
                <span key={i} style={{background:C.teal+"18",border:`1px solid ${C.teal}33`,color:C.teal,fontSize:10,fontWeight:600,padding:"2px 8px",borderRadius:99}}>{fn}</span>
              ))}
            </div>
          </div>
          <button onClick={onClose} style={{background:"none",border:"none",cursor:"pointer",color:C.muted,fontSize:24,lineHeight:1}}>×</button>
        </div>
        {/* Progress bar during import */}
        {importing&&importProgress&&(
          <div style={{background:C.bg,border:`1px solid ${C.border}`,borderRadius:10,padding:"10px 14px",marginBottom:14}}>
            <div style={{display:"flex",justifyContent:"space-between",fontSize:12,color:C.teal,fontWeight:700,marginBottom:6}}>
              <span>⏳ {importProgress.msg}</span>
              <span>{importProgress.done}/{importProgress.total}</span>
            </div>
            <div style={{height:6,borderRadius:99,background:C.border}}>
              <div style={{width:`${Math.round((importProgress.done/importProgress.total)*100)}%`,background:C.teal,height:6,borderRadius:99,transition:"width 0.3s"}}/>
            </div>
          </div>
        )}

        {/* Banners */}
        <div style={{display:"flex",flexDirection:"column",gap:8,marginBottom:14}}>
          <div style={{background:C.indigo+"18",border:`1px solid ${C.indigo}44`,borderRadius:10,padding:"9px 14px",fontSize:12,color:C.indigo,display:"flex",alignItems:"center",gap:8}}>
            <span style={{fontSize:15}}>📥</span>
            <span>These records will be saved as <strong>Historical Data</strong> — they keep their original Reference IDs from Excel and will show a <strong>📥 Historical</strong> badge in the table.</span>
          </div>
          {dupCount>0&&(
            <div style={{background:C.yellow+"18",border:`1px solid ${C.yellow}44`,borderRadius:10,padding:"9px 14px",fontSize:12,color:C.yellow,display:"flex",alignItems:"center",gap:8}}>
              <span style={{fontSize:15}}>⚠️</span>
              <span><strong>{dupCount} duplicate{dupCount!==1?"s":""} detected</strong> — already exist in the database (matched by Reference ID). They are unchecked and will be skipped automatically.</span>
            </div>
          )}
        </div>

        {/* Summary pills */}
        <div style={{display:"flex",gap:8,flexWrap:"wrap",marginBottom:14,alignItems:"center"}}>
          {[["High",preview.filter(r=>r.severity==="High").length,C.red],["Medium",preview.filter(r=>r.severity==="Medium").length,C.orange],["Low",preview.filter(r=>r.severity==="Low").length,C.yellow],["Good Practice",preview.filter(r=>r.severity==="Positive").length,C.green]].map(([l,v,c])=>(
            v>0&&<div key={l} style={{background:c+"18",border:`1px solid ${c}44`,borderRadius:8,padding:"4px 12px",fontSize:12,color:c,fontWeight:700}}>{v} {l}</div>
          ))}
          <div style={{marginLeft:"auto",fontSize:12,color:C.muted}}>
            <span style={{color:C.teal,fontWeight:700}}>{selected.size} new</span>
            {dupCount>0&&<span style={{color:C.yellow,fontWeight:700,marginLeft:8}}>{dupCount} skipped (duplicate)</span>}
          </div>
        </div>

        {/* Table */}
        <div style={{overflowX:"auto",border:`1px solid ${C.border}`,borderRadius:10}}>
          <table style={{width:"100%",borderCollapse:"collapse",minWidth:760}}>
            <thead>
              <tr style={{background:C.bg}}>
                <Th C={C} style={{width:36}}>
                  <input type="checkbox"
                    checked={selected.size===newCount&&newCount>0}
                    onChange={toggleAll}
                    style={{accentColor:C.teal,width:14,height:14,cursor:"pointer"}}/>
                </Th>
                {["Reference ID","#","Type / Category","Description (preview)","Zone","Priority","Status","Date","File"].map(h=><Th key={h} C={C}>{h}</Th>)}
              </tr>
            </thead>
            <tbody>
              {preview.map((row,i)=>{
                const isDup=existingIds.has(row.id);
                const isSel=selected.has(i);
                const pc=priorityColor(row.severity==="Positive"?"Good Practice":row.severity,C);
                return(
                  <tr key={i}
                    style={{background:isDup?C.yellow+"08":isSel?"transparent":C.border+"22",opacity:isDup?0.4:isSel?1:0.5,cursor:isDup?"not-allowed":"pointer"}}
                    onClick={()=>!isDup&&toggleRow(i)}
                    onMouseEnter={e=>{if(!isDup&&isSel)e.currentTarget.style.background=C.border+"33";}}
                    onMouseLeave={e=>{e.currentTarget.style.background=isDup?C.yellow+"08":isSel?"transparent":C.border+"22";}}>
                    <Td C={C} style={{width:36}}>
                      {isDup
                        ? <span title="Duplicate — already exists" style={{color:C.yellow,fontSize:14}}>⚠️</span>
                        : <input type="checkbox" checked={isSel} onChange={()=>toggleRow(i)} onClick={e=>e.stopPropagation()} style={{accentColor:C.teal,width:14,height:14,cursor:"pointer"}}/>
                      }
                    </Td>
                    <Td C={C} style={{fontFamily:"monospace",fontSize:9,color:isDup?C.yellow:C.teal,whiteSpace:"nowrap"}}>{row.id}</Td>
                    <Td C={C} style={{color:C.muted,fontSize:11,fontWeight:700}}>{row.srNo}</Td>
                    <Td C={C} style={{color:C.text,fontWeight:600,whiteSpace:"nowrap",fontSize:12}}>{row.type}</Td>
                    <Td C={C} style={{maxWidth:200,fontSize:11,color:C.sub}}>
                      <div style={{overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap",maxWidth:200}} title={row.desc}>{row.desc}</div>
                    </Td>
                    <Td C={C} style={{whiteSpace:"nowrap",fontSize:12}}>{row.area||"—"}</Td>
                    <Td C={C}><Badge label={row.severity==="Positive"?"Good Practice":row.severity} color={pc}/></Td>
                    <Td C={C}><Badge label={row.status} color={stColor(row.status,C)}/></Td>
                    <Td C={C} style={{fontSize:11,whiteSpace:"nowrap"}}>{row.date}</Td>
                    <Td C={C} style={{fontSize:10,color:C.teal,maxWidth:120,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}} title={row.fileName}>{row.fileName?.replace("Daily_Observation_Report_","").replace(".xlsx","").replace(".xls","")}</Td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>

        {/* Footer */}
        <div style={{display:"flex",gap:10,marginTop:18,justifyContent:"flex-end",flexWrap:"wrap",alignItems:"center"}}>
          {dupCount>0&&<span style={{fontSize:12,color:C.muted,marginRight:"auto"}}>{dupCount} duplicate{dupCount!==1?"s":""} will be skipped automatically</span>}
          <button onClick={onClose} style={{background:"none",border:`1px solid ${C.border}`,borderRadius:8,padding:"8px 20px",color:C.sub,cursor:"pointer",fontWeight:600,fontSize:13}}>Cancel</button>
          <button onClick={()=>onConfirm([...selected].map(i=>preview[i]))} disabled={selected.size===0||importing}
            style={{background:selected.size===0||importing?"#33415555":C.indigo,color:"#fff",border:"none",borderRadius:8,padding:"8px 24px",cursor:selected.size===0||importing?"not-allowed":"pointer",fontWeight:700,fontSize:13,display:"flex",alignItems:"center",gap:8,opacity:selected.size===0?0.5:1}}>
            {importing
              ?<><span style={{width:14,height:14,border:"2px solid #fff",borderTopColor:"transparent",borderRadius:"50%",display:"inline-block",animation:"spin 0.8s linear infinite"}}/>Saving to database…</>
              :<><Download size={14}/>Import {selected.size} Record{selected.size!==1?"s":""} from {fileNames.length} File{fileNames.length!==1?"s":""}</>}
          </button>
        </div>
      </div>
    </div>
  );
};

// ── PARSE PRIORITY → SEVERITY ─────────────────────────────────────────────────
const parsePriority = (raw) => {
  if(!raw) return "Medium";
  const r = String(raw).toLowerCase();
  if(r.includes("good practice") || r.includes("gp")) return "Positive";
  if(r.includes("high") || r === "h" || r === "a") return "High";
  if(r.includes("medium") || r === "m" || r === "b") return "Medium";
  if(r.includes("low") || r === "l" || r === "c" || r === "d") return "Low";
  return "Medium";
};

// ── PARSE STATUS ──────────────────────────────────────────────────────────────
const parseStatus = (raw) => {
  if(!raw) return "Open";
  const r = String(raw).toLowerCase();
  if(r.includes("closed") || r.includes("close")) return "Closed";
  if(r.includes("overdue")) return "Open";
  if(r.includes("pending")) return "Open";
  if(r.includes("progress")) return "Under Review";
  return "Open";
};

// ── PARSE EXCEL DATE ──────────────────────────────────────────────────────────
const parseExcelDate = (val) => {
  if(!val) return "";
  if(val instanceof Date) {
    return val.toISOString().split("T")[0];
  }
  if(typeof val === "number") {
    // Excel serial date
    const d = new Date(Math.round((val - 25569) * 86400 * 1000));
    return d.toISOString().split("T")[0];
  }
  const s = String(val);
  const m = s.match(/(\d{4}[-/]\d{2}[-/]\d{2})/);
  return m ? m[1].replace(/\//g,"-") : s.split("T")[0] || "";
};

// ── MAIN OBSERVATIONS COMPONENT ───────────────────────────────────────────────
const Observations = ({user,obs,zones,obsTypes,actionsList,obsSeverity=DEFAULT_OBS_SEVERITY,C}) => {
  const [showForm,setShowForm]=useState(false),[closeoutObs,setCloseoutObs]=useState(null),[detailObs,setDetailObs]=useState(null),[showBulk,setShowBulk]=useState(false);
  const [filter,setFilter]=useState({site:"",status:"",severity:"",type:"",zone:"",observer:"",dateFrom:"",dateTo:"",search:""}),[selected,setSelected]=useState([]);
  const [page,setPage]=useState(1);
  const PAGE_SIZE=50;
  const [xlPreview,setXlPreview]=useState(null),[xlFileNames,setXlFileNames]=useState([]),[xlImporting,setXlImporting]=useState(false),[xlProgress,setXlProgress]=useState(null);
  const role=ROLE_META[user.role];
  // Reset to page 1 when filters change
  useEffect(()=>setPage(1),[filter]);

  const filtered=useMemo(()=>obs.filter(o=>{
    if(filter.site     && o.site     !==filter.site)     return false;
    if(filter.status   && o.status   !==filter.status)   return false;
    if(filter.severity && o.severity !==filter.severity) return false;
    if(filter.type     && o.type     !==filter.type)     return false;
    if(filter.zone     && o.area     !==filter.zone)     return false;
    if(filter.observer && !o.observer?.toLowerCase().includes(filter.observer.toLowerCase())) return false;
    if(filter.dateFrom && o.date     < filter.dateFrom)  return false;
    if(filter.dateTo   && o.date     > filter.dateTo)    return false;
    if(filter.search   && !o.desc?.toLowerCase().includes(filter.search.toLowerCase())
                       && !o.id?.toLowerCase().includes(filter.search.toLowerCase())
                       && !o.observer?.toLowerCase().includes(filter.search.toLowerCase())) return false;
    return true;
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }),[obs,filter.site,filter.status,filter.severity,filter.type,filter.zone,filter.observer,filter.dateFrom,filter.dateTo,filter.search]);
  const counts={all:obs.length,open:obs.filter(o=>o.status==="Open").length,high:obs.filter(o=>o.severity==="High").length,positive:obs.filter(o=>o.type==="Good Practice").length};
  const totalPages=Math.max(1,Math.ceil(filtered.length/PAGE_SIZE));
  const paginated=filtered.slice((page-1)*PAGE_SIZE, page*PAGE_SIZE);
  const allSel=filtered.length>0&&filtered.every(o=>selected.includes(o._docId));
  // eslint-disable-next-line no-unused-vars
  const toggleAll=()=>setSelected(allSel?[]:filtered.map(o=>o._docId));
  // eslint-disable-next-line no-unused-vars
  const toggleOne=id=>setSelected(p=>p.includes(id)?p.filter(x=>x!==id):[...p,id]);
  const bulkDelete=async()=>{
    if(!window.confirm(`Permanently delete ${selected.length} observation(s)? This cannot be undone.`))return;
    let failed=0;
    for(const id of selected){
      try{await fbDelId("observations",id);}
      catch(e){failed++;console.error("[HSSE] bulk delete failed for",id,e);}
    }
    setSelected([]);
    if(failed>0) alert(`⚠️ ${failed} record(s) could not be deleted. Check your permissions.`);
  };
  const bulkClose=async()=>{
    const d = todayStr();
    const t = nowTimeStr();
    let failed=0;
    for(const id of selected){
      const o=obs.find(x=>x._docId===id);
      if(o&&o.status!=="Closed"){
        try{await updateDoc(doc(db,"observations",id),{status:"Closed",closeDate:d,closeTime:t});}
        catch(e){failed++;console.error("[HSSE] bulk close failed for",id,e);}
      }
    }
    setSelected([]);
    if(failed>0) alert(`⚠️ ${failed} record(s) could not be closed.`);
  };

  // ── PARSE ONE EXCEL FILE → array of observation rows ─────────────────────
  const parseOneFile = async (XLSX, file) => {
    const buffer = await file.arrayBuffer();
    const wb = XLSX.read(buffer, {type:"array", cellDates:true});
    const sheetName = wb.SheetNames.find(n => n.trim().toLowerCase() === "sheet1") || wb.SheetNames[0];
    const ws = wb.Sheets[sheetName];
    const rows = XLSX.utils.sheet_to_json(ws, {header:1, defval:null, raw:false, dateNF:"yyyy-mm-dd"});
    const reportRef = String(rows[0]?.[16] || "").trim() || "UNKNOWN-REF";
    const reportDateRaw = rows[1]?.[1];
    let reportDateStr = "";
    if(reportDateRaw) {
      const d = new Date(reportDateRaw);
      if(!isNaN(d.getTime())) reportDateStr = d.toISOString().split("T")[0];
    }
    const parsed = [];
    for(let i = 12; i < rows.length; i++) {
      const row = rows[i];
      if(!row || row[0] === null || row[0] === undefined) continue;
      const srNo = row[0];
      if(typeof srNo !== "number" && isNaN(parseInt(String(srNo)))) continue;
      const srPadded = String(parseInt(srNo)).padStart(4,"0");
      const id      = `${reportRef}-${srPadded}`;
      const type    = String(row[1] || "").trim() || "Unsafe Condition";
      const desc    = String(row[4] || "").trim();
      const action  = String(row[6] || "").trim();
      const rawDate = row[13];
      const rawDue  = row[17];
      const zone    = String(row[18] || "").trim();
      const rawStat = row[19];
      const rawPri  = row[21];
      if(!desc && !type) continue;
      let date = reportDateStr, time = "08:00";
      if(rawDate) {
        const d = new Date(rawDate);
        if(!isNaN(d.getTime())) { date = d.toISOString().split("T")[0]; time = d.toTimeString().slice(0,5); }
        else { const p=parseExcelDate(rawDate); if(p) date=p; }
      }
      if(!date) date = new Date().toISOString().split("T")[0];
      const due      = parseExcelDate(rawDue);
      const severity = parsePriority(rawPri);
      const status   = severity === "Positive" ? "Closed" : parseStatus(rawStat);
      parsed.push({ id, srNo: parseInt(srNo), type, desc, action, date, time, due, area: zone, severity, status, reportRef, fileName: file.name });
    }
    return parsed;
  };

  // ── EXCEL IMPORT HANDLER — supports multiple files ────────────────────────
  const handleExcelUpload = async (e) => {
    const files = Array.from(e.target.files);
    if(!files.length) return;
    e.target.value = "";
    try {
      const XLSX = await import("xlsx");
      const allParsed = [];
      const fileNames = [];
      const errors = [];
      for(let fi = 0; fi < files.length; fi++) {
        const file = files[fi];
        try {
          const rows = await parseOneFile(XLSX, file);
          if(rows.length > 0) {
            allParsed.push(...rows);
            fileNames.push(file.name);
          } else {
            errors.push(`${file.name}: no valid rows found`);
          }
        } catch(err) {
          errors.push(`${file.name}: ${err.message}`);
        }
      }
      if(allParsed.length === 0) {
        alert("⚠️ No valid observation rows found in any of the selected files.\nMake sure the files match the Daily Observation Report format.");
        return;
      }
      if(errors.length > 0) {
        console.warn("Some files had errors:", errors);
      }
      // Sort all records by date ascending so oldest appear first
      allParsed.sort((a,b) => a.date.localeCompare(b.date));
      setXlFileNames(fileNames);
      setXlPreview(allParsed);
    } catch(err) {
      console.error(err);
      alert("❌ Could not read Excel files.\n" + err.message);
    }
  };

  // ── CONFIRM IMPORT → SAVE TO FIRESTORE (Historical, multi-file) ─────────
  const confirmImport = async (rows) => {
    setXlImporting(true);
    setXlProgress({done:0, total:rows.length, msg:"Preparing..."});
    try {
      const site = user.site === "All Sites" ? "Site 1" : user.site;
      const existingIdSet = new Set(obs.map(o => o.id));
      let skipped = 0, imported = 0;
      for(let i = 0; i < rows.length; i++) {
        const r = rows[i];
        // Update progress
        setXlProgress({done:i, total:rows.length, msg:`Saving record ${i+1} of ${rows.length}…`});
        if(existingIdSet.has(r.id)) { skipped++; continue; }
        const obsType = r.severity === "Positive" ? "Good Practice" : "Unsafe Condition";
        await fbAdd("observations", {
          id:          r.id,
          seqNum:      r.srNo,
          date:        r.date,
          time:        r.time,
          site,
          area:        r.area || "General",
          type:        r.type || obsType,
          severity:    r.severity,
          status:      r.status,
          action:      r.action ? r.action.split("\n")[0].slice(0,120) : "Corrective Action Issued",
          desc:        r.desc,
          observer:    user.name,
          observerId:  user.uid,
          openPhoto:   "",
          closePhoto:  "",
          closeDate:   r.status === "Closed" ? r.due : "",
          closeTime:   r.status === "Closed" ? "00:00" : "",
          source:      "historical",
          reportRef:   r.reportRef,
          fileName:    r.fileName,
          importedAt:  new Date().toISOString(),
        });
        imported++;
      }
      setXlProgress({done:rows.length, total:rows.length, msg:"Done!"});
      setXlPreview(null);
      setXlFileNames([]);
      setXlProgress(null);
      const msg = skipped > 0
        ? `✅ Imported ${imported} historical record${imported!==1?"s":""}. \n⚠️ ${skipped} duplicate${skipped!==1?"s":""} were skipped.`
        : `✅ Successfully imported ${imported} historical record${imported!==1?"s":""}!`;
      alert(msg);
    } catch(err) {
      console.error(err);
      alert("❌ Import failed: " + err.message);
    } finally {
      setXlImporting(false);
      setXlProgress(null);
    }
  };

  return(
    <div style={{display:"flex",flexDirection:"column",gap:18}}>

      {/* Excel Import Preview Modal */}
      {xlPreview && (
        <ExcelImportModal
          preview={xlPreview}
          fileNames={xlFileNames}
          importing={xlImporting}
          importProgress={xlProgress}
          existingIds={new Set(obs.map(o=>o.id))}
          onConfirm={confirmImport}
          onClose={()=>{setXlPreview(null);setXlFileNames([]);setXlProgress(null);}}
          C={C}
        />
      )}

      <PillGrid minWidth={110}>
        {[["Total",counts.all,C.blue],["Open",counts.open,C.red],["High Risk",counts.high,C.orange],["Good Practice",counts.positive,C.green]].map(([l,v,c])=>(
          <StatPill key={l} label={l} value={v} color={c} C={C}/>
        ))}
      </PillGrid>

      {/* ── Row 1: search + dropdowns + action buttons ── */}
      <div style={{display:"flex",gap:8,flexWrap:"wrap",alignItems:"center"}}>
        <input placeholder="🔍 Search ID, description, observer..." value={filter.search}
          onChange={e=>setFilter(p=>({...p,search:e.target.value}))}
          style={{background:C.bg,border:`1px solid ${C.border}`,borderRadius:8,padding:"7px 12px",color:C.text,fontSize:13,outline:"none",flex:2,minWidth:150}}/>
        {[
          ["site",    "All Sites",  SITE_IDS,   o=>SITE_IDS.includes(o)?siteName(o):o],
          ["status",  "All Status", ["Open","Closed","Under Review"], null],
          ["severity","Severity",   obsSeverity, null],
          ["type",    "All Types",  obsTypes,    null],
          ["zone",    "All Zones",  zones,       null],
        ].map(([k,ph,opts,lbl])=>(
          <select key={k} value={filter[k]} onChange={e=>setFilter(p=>({...p,[k]:e.target.value}))}
            style={{background:C.bg,border:`1px solid ${filter[k]?C.teal:C.border}`,borderRadius:8,padding:"7px 10px",color:filter[k]?C.teal:C.text,fontSize:12,outline:"none",fontWeight:filter[k]?700:400}}>
            <option value="">{ph}</option>
            {opts.map(o=><option key={o} value={o}>{lbl?lbl(o):o}</option>)}
          </select>
        ))}
        {can(user,"observations",user.site,"add")&&<Btn onClick={()=>setShowForm(true)} color={C.teal}><Plus size={14}/>New</Btn>}
        {/* Excel Import Button — needs 'add' to be useful since import inserts records */}
        {can(user,"observations",user.site,"add")&&(
          <label style={{background:C.indigo,color:"#fff",borderRadius:8,padding:"8px 14px",fontWeight:700,fontSize:13,cursor:"pointer",display:"flex",alignItems:"center",gap:6,whiteSpace:"nowrap"}} title="Select one or more Daily Observation Report Excel files to import">
            📥 Import Historical
            <input type="file" accept=".xlsx,.xls" multiple onChange={handleExcelUpload} style={{display:"none"}}/>
          </label>
        )}
        {/* Bulk Import — same permission as Import Historical (inserts records) */}
        {can(user,"observations",user.site,"add")&&(
          <Btn onClick={()=>setShowBulk(p=>!p)} color={C.teal}><Download size={14}/>{showBulk?"Hide Import":"📊 Bulk Import"}</Btn>
        )}
        {/* CSV export stays available to anyone who can see the data */}
        <Btn onClick={()=>exportCSV(obs,"observations")} color={C.indigo}><Download size={14}/>CSV</Btn>
      </div>

      {/* ── Row 2: date range + observer + clear ── */}
      <div style={{display:"flex",gap:8,flexWrap:"wrap",alignItems:"center"}}>
        <div style={{display:"flex",alignItems:"center",gap:6,background:C.bg,border:`1px solid ${filter.dateFrom?C.teal:C.border}`,borderRadius:8,padding:"5px 10px"}}>
          <span style={{fontSize:11,color:C.muted,whiteSpace:"nowrap"}}>From</span>
          <input type="date" value={filter.dateFrom} onChange={e=>setFilter(p=>({...p,dateFrom:e.target.value}))}
            style={{background:"transparent",border:"none",color:C.text,fontSize:12,outline:"none",cursor:"pointer"}}/>
        </div>
        <div style={{display:"flex",alignItems:"center",gap:6,background:C.bg,border:`1px solid ${filter.dateTo?C.teal:C.border}`,borderRadius:8,padding:"5px 10px"}}>
          <span style={{fontSize:11,color:C.muted,whiteSpace:"nowrap"}}>To</span>
          <input type="date" value={filter.dateTo} onChange={e=>setFilter(p=>({...p,dateTo:e.target.value}))}
            style={{background:"transparent",border:"none",color:C.text,fontSize:12,outline:"none",cursor:"pointer"}}/>
        </div>
        <input placeholder="👤 Observer name..." value={filter.observer}
          onChange={e=>setFilter(p=>({...p,observer:e.target.value}))}
          style={{background:C.bg,border:`1px solid ${filter.observer?C.teal:C.border}`,borderRadius:8,padding:"7px 12px",color:filter.observer?C.teal:C.text,fontSize:12,outline:"none",flex:1,minWidth:140,fontWeight:filter.observer?700:400}}/>
        <span style={{fontSize:12,color:C.muted}}>{filtered.length} of {obs.length} records</span>
        {Object.values(filter).some(Boolean)&&(
          <button onClick={()=>setFilter({site:"",status:"",severity:"",type:"",zone:"",observer:"",dateFrom:"",dateTo:"",search:""})}
            style={{background:C.red+"22",border:`1px solid ${C.red}44`,color:C.red,borderRadius:8,padding:"6px 12px",fontSize:12,fontWeight:700,cursor:"pointer",whiteSpace:"nowrap"}}>
            ✕ Clear all filters
          </button>
        )}
      </div>

      {/* Import hints */}
      {can(user,"observations",user.site,"add")&&(
        <div style={{background:C.indigo+"11",border:`1px solid ${C.indigo}33`,borderRadius:10,padding:"9px 14px",fontSize:12,color:C.indigo,display:"flex",alignItems:"center",gap:8}}>
          <span style={{fontSize:15}}>📥</span>
          <span>Use <strong>📥 Import Historical</strong> to upload one or <strong>multiple</strong> past Daily Observation Report Excel files at once. The system reads Sheet1 from each file, sorts all records by date, skips duplicates automatically, and marks imported records with a <strong>📥 Historical</strong> badge.</span>
        </div>
      )}

      {selected.length>0&&(
        <div style={{background:C.indigo+"22",border:`1px solid ${C.indigo}44`,borderRadius:10,padding:"10px 16px",display:"flex",alignItems:"center",gap:10,flexWrap:"wrap"}}>
          <span style={{color:C.indigo,fontWeight:700,fontSize:13}}>{selected.length} selected</span>
          {role.canEdit&&<Btn onClick={bulkClose} color={C.green} style={{padding:"6px 12px",fontSize:12}}>✅ Close Selected</Btn>}
          {role.canDelete&&<Btn onClick={bulkDelete} color={C.red} style={{padding:"6px 12px",fontSize:12}}><Trash2 size={13}/>Delete Selected</Btn>}
          <button onClick={()=>setSelected([])} style={{background:"none",border:"none",color:C.muted,cursor:"pointer",fontSize:12}}>✕ Clear</button>
        </div>
      )}
      {showBulk&&(
        <BulkImporter
          section="observations" siteId={user.site==="All Sites"?"Site 1":user.site}
          existingIds={obs.map(o=>o.id)}
          user={user}
          zones={zones} obsTypes={obsTypes} actionsList={actionsList} obsSeverity={obsSeverity}
          ncrCats={[]} ncrSeverity={[]} ncrStatus={[]}
          riskCats={[]} riskStatus={[]}
          onDone={()=>setShowBulk(false)}
          C={C}
        />
      )}
      {showForm&&<ObsForm user={user} zones={zones} obsTypes={obsTypes} actionsList={actionsList} obsSeverity={obsSeverity} obsCount={obs.length} onSubmit={o=>fbAdd("observations",o)} onClose={()=>setShowForm(false)} C={C}/>}
      {closeoutObs&&<CloseoutModal obs={closeoutObs} onClose={()=>setCloseoutObs(null)} C={C}/>}
      {detailObs&&<ObsDetail obs={detailObs} onClose={()=>setDetailObs(null)} C={C}/>}
      <TableCard title={`Observations (${filtered.length})`} C={C}>
        <table style={{width:"100%",borderCollapse:"collapse"}}>
          <thead><tr>
            <Th C={C} style={{width:36}}><input type="checkbox" checked={allSel} onChange={toggleAll} style={{accentColor:C.teal,width:14,height:14,cursor:"pointer"}}/></Th>
            {["ID","Date","Time","Site","Zone","Type","Severity","Observer","Status","Photos","Actions"].map(h=><Th key={h} C={C}>{h}</Th>)}
          </tr></thead>
          <tbody>
            {paginated.map(o=>{
              const isSel=selected.includes(o._docId);
              return(
                <tr key={o._docId||o.id} style={{background:isSel?C.indigo+"11":"transparent"}} onMouseEnter={e=>{if(!isSel)e.currentTarget.style.background=C.border+"33";}} onMouseLeave={e=>{e.currentTarget.style.background=isSel?C.indigo+"11":"transparent";}}>
                  <Td C={C}><input type="checkbox" checked={isSel} onChange={()=>toggleOne(o._docId)} style={{accentColor:C.teal,width:14,height:14,cursor:"pointer"}}/></Td>
                  <Td C={C}>
                    <div style={{display:"flex",flexDirection:"column",gap:3}}>
                      <button onClick={()=>setDetailObs(o)} style={{background:"none",border:"none",cursor:"pointer",color:C.teal,fontFamily:"monospace",fontSize:10,textDecoration:"underline",padding:0,textAlign:"left"}}>{o.id}</button>
                      {o.source==="historical"&&<span style={{background:C.indigo+"22",color:C.indigo,border:`1px solid ${C.indigo}44`,fontSize:9,fontWeight:700,padding:"1px 5px",borderRadius:4,width:"fit-content",whiteSpace:"nowrap"}}>📥 Historical</span>}
                    </div>
                  </Td>
                  <Td C={C}>{o.date}</Td><Td C={C}>{o.time}</Td><Td C={C}>{siteName(o.site)||o.site}</Td><Td C={C}>{o.area}</Td><Td C={C}>{o.type}</Td>
                  <Td C={C}><Badge label={o.severity} color={sevColor(o.severity,C)}/></Td>
                  <Td C={C}><div style={{display:"flex",alignItems:"center",gap:5}}><div style={{background:C.teal+"33",width:22,height:22,borderRadius:"50%",display:"flex",alignItems:"center",justifyContent:"center",fontSize:8,fontWeight:700,color:C.teal,flexShrink:0}}>{o.observer?.split(" ").map(w=>w[0]).join("").slice(0,2)}</div><span style={{fontSize:12}}>{o.observer}</span></div></Td>
                  <Td C={C}><Badge label={o.status} color={stColor(o.status,C)}/></Td>
                  <Td C={C}><div style={{display:"flex",gap:4}}>{o.openPhoto&&<span title="Opening photo" style={{fontSize:16,cursor:"pointer"}} onClick={()=>setDetailObs(o)}>📷</span>}{o.closePhoto&&<span title="Closeout photo" style={{fontSize:16,cursor:"pointer"}} onClick={()=>setDetailObs(o)}>✅</span>}{!o.openPhoto&&!o.closePhoto&&<span style={{color:C.muted,fontSize:11}}>—</span>}</div></Td>
                  <Td C={C}><div style={{display:"flex",gap:4}}>
                    <button onClick={()=>setDetailObs(o)} style={{background:C.blue+"22",border:`1px solid ${C.blue}44`,color:C.blue,borderRadius:6,padding:"3px 7px",cursor:"pointer",fontSize:10,fontWeight:700}}>View</button>
                    {role.canEdit&&o.status!=="Closed"&&<button onClick={()=>setCloseoutObs(o)} style={{background:C.green+"22",border:`1px solid ${C.green}44`,color:C.green,borderRadius:6,padding:"3px 7px",cursor:"pointer",fontSize:10,fontWeight:700}}>Close</button>}
                    {role.canDelete&&<button onClick={()=>fbDel("observations",o)} style={{background:"none",border:"none",cursor:"pointer",color:"#94a3b8"}}><Trash2 size={13}/></button>}
                  </div></Td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </TableCard>

      {/* ── Pagination controls ── */}
      {totalPages>1&&(
        <div style={{display:"flex",alignItems:"center",justifyContent:"space-between",flexWrap:"wrap",gap:8,padding:"10px 4px"}}>
          <span style={{fontSize:12,color:C.muted}}>
            Showing {(page-1)*PAGE_SIZE+1}–{Math.min(page*PAGE_SIZE,filtered.length)} of {filtered.length} records
          </span>
          <div style={{display:"flex",gap:4,alignItems:"center"}}>
            <button onClick={()=>setPage(1)} disabled={page===1}
              style={{background:C.bg,border:`1px solid ${C.border}`,borderRadius:6,padding:"4px 8px",color:page===1?C.muted:C.text,cursor:page===1?"not-allowed":"pointer",fontSize:12}}>«</button>
            <button onClick={()=>setPage(p=>Math.max(1,p-1))} disabled={page===1}
              style={{background:C.bg,border:`1px solid ${C.border}`,borderRadius:6,padding:"4px 10px",color:page===1?C.muted:C.text,cursor:page===1?"not-allowed":"pointer",fontSize:12}}>‹ Prev</button>
            {Array.from({length:Math.min(7,totalPages)},(_,i)=>{
              let p;
              if(totalPages<=7) p=i+1;
              else if(page<=4) p=i+1;
              else if(page>=totalPages-3) p=totalPages-6+i;
              else p=page-3+i;
              return(
                <button key={p} onClick={()=>setPage(p)}
                  style={{background:p===page?C.teal:C.bg,border:`1px solid ${p===page?C.teal:C.border}`,borderRadius:6,padding:"4px 10px",color:p===page?"#fff":C.text,cursor:"pointer",fontSize:12,fontWeight:p===page?700:400,minWidth:34}}>
                  {p}
                </button>
              );
            })}
            <button onClick={()=>setPage(p=>Math.min(totalPages,p+1))} disabled={page===totalPages}
              style={{background:C.bg,border:`1px solid ${C.border}`,borderRadius:6,padding:"4px 10px",color:page===totalPages?C.muted:C.text,cursor:page===totalPages?"not-allowed":"pointer",fontSize:12}}>Next ›</button>
            <button onClick={()=>setPage(totalPages)} disabled={page===totalPages}
              style={{background:C.bg,border:`1px solid ${C.border}`,borderRadius:6,padding:"4px 8px",color:page===totalPages?C.muted:C.text,cursor:page===totalPages?"not-allowed":"pointer",fontSize:12}}>»</button>
          </div>
        </div>
      )}
    </div>
  );
};

// ── HOME DASHBOARD ────────────────────────────────────────────────────────────
// Executive landing page: hero cards for each site + comparison charts + global KPIs.
// Each hero card is clickable and navigates to that site's dedicated page.
const Overview = ({obs,ncr,incidents=[],training,ptw,manualStats,setManualStats,userRole,kpis,computedDaysLTI,manpower=[],equipment=[],setActive,C}) => {
  // ── Compute live 6-month trend from actual observation + NCR data ─────────
  const liveTrend = buildMonthWindow(6).map(m => ({
    month:        m.label,
    observations: obs.filter(o => m.inMonth(o.date)).length,
    // Incidents come from the incidents register collection ONLY — never obs proxy
    incidents:    (incidents||[]).filter(i => m.inMonth(i.date)).length,
    nearMiss:     obs.filter(o => m.inMonth(o.date) && o.type==="Near Miss").length,
    ncrOpen:      ncr.filter(n => m.inMonth(n.date) && n.status!=="Closed").length,
    welfare:      87,
  }));
  const [editStats,setEditStats]=useState(false),[draft,setDraft]=useState(manualStats),[saving,setSaving]=useState(false);
  // FIX: sync draft when Firestore data loads in after mount
  useEffect(()=>{ if(!editStats) setDraft(manualStats); },[manualStats, editStats]);
  const save=async()=>{
    setSaving(true);setManualStats(draft);
    await saveSettings({manualStats:draft});
    setSaving(false);setEditStats(false);
  };

  // ── Lag fix: manual Refresh + auto-refresh on tab visibility/focus ─────────
  // Previously users reported the Overview felt stale when returning from
  // another tab or after leaving it open. The 15-second polling tick could
  // leave the numbers frozen for up to a full interval. Now:
  //  • Clicking Refresh forces every listener to re-poll immediately.
  //  • Returning to this tab (visibilitychange → visible) triggers the same.
  //  • Window focus also triggers it (covers multi-window setups).
  // A "Last refreshed" timestamp makes the freshness visible to the user.
  const [lastRefreshed,setLastRefreshed]=useState(new Date());
  const [refreshing,setRefreshing]=useState(false);
  const doRefresh=useCallback(async()=>{
    setRefreshing(true);
    try{ await refreshAllSnapshots(); }
    catch(e){ console.warn("[Overview] refresh failed:",e); }
    setLastRefreshed(new Date());
    // Keep the spin visible at least 600ms so the click feels responsive
    setTimeout(()=>setRefreshing(false),600);
  },[]);
  useEffect(()=>{
    const onVis=()=>{ if(document.visibilityState==="visible") doRefresh(); };
    const onFocus=()=>doRefresh();
    document.addEventListener("visibilitychange",onVis);
    window.addEventListener("focus",onFocus);
    return()=>{
      document.removeEventListener("visibilitychange",onVis);
      window.removeEventListener("focus",onFocus);
    };
  },[doRefresh]);
  // ── Hero site cards — Option B: 8 metrics per site, one unified view ──────
  // This replaces the previous "3-metric hero + duplicated Per-Project
  // Breakdown" layout. Each site now owns all of its key numbers in one
  // place — no more hunting across two sections that showed the same data.
  const siteHeroes = [
    {id:"Site 1", navId:"site1", label:"Palm1 Al-Ahsa Project",      short:"Palm1", accent:C.teal,   grad:"linear-gradient(135deg,#0f4c3a,#065f46)"},
    {id:"Site 2", navId:"site2", label:"Palm2 Al-Madinah Project",   short:"Palm2", accent:C.purple, grad:"linear-gradient(135deg,#4c1d95,#5b21b6)"},
    {id:"Site 3", navId:"site3", label:"Site 3",                     short:"Site 3",accent:C.orange, grad:"linear-gradient(135deg,#7c2d12,#9a3412)"},
  ].map(s => {
    const sObs = bySite(obs, s.id);
    const sNcr = bySite(ncr, s.id);
    const sMp  = bySite(manpower, s.id);
    const sInc = bySite(incidents, s.id);
    // Per-site Days-LTI override (if present in manualStats), else global value
    const perSite = manualStats?.perSite?.[s.id] || {};
    return {
      ...s,
      daysLTI:     perSite.daysLTI ?? (computedDaysLTI ?? manualStats?.daysLTI ?? 0),
      mhWeek:      perSite.manhoursWeek ?? manualStats?.manhoursWeek ?? 0,
      openObs:     sObs.filter(o=>o.status==="Open").length,
      criticalNcr: sNcr.filter(n=>n.severity==="Critical").length,
      nearMiss:    sObs.filter(o=>o.type==="Near Miss").length,
      totalObs:    sObs.length,
      totalNcr:    sNcr.length,
      mp:          sMp.length,
      inc:         sInc.length,
    };
  });
  // ── Comparison chart data: observations / NCR / near-miss per site ─────────
  const siteCompare = siteHeroes.map(s => ({
    site:         s.short,
    Observations: s.totalObs,
    "Open Obs":   s.openObs,
    NCRs:         s.totalNcr,
    "Critical":   s.criticalNcr,
    "Near Miss":  s.nearMiss,
  }));
  return(
    <div style={{display:"flex",flexDirection:"column",gap:20}}>
      {/* ══ Welcome banner + Refresh + admin edit button ═════════════════════ */}
      <div style={{background:"linear-gradient(135deg,#0d9488 0%,#6366f1 100%)",borderRadius:14,padding:"20px 24px",display:"flex",justifyContent:"space-between",alignItems:"center",flexWrap:"wrap",gap:12}}>
        <div>
          <div style={{color:"#fff",fontWeight:900,fontSize:22,letterSpacing:0.3}}>HSSE Command Center</div>
          <div style={{color:"rgba(255,255,255,0.8)",fontSize:12,marginTop:4}}>
            Executive overview · {siteHeroes.length} active projects · {new Date().toLocaleDateString(undefined,{weekday:"long",year:"numeric",month:"long",day:"numeric"})}
          </div>
          <div style={{color:"rgba(255,255,255,0.65)",fontSize:11,marginTop:4,fontStyle:"italic"}}>
            Last refreshed: {lastRefreshed.toLocaleTimeString()}
          </div>
        </div>
        <div style={{display:"flex",gap:8,alignItems:"center",flexWrap:"wrap"}}>
          <button
            onClick={doRefresh}
            disabled={refreshing}
            title="Force-refresh all site data"
            style={{background:"rgba(255,255,255,0.18)",color:"#fff",border:"1px solid rgba(255,255,255,0.3)",borderRadius:8,padding:"8px 14px",fontWeight:700,fontSize:12,cursor:refreshing?"wait":"pointer",display:"flex",alignItems:"center",gap:6,opacity:refreshing?0.75:1}}>
            <span style={{display:"inline-block",transition:"transform .9s ease",transform:refreshing?"rotate(360deg)":"none"}}>⟳</span>
            {refreshing ? "Refreshing…" : "Refresh"}
          </button>
          {userRole==="admin" && (
            <>
              <SavingBadge saving={saving} C={C}/>
              {editStats
                ? <><Btn onClick={save} color={C.green}><Save size={14}/>Save Stats</Btn>
                     <Btn onClick={()=>{setDraft(manualStats);setEditStats(false);}} color={C.muted} style={{background:C.border}}>Cancel</Btn></>
                : <Btn onClick={()=>setEditStats(true)} color={C.blue} style={{background:"rgba(255,255,255,0.18)",color:"#fff",border:"1px solid rgba(255,255,255,0.3)"}}><Edit2 size={14}/>Edit Global Stats</Btn>}
            </>
          )}
        </div>
      </div>

      {/* ══ Three site hero cards (Option B) — 8 metrics each, click to open ═ */}
      <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fit,minmax(360px,1fr))",gap:16}}>
        {siteHeroes.map(s => (
          <div key={s.id}
            onClick={()=>setActive&&setActive(s.navId)}
            role="button"
            tabIndex={0}
            onKeyDown={(e)=>{if(e.key==="Enter"||e.key===" ")setActive&&setActive(s.navId);}}
            style={{background:s.grad,borderRadius:16,padding:22,cursor:"pointer",border:`1px solid ${s.accent}55`,boxShadow:"0 4px 16px rgba(0,0,0,0.25)",transition:"transform .15s, box-shadow .15s",display:"flex",flexDirection:"column",gap:14}}
            onMouseEnter={(e)=>{e.currentTarget.style.transform="translateY(-3px)";e.currentTarget.style.boxShadow="0 10px 28px rgba(0,0,0,0.4)";}}
            onMouseLeave={(e)=>{e.currentTarget.style.transform="none";e.currentTarget.style.boxShadow="0 4px 16px rgba(0,0,0,0.25)";}}>
            <div style={{display:"flex",justifyContent:"space-between",alignItems:"flex-start",gap:8}}>
              <div>
                <div style={{color:"#fff",fontWeight:900,fontSize:18,lineHeight:1.2}}>{s.label}</div>
                <div style={{color:"rgba(255,255,255,0.65)",fontSize:11,marginTop:3,letterSpacing:0.4,textTransform:"uppercase"}}>{s.id}</div>
              </div>
              <div style={{background:"rgba(255,255,255,0.18)",border:"1px solid rgba(255,255,255,0.25)",borderRadius:99,padding:"4px 10px",color:"#fff",fontSize:11,fontWeight:700,display:"flex",alignItems:"center",gap:4,whiteSpace:"nowrap"}}>
                View Site →
              </div>
            </div>
            <div style={{display:"grid",gridTemplateColumns:"repeat(4,1fr)",gap:8}}>
              {[
                ["Days LTI",     s.daysLTI,     "#bbf7d0"],
                ["Open Obs",     s.openObs,     "#fca5a5"],
                ["Crit NCR",     s.criticalNcr, "#fecaca"],
                ["Near Miss",    s.nearMiss,    "#fde68a"],
                ["Total Obs",    s.totalObs,    "#a7f3d0"],
                ["Manpower",     s.mp,          "#c4b5fd"],
                ["Incidents",    s.inc,         "#fed7aa"],
                ["MH Week",      (s.mhWeek||0).toLocaleString(), "#bae6fd"],
              ].map(([l,v,c]) => (
                <div key={l} style={{background:"rgba(255,255,255,0.12)",borderRadius:8,padding:"10px 8px",textAlign:"center",minHeight:58,display:"flex",flexDirection:"column",justifyContent:"center"}}>
                  <div style={{color:c,fontWeight:900,fontSize:19,lineHeight:1}}>{v}</div>
                  <div style={{color:"rgba(255,255,255,0.72)",fontSize:9,marginTop:4,textTransform:"uppercase",letterSpacing:0.4}}>{l}</div>
                </div>
              ))}
            </div>
          </div>
        ))}
      </div>

      {/* ══ Site comparison chart ═════════════════════════════════════════════ */}
      <div style={{background:C.card,border:`1px solid ${C.border}`,borderRadius:14,padding:18}}>
        <h3 style={{color:C.text,fontWeight:700,margin:"0 0 14px",fontSize:14}}>🏗 Site Comparison — Observations, NCRs & Near-Misses</h3>
        <ResponsiveContainer width="100%" height={240}>
          <BarChart data={siteCompare}>
            <CartesianGrid strokeDasharray="3 3" stroke={C.border}/>
            <XAxis dataKey="site" tick={{fill:C.muted,fontSize:11}}/>
            <YAxis tick={{fill:C.muted,fontSize:11}}/>
            <Tooltip contentStyle={chartTooltip(C)}/>
            <Legend/>
            <Bar dataKey="Observations" fill={C.teal}    radius={[4,4,0,0]}/>
            <Bar dataKey="Open Obs"     fill={C.orange}  radius={[4,4,0,0]}/>
            <Bar dataKey="NCRs"         fill={C.indigo}  radius={[4,4,0,0]}/>
            <Bar dataKey="Critical"     fill={C.red}     radius={[4,4,0,0]}/>
            <Bar dataKey="Near Miss"    fill={C.yellow}  radius={[4,4,0,0]}/>
          </BarChart>
        </ResponsiveContainer>
      </div>

      {editStats&&(
        <div style={{background:C.card,border:`1px solid ${C.blue}44`,borderRadius:14,padding:20}}>
          <h3 style={{color:C.text,fontWeight:700,margin:"0 0 14px",fontSize:14}}>📊 Edit Manual Stats</h3>
          <ManualStatsEditor draft={draft} setDraft={setDraft} C={C} minWidth={200}/>
        </div>
      )}
      {/* NOTE: Option B layout removes the global StatBox strip and the
            "Per-Project Breakdown" block that previously duplicated what
            the three site hero cards above already show. The two extra
            portfolio-level tiles (Active Permits, Expired Training) that
            are NOT part of the per-site cards live together below so no
            unique information is lost. */}
      <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fit,minmax(220px,1fr))",gap:12}}>
        <StatBox label="Active Permits"   value={ptw.filter(p=>p.status==="Active").length}       color={C.blue} icon={ClipboardList} sub="Portfolio-wide"    C={C}/>
        <StatBox label="Expired Training" value={training.filter(t=>t.status==="Expired").length} color={C.red}  icon={BookOpen}      sub="Needs renewal"     C={C}/>
        <StatBox label="NCRs Overdue"     value={ncr.filter(n=>n.status==="Overdue").length}      color={C.orange} icon={FileWarning} sub="Portfolio-wide"    C={C}/>
      </div>
      <div style={{background:C.card,border:`1px solid ${C.border}`,borderRadius:14,padding:18}}>
        <h3 style={{color:C.text,fontWeight:700,margin:"0 0 14px",fontSize:14}}>📋 Project Statistics</h3>
        <ProjectStatsGrid stats={manualStats} C={C} minWidth={190}/>
      </div>
      <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fit,minmax(280px,1fr))",gap:16}}>
        <div style={{background:C.card,border:`1px solid ${C.border}`,borderRadius:14,padding:18}}>
          <h3 style={{color:C.text,fontWeight:700,margin:"0 0 14px"}}>6-Month Safety Trend</h3>
          <ResponsiveContainer width="100%" height={200}>
            <AreaChart data={liveTrend}>
              <defs>
                <linearGradient id="g1" x1="0" y1="0" x2="0" y2="1"><stop offset="5%" stopColor={C.teal} stopOpacity={0.3}/><stop offset="95%" stopColor={C.teal} stopOpacity={0}/></linearGradient>
                <linearGradient id="g2" x1="0" y1="0" x2="0" y2="1"><stop offset="5%" stopColor={C.red} stopOpacity={0.3}/><stop offset="95%" stopColor={C.red} stopOpacity={0}/></linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke={C.border}/>
              <XAxis dataKey="month" tick={{fill:C.muted,fontSize:11}}/><YAxis tick={{fill:C.muted,fontSize:11}}/>
              <Tooltip contentStyle={chartTooltip(C)}/><Legend/>
              <Area type="monotone" dataKey="observations" name="Observations" stroke={C.teal} fill="url(#g1)" strokeWidth={2}/>
              <Area type="monotone" dataKey="incidents" name="Incidents" stroke={C.red} fill="url(#g2)" strokeWidth={2}/>
            </AreaChart>
          </ResponsiveContainer>
        </div>
        <div style={{background:C.card,border:`1px solid ${C.border}`,borderRadius:14,padding:18}}>
          <h3 style={{color:C.text,fontWeight:700,margin:"0 0 14px"}}>Observation Breakdown</h3>
          <ResponsiveContainer width="100%" height={200}>
            <PieChart>
              <Pie data={[{name:"Open",value:obs.filter(o=>o.status==="Open").length||1},{name:"Closed",value:obs.filter(o=>o.status==="Closed").length||1},{name:"Under Review",value:obs.filter(o=>o.status==="Under Review").length||1}]} cx="50%" cy="50%" innerRadius={45} outerRadius={75} dataKey="value" paddingAngle={4}>
                {[C.red,C.green,C.blue].map((c,i)=><Cell key={i} fill={c}/>)}
              </Pie>
              <Tooltip contentStyle={chartTooltip(C)}/><Legend/>
            </PieChart>
          </ResponsiveContainer>
        </div>
      </div>
      <div style={{background:C.card,border:`1px solid ${C.border}`,borderRadius:14,padding:18}}>
        <h3 style={{color:C.text,fontWeight:700,margin:"0 0 14px"}}>KPI Snapshot</h3>
        <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fit,minmax(160px,1fr))",gap:12}}>
          {kpis.map(k=><KPICard key={k.label} kpi={k} C={C}/>)}
        </div>
      </div>
    </div>
  );
};

// ── NCR ───────────────────────────────────────────────────────────────────────
// ── UNIVERSAL BULK IMPORTER ───────────────────────────────────────────────────
// Supports: observations, ncr, risks
// Auto-detects columns by header name, previews rows, skips duplicates
const BulkImporter = ({
  section,        // "observations" | "ncr" | "risks"
  siteId,         // default site for imported records
  existingIds,    // Set or array of existing IDs to skip duplicates
  onDone,         // callback when import finishes
  zones, obsTypes, actionsList, obsSeverity,
  ncrCats, ncrSeverity, ncrStatus,
  riskCats, riskStatus,
  user, C
}) => {
  const [stage,setStage]       = useState("idle"); // idle|preview|importing|done
  const [rows,setRows]         = useState([]);
  const [skipped,setSkipped]   = useState(0);
  const [imported,setImported] = useState(0);
  const [total,setTotal]       = useState(0);
  const [progress,setProgress] = useState(0);
  const [errors,setErrors]     = useState([]);
  const [fileName,setFileName] = useState("");

  // ── SECTION METADATA ──────────────────────────────────────────────────────
  // Each section declares THREE things:
  //   • templateColumns — the canonical, ordered list of columns that the
  //     downloaded .xlsx template exposes. Import reads these keys back out.
  //     Treat this as the contract between the template and the importer.
  //   • aliases        — extra header strings that should ALSO map to each
  //     key, for users whose spreadsheets use a different wording.
  //   • example        — a sample data row used by the Download Template
  //     button so users see valid values for each column.
  //
  // Keep templateColumns and map() in lockstep — if you add/rename a key
  // here, update both.
  const SECTION_META = {
    observations: {
      color:C.teal,   label:"Observations",
      // ── Native format: DAN Company "Daily Observation Report" ────────────
      // The uploaded file structure is a multi-row template with a metadata
      // header band, a priority legend, and then a data grid starting at row
      // 12 (0-indexed). When we detect that layout we use `dorConfig` below
      // to extract rows. Otherwise we fall back to the generic header-matched
      // template (templateColumns + aliases) so hand-rolled CSVs still work.
      format:"dor",
      dorConfig:{
        headerRowIdx: 11,     // row with "Sr No.", "Aid Ref", "Description of Findings", ...
        dataStartIdx: 12,
        columns:{
          sr:          0,
          category:    1,
          description: 4,
          action:      6,
          issueDate:   13,
          closeDate:   17,
          zone:        18,
          status:      19,
          dueDays:     20,
          priority:    21,
        },
        metaCells:{
          reference: {row:0, col:16},
          datetime:  {row:1, col:1},
          location:  {row:1, col:16},
          observer:  {row:2, col:1},
          pmc:       {row:2, col:12},
          contractor:{row:3, col:12},
        },
      },
      // Generic-template fallback (for hand-rolled CSVs without the DOR layout)
      templateColumns:["id","date","time","area","type","severity","action","status","description","observer","site"],
      aliases:{
        id:          ["id","ref","refno","referenceno","observationid","observationno","obsid","srno"],
        date:        ["date","obsdate","observationdate","reportdate","issuingdate","issuedate"],
        time:        ["time","obstime","observationtime"],
        area:        ["area","zone","location","place"],
        type:        ["type","obstype","observationtype","category","aidref"],
        severity:    ["severity","priority","risk","risklevel"],
        action:      ["action","actiontaken","correctiveaction","actionrequired","actionstobetaken"],
        status:      ["status","state"],
        description: ["description","desc","details","finding","observation","remarks","comments","notes","descriptionoffindings"],
        observer:    ["observer","reportedby","raisedby","observername","hsetourby"],
        site:        ["site","project"],
      },
      example:{
        id:"OBS-0001", date:"2026-01-15", time:"08:30", area:"Zone A",
        type:"Unsafe Act", severity:"High", action:"Corrective Action Issued",
        status:"Open", description:"Worker not wearing proper PPE",
        observer:"John Smith", site:"Site 1",
      },
      required:["date"],
      map:(r,h,idx)=>({
        id:         r[h.id]||genObsId(idx,siteId),
        date:       r[h.date]||new Date().toISOString().split("T")[0],
        time:       r[h.time]||"08:00",
        area:       r[h.area]||zones[0]||"Zone A",
        type:       r[h.type]||obsTypes[0]||"Unsafe Act",
        severity:   r[h.severity]||obsSeverity[0]||"High",
        action:     r[h.action]||actionsList[0]||"Corrective Action Issued",
        status:     r[h.status]||"Open",
        desc:       r[h.description]||"",
        observer:   r[h.observer]||user.name,
        observerId: user.uid,
        site:       r[h.site]||siteId,
        openPhoto:"", closePhoto:"", closeDate:"", closeTime:"",
        imported:true,
      }),
    },
    ncr: {
      color:C.orange, label:"NCR Register",
      templateColumns:["id","date","category","severity","site","assignee","due","status","closure","description"],
      aliases:{
        id:          ["id","ref","refno","ncrid","ncrno","ncrnumber"],
        date:        ["date","ncrdate","issuedate","raiseddate"],
        category:    ["category","cat","type","ncrtype"],
        severity:    ["severity","priority","risk"],
        site:        ["site","project","location"],
        assignee:    ["assignee","responsible","assignedto","owner","actionowner"],
        due:         ["due","duedate","targetdate","closuredate"],
        status:      ["status","state"],
        closure:     ["closure","closurepercent","closure%","percent","progress"],
        description: ["description","desc","details","finding","remarks","comments","notes"],
      },
      example:{
        id:"NCR-0001", date:"2026-01-15", category:"PPE", severity:"Major",
        site:"Site 1", assignee:"Jane Doe", due:"2026-02-01", status:"Open",
        closure:0, description:"Missing hard hat in active work zone",
      },
      required:["date"],
      map:(r,h,idx)=>({
        id:       r[h.id]||genNcrId(idx,siteId),
        date:     r[h.date]||new Date().toISOString().split("T")[0],
        category: r[h.category]||ncrCats[0]||"PPE",
        severity: r[h.severity]||ncrSeverity[0]||"Major",
        site:     r[h.site]||siteId,
        assignee: r[h.assignee]||"",
        due:      r[h.due]||"",
        status:   r[h.status]||ncrStatus[0]||"Open",
        closure:  Number(r[h.closure])||0,
        desc:     r[h.description]||"",
        raisedBy: user.name,
        photo:"", imported:true,
      }),
    },
    risks: {
      color:C.purple, label:"Risk Register",
      templateColumns:["id","hazard","category","likelihood","impact","controls","residual","owner","status"],
      aliases:{
        id:         ["id","ref","refno","riskid","riskno"],
        hazard:     ["hazard","hazarddescription","description","desc","risk","details"],
        category:   ["category","cat","type","risktype"],
        likelihood: ["likelihood","probability","prob","freq","frequency"],
        impact:     ["impact","consequence","severity"],
        controls:   ["controls","mitigations","controlmeasures","measures"],
        residual:   ["residual","residualrisk","residualscore"],
        owner:      ["owner","responsible","assignedto","riskowner"],
        status:     ["status","state"],
      },
      example:{
        id:"R-0001", hazard:"Working at height without harness",
        category:"Physical", likelihood:3, impact:4,
        controls:"Daily toolbox talks, harness inspection, supervisor signoff",
        residual:2, owner:"Site HSE Officer", status:"Active",
      },
      required:["hazard"],
      map:(r,h,idx)=>({
        id:          r[h.id]||`R-${Date.now()}-${idx}`,
        hazard:      r[h.hazard]||"",
        category:    r[h.category]||riskCats[0]||"Physical",
        likelihood:  Number(r[h.likelihood])||3,
        impact:      Number(r[h.impact])||3,
        controls:    r[h.controls]||"",
        residual:    Number(r[h.residual])||1,
        owner:       r[h.owner]||"",
        status:      r[h.status]||riskStatus[0]||"Active",
        imported:true,
      }),
    },
  };

  const meta = SECTION_META[section];
  const existingSet = new Set(Array.isArray(existingIds)?existingIds:Array.from(existingIds||[]));

  // ── Column-header auto-detection ──────────────────────────────────────────
  // Strategy: for each canonical key, walk its alias list (itself + synonyms)
  // and try three progressively looser matches in order:
  //   1. exact normalized match       ("Observation Date" → "observationdate")
  //   2. starts-with on either side   ("Description" matches alias "desc")
  //   3. substring (only for aliases of length ≥ 4 — short words like "id"
  //      must match cleanly, otherwise they pick up "Provide Notes" etc.)
  // Once a column is claimed by one key it cannot be re-claimed by another,
  // so "Description" can't accidentally also bind to "desc" and double-map.
  const normalize = (s) => String(s||"").toLowerCase().replace(/[\s_\-\.\/()]/g,"").trim();

  const mapHeaders = (headerRow) => {
    const normCols = headerRow.map(normalize);
    const claimed  = new Set();
    const h        = {};

    const tryClaim = (key, predicate) => {
      if (h[key] !== undefined) return;
      for (let i = 0; i < normCols.length; i++) {
        if (claimed.has(i)) continue;
        if (!normCols[i]) continue;
        if (predicate(normCols[i])) { h[key] = i; claimed.add(i); return; }
      }
    };

    const aliasesFor = (key) => {
      const list = (meta.aliases && meta.aliases[key]) || [key];
      return list.map(normalize).filter(Boolean);
    };

    // Pass 1: exact matches
    meta.templateColumns.forEach(key => {
      const aliases = aliasesFor(key);
      tryClaim(key, col => aliases.includes(col));
    });
    // Pass 2: starts-with either side
    meta.templateColumns.forEach(key => {
      const aliases = aliasesFor(key);
      tryClaim(key, col => aliases.some(a => col.startsWith(a) || a.startsWith(col)));
    });
    // Pass 3: substring — skip short aliases that would false-positive
    meta.templateColumns.forEach(key => {
      const aliases = aliasesFor(key).filter(a => a.length >= 4);
      if (!aliases.length) return;
      tryClaim(key, col => aliases.some(a => col.includes(a)));
    });
    return h;
  };

  // ── Detect: does this sheet match the Daily Observation Report layout? ────
  // Signal: row 11 (0-indexed) column A contains "Sr No." AND column R / S
  // area contains "Zone" / "Status" labels. We check loosely so cosmetic
  // tweaks (extra whitespace, different casing) don't break detection.
  const looksLikeDOR = (raw) => {
    if (!meta.dorConfig) return false;
    const {headerRowIdx, columns} = meta.dorConfig;
    const hr = raw[headerRowIdx];
    if (!hr) return false;
    const cellAt = (i) => String(hr[i]||"").toLowerCase().replace(/\s+/g,"");
    return cellAt(columns.sr).includes("srno")
        && (cellAt(columns.zone).includes("zone") || cellAt(columns.status).includes("status"));
  };

  // ── Parse the Daily Observation Report format ────────────────────────────
  // Uses the fixed column positions declared in meta.dorConfig, and pulls
  // report-level metadata (reference, date/time, observer) from the top band
  // so they can default into every row.
  const parseDOR = (raw) => {
    const {dataStartIdx, columns:cols, metaCells} = meta.dorConfig;
    const cellAt = (row, col) => {
      const r = raw[row]; if (!r) return "";
      return String(r[col]==null?"":r[col]).trim();
    };

    // Report-level metadata (all rows inherit these unless overridden)
    const reportRef = cellAt(metaCells.reference.row, metaCells.reference.col) || "UNKNOWN-REF";
    const datetimeRaw = cellAt(metaCells.datetime.row, metaCells.datetime.col);
    const reportDate = parseExcelDate(datetimeRaw) || new Date().toISOString().split("T")[0];
    // Pull time from the "date and time" cell if it's in "M/D/YY HH:MM" form
    const timeMatch = datetimeRaw.match(/(\d{1,2}):(\d{2})/);
    const reportTime = timeMatch ? `${timeMatch[1].padStart(2,"0")}:${timeMatch[2]}` : "08:00";
    // Observer cell looks like "DAN :Mohammed Alshehri" — strip the prefix
    const observerRaw = cellAt(metaCells.observer.row, metaCells.observer.col);
    const reportObserver = (observerRaw.split(":")[1] || observerRaw || user.name).trim();

    const records = [];
    for (let i = dataStartIdx; i < raw.length; i++) {
      const row = raw[i]; if (!row) continue;
      const srRaw = row[cols.sr];
      // Skip rows where column A is not a number (disclaimer/empty rows)
      if (srRaw == null || srRaw === "" || isNaN(parseInt(String(srRaw)))) continue;

      const srPadded   = String(parseInt(srRaw)).padStart(4,"0");
      const id         = `${reportRef}-${srPadded}`;
      const category   = cellAt(i, cols.category) || "Unsafe Condition";
      const description= cellAt(i, cols.description);
      const action     = cellAt(i, cols.action) || "Corrective Action Issued";
      const zone       = cellAt(i, cols.zone) || zones[0] || "General";
      const issueDate  = parseExcelDate(row[cols.issueDate]) || reportDate;
      const closeDate  = parseExcelDate(row[cols.closeDate]) || "";
      const priority   = parsePriority(cellAt(i, cols.priority));
      // If priority is "Positive" (Good Practice), force status to Closed
      const rawStatus  = cellAt(i, cols.status);
      const status     = priority==="Positive" ? "Closed" : parseStatus(rawStatus);
      // Skip completely blank data rows (no description AND no category useful content)
      if (!description && (!category || category === "Unsafe Condition")) continue;

      // Normalize CRLF → LF so downstream rendering is clean, and pick the
      // first non-empty line for the short `action` field (full text stays in
      // `actionDetail`).
      const actionClean = action.replace(/\r/g, "");
      const actionShort = actionClean.split("\n").map(s=>s.trim()).find(Boolean) || actionClean;
      records.push({
        id,
        date:       issueDate,
        time:       reportTime,
        area:       zone,
        type:       priority==="Positive" ? "Good Practice" : (category || "Unsafe Condition"),
        severity:   priority,
        action:     actionShort.slice(0,200),
        actionDetail: actionClean,
        status,
        desc:       (description || (priority==="Positive" ? "Good Practice (GP)" : "")).replace(/\r/g,""),
        observer:   reportObserver,
        observerId: user.uid,
        site:       siteId,
        openPhoto:"",
        closePhoto:"",
        closeDate,
        closeTime: closeDate ? "00:00" : "",
        reportRef,
        imported:true,
      });
    }
    return records;
  };

  // ── Download a blank template (.xlsx) ─────────────────────────────────────
  // For sections flagged with `format:"dor"` we emit the full Daily
  // Observation Report template (metadata band + priority legend + data
  // grid). For other sections we emit a plain canonical-columns template.
  const downloadTemplate = async () => {
    const XLSX = await import("xlsx");
    const wb = XLSX.utils.book_new();

    if (meta.format === "dor") {
      // Build a 23-column layout matching the uploaded DOR file exactly
      const width = 23;
      const blank = () => Array(width).fill("");
      const row = (cells) => { const r = blank(); Object.entries(cells).forEach(([k,v])=>r[Number(k)]=v); return r; };

      const aoa = [
        // Row 0: Project / Reference
        row({0:" Project:", 1:"Palm 1-Al Ahsa", 9:"Reference:", 16:"01-000001-000000-DAN-RPT-HSE-00001"}),
        // Row 1: Date & time / Location
        row({0:"Date and time:  ", 1:"4/7/26 8:30", 9:"Location: ", 16:"AD-AG-WE-LA-DP."}),
        // Row 2: HSE Tour by / PMC
        row({0:"HSE Tour by:", 1:"DAN :Observer Name", 12:"PMC; PMC Name"}),
        // Row 3: Contractor
        row({12:"Contractor: Contractor Name"}),
        // Row 4-9: Priority legend
        row({0:"Response", 6:"Definition"}),
        row({0:"A", 2:"Immediate",      6:"Immediate action is required to eliminate the high risk of accidents or incident."}),
        row({0:"B", 2:"Within 24 Hrs",  6:"No immediate risk of accident or incident"}),
        row({0:"C", 2:"Within 3 days",  6:"Action is required to minimize health, safety, or environmental risks."}),
        row({0:"D", 2:"As agreed",      6:"Improvement action is required to meet best practices and continually improve standards"}),
        row({0:"GP",2:"Good Practice",  6:"Good practice to be shared with other Projects"}),
        // Row 10: blank spacer
        blank(),
        // Row 11: Data column headers
        row({
          0:"Sr No.", 1:"Aid Ref", 4:"Description of Findings",
          6:"Action(s) to be taken & recommendations",
          9:"Supporting Photo", 13:"Issuing dates",
          14:"Closeout Photo", 17:"Closeout dates",
          18:"Zone", 19:"Status", 20:"Due Date", 21:"Priority H/ M/L/I",
        }),
        // Rows 12-14: Example data rows
        row({0:1, 1:"Chemicals / COSHH", 4:"Unsafe storage of chemical materials...", 6:"The contractor must remove the chemical materials...", 13:"4/7/26", 17:"4/8/26", 18:"Laydown area", 19:"Open", 20:1, 21:"High (H)"}),
        row({0:2, 1:"Fire protection",   4:"Fire extinguisher inspection tag unclear", 6:"Replace inspection tag",                             13:"4/7/26", 17:"4/8/26", 18:"Laydown area", 19:"Open", 20:1, 21:"High (H)"}),
        row({0:3, 4:"Good Practice (GP)", 13:"4/7/26", 17:"4/7/26", 19:"Closed", 20:0, 21:"Good Practice (GP)"}),
        // A few blank rows ready to fill
        blank(), blank(), blank(), blank(), blank(),
      ];
      const ws = XLSX.utils.aoa_to_sheet(aoa);
      // Column widths to make it readable
      ws["!cols"] = [
        {wch:8}, {wch:18}, {wch:6}, {wch:6}, {wch:40}, {wch:6}, {wch:40},
        {wch:6}, {wch:6}, {wch:12}, {wch:6}, {wch:6}, {wch:20},
        {wch:12}, {wch:12}, {wch:6}, {wch:6}, {wch:12},
        {wch:14}, {wch:10}, {wch:10}, {wch:18}, {wch:10},
      ];
      XLSX.utils.book_append_sheet(wb, ws, "Sheet1");
    } else {
      // Generic canonical-columns template (NCR, Risks)
      const headers  = meta.templateColumns.slice();
      const sample   = headers.map(k => (meta.example && meta.example[k]!==undefined) ? meta.example[k] : "");
      const blankRow = headers.map(() => "");
      const ws = XLSX.utils.aoa_to_sheet([headers, sample, blankRow, blankRow, blankRow]);
      ws["!cols"] = headers.map(h => ({ wch: Math.max(14, h.length + 4) }));
      XLSX.utils.book_append_sheet(wb, ws, meta.label.slice(0,28));
    }

    const fileName = `${meta.label.replace(/\s+/g,"_")}_Template.xlsx`;
    XLSX.writeFile(wb, fileName);
  };

  // ── Parse file ─────────────────────────────────────────────────────────────
  const handleFile = async (e) => {
    const file = e.target.files[0]; if(!file)return;
    setFileName(file.name);
    const XLSX = await import("xlsx");
    const buf  = await file.arrayBuffer();
    const wb   = XLSX.read(buf,{type:"array",cellDates:true});
    // Always read Sheet1 if present (matches the DOR template convention);
    // fall back to the first sheet otherwise
    const sheetName = wb.SheetNames.find(n => n.trim().toLowerCase() === "sheet1") || wb.SheetNames[0];
    const ws   = wb.Sheets[sheetName];
    const raw  = XLSX.utils.sheet_to_json(ws,{header:1,defval:"",raw:false,dateNF:"yyyy-mm-dd"});

    // ── DOR format (observations) takes priority when the layout matches ──
    if (meta.format === "dor" && looksLikeDOR(raw)) {
      const parsed = parseDOR(raw);
      setRows(parsed);
      setTotal(parsed.length);
      setSkipped(parsed.filter(r=>existingSet.has(r.id)).length);
      setStage("preview");
      e.target.value="";
      return;
    }

    // ── Generic header-matched fallback ──────────────────────────────────
    const headerIdx = raw.findIndex(r=>r.filter(Boolean).length>2);
    if(headerIdx<0){alert("Could not find a header row. Make sure row 1 or 2 has column names.");return;}

    const headerRow = raw[headerIdx].map(c=>String(c||"").toLowerCase().trim());
    let h = mapHeaders(headerRow);

    // ── Positional fallback ─────────────────────────────────────────────────
    // If fewer than half of the required template columns resolved to a real
    // column, we assume the sheet doesn't have our headers at all (e.g. the
    // user copy-pasted data without a header row, or used a totally foreign
    // schema). In that case we map positionally against templateColumns so
    // the rows still flow through in the canonical order.
    const matchCount  = Object.keys(h).length;
    const usePositional = matchCount < Math.ceil(meta.templateColumns.length/2);
    if (usePositional) {
      h = {};
      meta.templateColumns.forEach((key, i) => { if (i < headerRow.length) h[key] = i; });
    }

    const dataRows = raw.slice(headerIdx + (usePositional ? 0 : 1)).filter(r=>r.some(Boolean));

    const parsed = dataRows.map((r,i)=>{
      const mapped = {};
      Object.entries(h).forEach(([key,col])=>{ mapped[key]=String(r[col]||"").trim(); });
      return meta.map(mapped,h,i+1);
    }).filter(r=>r[meta.required[0]||"date"]); // skip blank required field

    setRows(parsed);
    setTotal(parsed.length);
    setSkipped(parsed.filter(r=>existingSet.has(r.id)).length);
    setStage("preview");
    e.target.value="";
  };

  // ── Run import ─────────────────────────────────────────────────────────────
  const runImport = async () => {
    setStage("importing");
    const toImport = rows.filter(r=>!existingSet.has(r.id));
    let done=0; const errs=[];
    for(const r of toImport){
      try{
        const {_docId,...rest}=r;
        await addDoc(collection(db,section),rest);
        done++;
        setImported(done);
        setProgress(Math.round(done/toImport.length*100));
      }catch(e){errs.push(`${r.id||r.hazard}: ${e.message}`);}
    }
    setErrors(errs);
    setStage("done");
    if(onDone) onDone(done);
  };

  const reset=()=>{setStage("idle");setRows([]);setImported(0);setProgress(0);setErrors([]);setSkipped(0);};
  const color=meta.color;
  const toImportCount=rows.filter(r=>!existingSet.has(r.id)).length;

  return(
    <div>
      {/* ── IDLE: file picker + template download ── */}
      {stage==="idle"&&(
        <div style={{display:"flex",flexDirection:"column",gap:10}}>
          <label style={{background:color+"22",border:`2px dashed ${color}55`,borderRadius:12,padding:"18px 24px",display:"flex",alignItems:"center",justifyContent:"center",gap:10,cursor:"pointer",flexDirection:"column",textAlign:"center"}}>
            <div style={{fontSize:28}}>📊</div>
            <div style={{color,fontWeight:700,fontSize:13}}>Click to import {meta.label} from Excel / CSV</div>
            <div style={{color:C.muted,fontSize:11}}>Supports .xlsx · .xls · .csv · Multiple sheets · Auto column detection</div>
            <input type="file" accept=".xlsx,.xls,.csv" onChange={handleFile} style={{display:"none"}}/>
          </label>

          {/* Template helper — exact column order + download button */}
          <div style={{background:C.card,border:`1px solid ${C.border}`,borderRadius:10,padding:"10px 14px",display:"flex",justifyContent:"space-between",alignItems:"center",flexWrap:"wrap",gap:10}}>
            <div style={{fontSize:11,color:C.muted,lineHeight:1.6,flex:1,minWidth:240}}>
              {meta.format === "dor" ? (
                <>
                  <div style={{color:C.text,fontWeight:700,fontSize:12,marginBottom:2}}>
                    📋 Daily Observation Report format
                  </div>
                  <div style={{color}}>
                    Sheet1 · data starts at row 13 · columns:
                    <span style={{fontFamily:"monospace",marginLeft:4}}>
                      Sr No · Aid Ref · Description · Action · Issuing date · Closeout date · Zone · Status · Due · Priority
                    </span>
                  </div>
                  <div style={{marginTop:4}}>
                    Row 1 reference, row 2 date/time &amp; location, row 3 observer (HSE Tour by)
                    — all auto-detected. Good Practice rows (priority <em>GP</em>) are imported as <em>Closed</em>.
                  </div>
                </>
              ) : (
                <>
                  <div style={{color:C.text,fontWeight:700,fontSize:12,marginBottom:2}}>📋 Expected column order</div>
                  <div style={{fontFamily:"monospace",color}}>
                    {meta.templateColumns.join(" · ")}
                  </div>
                  <div style={{marginTop:4}}>
                    Your spreadsheet can list columns <strong>in any order</strong> as long as the header names match
                    (e.g. <em>"Description"</em>, <em>"Details"</em>, or <em>"Remarks"</em> all map to the same field).
                    If no matching headers are found, columns are read positionally in the order shown above.
                  </div>
                </>
              )}
            </div>
            <Btn onClick={downloadTemplate} color={color} style={{whiteSpace:"nowrap"}}>
              <Download size={14}/>Download Template
            </Btn>
          </div>
        </div>
      )}

      {/* ── PREVIEW ── */}
      {stage==="preview"&&(
        <div style={{background:C.card,border:`1px solid ${color}44`,borderRadius:14,overflow:"hidden"}}>
          <div style={{padding:"12px 18px",borderBottom:`1px solid ${C.border}`,display:"flex",justifyContent:"space-between",alignItems:"center",flexWrap:"wrap",gap:8}}>
            <div>
              <div style={{color:C.text,fontWeight:700,fontSize:14}}>📋 Preview — {fileName}</div>
              <div style={{color:C.muted,fontSize:11,marginTop:2}}>
                {total} rows found · {toImportCount} will be imported · {skipped} duplicates skipped
              </div>
            </div>
            <div style={{display:"flex",gap:8}}>
              <Btn onClick={reset} color={C.muted} style={{background:C.border}}>← Back</Btn>
              <Btn onClick={runImport} color={color} disabled={toImportCount===0}>
                {toImportCount===0?"Nothing to import":`⬆ Import ${toImportCount} records`}
              </Btn>
            </div>
          </div>
          {/* Preview table — first 10 rows */}
          <div style={{overflowX:"auto",maxHeight:320,overflowY:"auto"}}>
            <table style={{width:"100%",borderCollapse:"collapse",fontSize:11}}>
              <thead style={{position:"sticky",top:0}}>
                <tr>
                  <Th C={C}>Status</Th>
                  {Object.keys(rows[0]||{}).filter(k=>!["_docId","openPhoto","closePhoto","closeDate","closeTime","observerId","raisedById","imported"].includes(k)).slice(0,8).map(k=><Th key={k} C={C}>{k}</Th>)}
                </tr>
              </thead>
              <tbody>
                {rows.slice(0,50).map((r,i)=>{
                  const isDup=existingSet.has(r.id);
                  const visKeys=Object.keys(r).filter(k=>!["_docId","openPhoto","closePhoto","closeDate","closeTime","observerId","raisedById","imported"].includes(k)).slice(0,8);
                  return(
                    <tr key={i} style={{background:isDup?C.muted+"11":"transparent",opacity:isDup?0.5:1}}
                      onMouseEnter={ev=>ev.currentTarget.style.background=isDup?C.muted+"11":C.border+"33"}
                      onMouseLeave={ev=>ev.currentTarget.style.background=isDup?C.muted+"11":"transparent"}>
                      <Td C={C}>
                        {isDup
                          ?<Badge label="Skip (dup)" color={C.muted}/>
                          :<Badge label="Import" color={color}/>
                        }
                      </Td>
                      {visKeys.map(k=><Td key={k} C={C} style={{maxWidth:120,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>{String(r[k]||"—")}</Td>)}
                    </tr>
                  );
                })}
                {rows.length>50&&<tr><td colSpan={10} style={{padding:10,textAlign:"center",color:C.muted,fontSize:11}}>...and {rows.length-50} more rows</td></tr>}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* ── IMPORTING ── */}
      {stage==="importing"&&(
        <div style={{background:C.card,border:`1px solid ${color}44`,borderRadius:14,padding:24,textAlign:"center"}}>
          <div style={{color:C.text,fontWeight:700,fontSize:15,marginBottom:16}}>Importing {meta.label}...</div>
          <div style={{height:8,borderRadius:99,background:C.border,overflow:"hidden",marginBottom:10}}>
            <div style={{width:`${progress}%`,height:8,background:color,borderRadius:99,transition:"width 0.3s"}}/>
          </div>
          <div style={{color:C.muted,fontSize:12}}>{imported} of {toImportCount} records saved · {progress}%</div>
        </div>
      )}

      {/* ── DONE ── */}
      {stage==="done"&&(
        <div style={{background:C.green+"11",border:`1px solid ${C.green}44`,borderRadius:14,padding:20}}>
          <div style={{color:C.green,fontWeight:700,fontSize:15,marginBottom:6}}>✅ Import Complete</div>
          <div style={{color:C.sub,fontSize:12,lineHeight:1.7}}>
            {imported} records imported · {skipped} duplicates skipped
            {errors.length>0&&<div style={{color:C.orange,marginTop:6}}>⚠️ {errors.length} errors — check console</div>}
          </div>
          <Btn onClick={reset} color={color} style={{marginTop:12}}>Import Another File</Btn>
        </div>
      )}
    </div>
  );
};

const NCR = ({user,ncr,ncrCats=DEFAULT_NCR_CATS,ncrSeverity=DEFAULT_NCR_SEVERITY,ncrStatus=DEFAULT_NCR_STATUS,C}) => {
  const [showForm,setShowForm]=useState(false);
  const [showBulk,setShowBulk]=useState(false);
  const role=ROLE_META[user.role];
  const today = todayStr();
  const defaultSite=user.site==="All Sites"?"Site 1":user.site;
  const [form,setForm]=useState({date:today,category:ncrCats[0]||"PPE",severity:ncrSeverity[0]||"Major",site:defaultSite,assignee:"",due:"",status:ncrStatus[0]||"Open",closure:0,desc:""});
  // ID recomputes when site changes
  const newId=genNcrId(ncr.length+1, form.site);
  const [photo,setPhoto]=useState(null),[preview,setPreview]=useState(null),[uploading,setUploading]=useState(false);
  const set=(k,v)=>setForm(p=>({...p,[k]:v}));
  const handlePhoto=e=>{const f=e.target.files[0];if(!f)return;setPhoto(f);setPreview(URL.createObjectURL(f));};
  const submit=async()=>{
    if(!form.assignee||!form.due)return;
    setUploading(true);
    try{
      let photoUrl="";
      if(photo) photoUrl=await uploadPhoto(photo);
      await fbAdd("ncr",{...form,id:newId,closure:Number(form.closure),photo:photoUrl,raisedBy:user.name,raisedById:user.uid});
      setShowForm(false);
      setPhoto(null);setPreview(null);
    }catch(e){console.error(e);}finally{setUploading(false);}
  };
  return(
    <div style={{display:"flex",flexDirection:"column",gap:18}}>
      <PillGrid minWidth={130}>
        {[["Total",ncr.length,C.blue],["Critical",ncr.filter(n=>n.severity==="Critical").length,C.red],["Overdue",ncr.filter(n=>n.status==="Overdue").length,C.orange],["Closed",ncr.filter(n=>n.status==="Closed").length,C.green]].map(([l,v,c])=>(
          <StatPill key={l} label={l} value={v} color={c} C={C}/>
        ))}
      </PillGrid>
      <div style={{display:"flex",justifyContent:"flex-end",gap:8,flexWrap:"wrap"}}>
        {can(user,"ncr",user.site,"add")&&<Btn onClick={()=>setShowForm(true)} color={C.orange}><Plus size={14}/>Raise NCR</Btn>}
        {can(user,"ncr",user.site,"add")&&<Btn onClick={()=>setShowBulk(p=>!p)} color={C.teal}><Download size={14}/>{showBulk?"Hide Import":"📊 Bulk Import"}</Btn>}
        <Btn onClick={()=>exportCSV(ncr,"ncr-register")} color={C.indigo}><Download size={14}/>CSV</Btn>
      </div>
      {showBulk&&(
        <BulkImporter
          section="ncr" siteId={user.site==="All Sites"?"Site 1":user.site}
          existingIds={ncr.map(n=>n.id)}
          user={user}
          ncrCats={ncrCats} ncrSeverity={ncrSeverity} ncrStatus={ncrStatus}
          zones={[]} obsTypes={[]} actionsList={[]} obsSeverity={[]}
          riskCats={[]} riskStatus={[]}
          onDone={()=>setShowBulk(false)}
          C={C}
        />
      )}
      {showForm&&(
        <Modal title="Raise New NCR" onClose={()=>setShowForm(false)} C={C} wide={true}>
          {/* NCR ID badge */}
          <div style={{background:C.orange+"22",border:`1px solid ${C.orange}44`,borderRadius:10,padding:"10px 14px",marginBottom:12,display:"flex",justifyContent:"space-between",alignItems:"center",flexWrap:"wrap",gap:8}}>
            <div style={{display:"flex",alignItems:"center",gap:8}}>
              <FileWarning size={15} style={{color:C.orange}}/>
              <div>
                <div style={{fontSize:11,color:C.orange,fontWeight:700}}>NCR Auto-ID</div>
                <div style={{fontSize:12,color:C.text,fontWeight:600}}>{user.name} · {siteName(form.site)}</div>
              </div>
            </div>
            <div style={{background:C.card,borderRadius:8,padding:"4px 10px"}}>
              <div style={{fontSize:9,color:C.muted}}>NCR Reference</div>
              <div style={{fontSize:10,color:C.orange,fontFamily:"monospace",fontWeight:700}}>{newId}</div>
            </div>
          </div>
          <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:12}}>
            <Field label="Date Identified" C={C}><Inp C={C} type="date" value={form.date} onChange={e=>set("date",e.target.value)}/></Field>
            <Field label="Category" C={C}><Sel C={C} value={form.category} onChange={e=>set("category",e.target.value)}>{ncrCats.map(s=><option key={s}>{s}</option>)}</Sel></Field>
            <Field label="Severity" C={C}><Sel C={C} value={form.severity} onChange={e=>set("severity",e.target.value)}>{ncrSeverity.map(s=><option key={s}>{s}</option>)}</Sel></Field>
            <Field label="Site" C={C}><Sel C={C} value={form.site} onChange={e=>set("site",e.target.value)}>{SITES.map(s=><option key={s.id} value={s.id}>{s.name}</option>)}</Sel></Field>
            <Field label="Assigned To" C={C}><Inp C={C} placeholder="Responsible person" value={form.assignee} onChange={e=>set("assignee",e.target.value)}/></Field>
            <Field label="Due Date" C={C}><Inp C={C} type="date" value={form.due} onChange={e=>set("due",e.target.value)}/></Field>
            <Field label="Closure %" C={C}><Inp C={C} type="number" min={0} max={100} value={form.closure} onChange={e=>set("closure",e.target.value)}/></Field>
            <Field label="Status" C={C}><Sel C={C} value={form.status} onChange={e=>set("status",e.target.value)}>{ncrStatus.map(s=><option key={s}>{s}</option>)}</Sel></Field>
          </div>
          <Field label="Description of Non-Conformance" C={C}><Txa C={C} rows={3} placeholder="Describe the non-conformance in detail..." value={form.desc} onChange={e=>set("desc",e.target.value)}/></Field>
          <PhotoBox id="ncrPhotoInput" preview={preview} onSelect={handlePhoto} onRemove={()=>{setPhoto(null);setPreview(null);}} label="📸 Evidence Photo" C={C}/>
          <Btn onClick={submit} color={C.orange} disabled={uploading} style={{marginTop:8,width:"100%",justifyContent:"center"}}>
            {uploading?"Uploading...":"Submit NCR"}
          </Btn>
        </Modal>
      )}
      <TableCard title="NCR Register" C={C}>
        <table style={{width:"100%",borderCollapse:"collapse"}}>
          <thead><tr>{["ID","Date","Category","Severity","Site","Assignee","Due","Status","Closure","Photo",""].map(h=><Th key={h} C={C}>{h}</Th>)}</tr></thead>
          <tbody>{ncr.map(n=>(
            <tr key={n._docId||n.id} onMouseEnter={e=>e.currentTarget.style.background=C.border+"33"} onMouseLeave={e=>e.currentTarget.style.background="transparent"}>
              <Td C={C} style={{color:C.orange,fontFamily:"monospace",fontSize:10,whiteSpace:"nowrap"}}>{n.id}</Td>
              <Td C={C}>{n.date}</Td><Td C={C}>{n.category}</Td>
              <Td C={C}><Badge label={n.severity} color={sevColor(n.severity,C)}/></Td>
              <Td C={C}>{siteName(n.site)||n.site}</Td><Td C={C}>{n.assignee}</Td>
              <Td C={C} style={{color:n.status==="Overdue"?C.red:C.sub}}>{n.due}</Td>
              <Td C={C}><Badge label={n.status} color={stColor(n.status,C)}/></Td>
              <Td C={C}><div style={{display:"flex",alignItems:"center",gap:6}}><div style={{flex:1,height:5,borderRadius:99,background:C.border,minWidth:40}}><div style={{width:`${n.closure}%`,background:n.closure>=70?C.green:n.closure>=30?C.orange:C.red,height:5,borderRadius:99}}/></div><span style={{fontSize:11,color:C.muted}}>{n.closure}%</span></div></Td>
              <Td C={C}>
                {n.photo
                  ? <a href={n.photo} target="_blank" rel="noreferrer" style={{background:C.teal+"22",border:`1px solid ${C.teal}44`,color:C.teal,borderRadius:6,padding:"3px 7px",cursor:"pointer",fontSize:10,fontWeight:700,textDecoration:"none"}}>📷 View</a>
                  : <span style={{color:C.muted,fontSize:11}}>—</span>
                }
              </Td>
              <Td C={C}>{role.canDelete&&<button onClick={()=>fbDel("ncr",n)} style={{background:"none",border:"none",cursor:"pointer",color:"#94a3b8"}}><Trash2 size={13}/></button>}</Td>
            </tr>
          ))}</tbody>
        </table>
      </TableCard>
    </div>
  );
};

// ── RISK ──────────────────────────────────────────────────────────────────────
const Risk = ({user,risks,riskCats=DEFAULT_RISK_CATS,riskStatus=DEFAULT_RISK_STATUS,C}) => {
  const role=ROLE_META[user.role];const [showForm,setShowForm]=useState(false);const [showBulk,setShowBulk]=useState(false);
  const [form,setForm]=useState({hazard:"",likelihood:3,impact:3,controls:"",owner:"",residual:1,category:riskCats[0]||"Physical",status:riskStatus[0]||"Active"});
  const set=(k,v)=>setForm(p=>({...p,[k]:v}));
  const [riskErr,setRiskErr]=useState("");
  const submit=async()=>{
    if(!form.hazard.trim()){setRiskErr("Hazard description is required.");return;}
    if(!form.owner.trim()){setRiskErr("Risk owner is required.");return;}
    const likelihood=Math.min(5,Math.max(1,Number(form.likelihood)||1));
    const impact    =Math.min(5,Math.max(1,Number(form.impact)||1));
    const residual  =Math.min(25,Math.max(1,Number(form.residual)||1));
    try{
      await fbAdd("risks",{...form,id:`R-${Date.now()}`,likelihood,impact,residual});
      setShowForm(false);setRiskErr("");
    }catch(e){setRiskErr("Failed to save risk: "+e.message);}
  };
  return(
    <div style={{display:"flex",flexDirection:"column",gap:18}}>
      <div style={{display:"flex",justifyContent:"flex-end",gap:8,flexWrap:"wrap"}}>
        {can(user,"risks",user.site,"add")&&<Btn onClick={()=>setShowForm(true)} color={C.purple}><Plus size={14}/>Add Risk</Btn>}
        {can(user,"risks",user.site,"add")&&<Btn onClick={()=>setShowBulk(p=>!p)} color={C.teal}><Download size={14}/>{showBulk?"Hide Import":"📊 Bulk Import"}</Btn>}
        <Btn onClick={()=>exportCSV(risks,"risk-register")} color={C.indigo}><Download size={14}/>CSV</Btn>
      </div>
      {showBulk&&(
        <BulkImporter
          section="risks" siteId={user.site==="All Sites"?"Site 1":user.site}
          existingIds={risks.map(r=>r.id)}
          user={user}
          riskCats={riskCats} riskStatus={riskStatus}
          zones={[]} obsTypes={[]} actionsList={[]} obsSeverity={[]}
          ncrCats={[]} ncrSeverity={[]} ncrStatus={[]}
          onDone={()=>setShowBulk(false)}
          C={C}
        />
      )}
      {showForm&&(
        <Modal title="Add New Risk" onClose={()=>setShowForm(false)} C={C}>
          <Field label="Hazard" C={C}><Inp C={C} placeholder="Describe the hazard" value={form.hazard} onChange={e=>set("hazard",e.target.value)}/></Field>
          <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:12}}>
            <Field label="Category" C={C}><Sel C={C} value={form.category} onChange={e=>set("category",e.target.value)}>{riskCats.map(s=><option key={s}>{s}</option>)}</Sel></Field>
            <Field label="Owner" C={C}><Inp C={C} value={form.owner} onChange={e=>set("owner",e.target.value)}/></Field>
            <Field label="Likelihood (1-5)" C={C}><Inp C={C} type="number" min={1} max={5} value={form.likelihood} onChange={e=>set("likelihood",e.target.value)}/></Field>
            <Field label="Impact (1-5)" C={C}><Inp C={C} type="number" min={1} max={5} value={form.impact} onChange={e=>set("impact",e.target.value)}/></Field>
            <Field label="Residual Score" C={C}><Inp C={C} type="number" min={1} max={25} value={form.residual} onChange={e=>set("residual",e.target.value)}/></Field>
            <Field label="Status" C={C}><Sel C={C} value={form.status} onChange={e=>set("status",e.target.value)}>{riskStatus.map(s=><option key={s}>{s}</option>)}</Sel></Field>
          </div>
          <Field label="Controls" C={C}><Txa C={C} rows={2} value={form.controls} onChange={e=>set("controls",e.target.value)}/></Field>
          {riskErr&&<div style={{color:C.red,fontSize:12,padding:"8px 12px",background:C.red+"11",borderRadius:8,marginTop:4}}>{riskErr}</div>}
          <Btn onClick={submit} color={C.purple} style={{marginTop:8}}>Add Risk</Btn>
        </Modal>
      )}
      <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fit,minmax(280px,1fr))",gap:16}}>
        <div style={{background:C.card,border:`1px solid ${C.border}`,borderRadius:14,padding:18}}><h3 style={{color:C.text,fontWeight:700,margin:"0 0 14px"}}>Risk Matrix</h3><RiskMatrix risks={risks} C={C}/></div>
        <div style={{background:C.card,border:`1px solid ${C.border}`,borderRadius:14,padding:18}}>
          <h3 style={{color:C.text,fontWeight:700,margin:"0 0 14px"}}>Distribution</h3>
          <ResponsiveContainer width="100%" height={180}>
            <PieChart><Pie data={[{name:"Critical",value:risks.filter(r=>riskScore(r)>=15).length||1},{name:"High",value:risks.filter(r=>{const s=riskScore(r);return s>=8&&s<15;}).length||1},{name:"Medium",value:risks.filter(r=>{const s=riskScore(r);return s>=4&&s<8;}).length||1},{name:"Low",value:risks.filter(r=>riskScore(r)<4).length||1}]} cx="50%" cy="50%" outerRadius={70} dataKey="value" label={({name,value})=>`${name}:${value}`}>{[C.red,C.orange,C.yellow,C.green].map((c,i)=><Cell key={i} fill={c}/>)}</Pie><Tooltip contentStyle={chartTooltip(C)}/></PieChart>
          </ResponsiveContainer>
        </div>
      </div>
      <TableCard title="Risk Register" C={C}>
        <table style={{width:"100%",borderCollapse:"collapse"}}>
          <thead><tr>{["ID","Hazard","Cat","L","I","Raw","Controls","Residual","Owner","Status",""].map(h=><Th key={h} C={C}>{h}</Th>)}</tr></thead>
          <tbody>{risks.map(r=>{const raw=riskScore(r);return(
            <tr key={r._docId||r.id} onMouseEnter={e=>e.currentTarget.style.background=C.border+"33"} onMouseLeave={e=>e.currentTarget.style.background="transparent"}>
              <Td C={C} style={{color:C.purple,fontFamily:"monospace",fontSize:11}}>{r.id}</Td>
              <Td C={C} style={{color:C.text,fontWeight:600}}>{r.hazard}</Td><Td C={C}>{r.category}</Td>
              <Td C={C} style={{textAlign:"center",color:riskColor(r.likelihood*3,C)}}>{r.likelihood}</Td>
              <Td C={C} style={{textAlign:"center",color:riskColor(r.impact*3,C)}}>{r.impact}</Td>
              <Td C={C}><Badge label={`${raw} ${riskLabel(raw)}`} color={riskColor(raw,C)}/></Td>
              <Td C={C} style={{maxWidth:140,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>{r.controls}</Td>
              <Td C={C}><Badge label={`${r.residual}`} color={riskColor(r.residual*3,C)}/></Td>
              <Td C={C}>{r.owner}</Td><Td C={C}><Badge label={r.status} color={stColor(r.status,C)}/></Td>
              <Td C={C}>{role.canDelete&&<button onClick={()=>fbDel("risks",r)} style={{background:"none",border:"none",cursor:"pointer",color:"#94a3b8"}}><Trash2 size={13}/></button>}</Td>
            </tr>
          );})}</tbody>
        </table>
      </TableCard>
    </div>
  );
};


// ── ADD INCIDENT MODAL ────────────────────────────────────────────────────────
// Smart form: fields show/hide and auto-populate based on the equation:
//   Injury      → Type=FAC/MTC/LTI/RWC/INJ, Nature=specific, BodyPart=specific, LWD shown
//   Damage-Only → Type=Asset/Fire/Material/Product, Nature=N/A, BodyPart=N/A, LWD hidden
//   Environmental → Type=spillage type, Nature=N/A, BodyPart=N/A
const AddIncidentModal = ({onClose, onSave, C}) => {
  const blank = {
    reportNo:"",damInjEnv:"FAC",date:"",day:"",time:"",shift:"A",
    description:"",eventCause:"",
    classification:"Injury",      // auto-derived
    type:"FAC",                   // injury subtype OR damage sub-type
    natureOfInjury:"",
    bodyPart:"",
    personName:"",personId:"",designation:"",department:"",age:"",
    lwd:"0",
    location:INCIDENT_AREAS[0],area:INCIDENT_AREAS[0],equipment:"",
    directCause:"",rootCause:ROOT_CAUSES[0],
    raScore:"",raLevel:"Moderate",
    likelihood:"2",severity:"2",
    reportSubmitted:"Yes",notes:"",
  };
  const [form,setForm] = useState(blank);
  const [saving,setSaving] = useState(false);
  const [err,setErr]       = useState("");
  const set = (k,v) => setForm(p=>({...p,[k]:v}));

  // ── The core equation: when damInjEnv changes, cascade all dependent fields ──
  const handleTypeChange = (code) => {
    const cls  = deriveClassification(code);
    const type = deriveType(code, cls);
    setForm(p=>({
      ...p,
      damInjEnv:      code,
      classification: cls,
      type:           type,
      // Reset injury-specific fields when switching to Damage/Environmental
      natureOfInjury: cls==="Injury" ? p.natureOfInjury : "N/A",
      bodyPart:       cls==="Injury" ? p.bodyPart        : "N/A",
      lwd:            cls==="Injury" ? p.lwd             : "0",
    }));
  };

  const isInjury     = form.classification === "Injury";
  const isDamage     = form.classification === "Damage-Only";
  const isEnv        = form.classification === "Environmental";

  const submit = async () => {
    if(!form.date)             { setErr("Date is required.");        return; }
    if(!form.description.trim()){ setErr("Description is required."); return; }
    if(isInjury && !form.natureOfInjury) { setErr("Nature of Injury is required for injury incidents."); return; }
    setSaving(true); setErr("");
    try {
      const day = new Date(form.date).toLocaleString("en-US",{weekday:"long"});
      await onSave({
        ...form, day,
        id: `INC-${Date.now()}`,
        createdAt: new Date().toISOString(),
      });
    } catch(e) { setErr("Save failed: "+e.message); }
    finally    { setSaving(false); }
  };

  // Classification badge colour for the indicator strip
  const clsColor = isInjury ? C.red : isDamage ? C.purple : C.green;
  const clsIcon  = isInjury ? "🩹" : isDamage ? "🚧" : "🌿";

  return(
    <Modal title="🚨 Log New Incident" onClose={onClose} C={C} wide>

      {/* ── Classification indicator strip ── */}
      <div style={{background:clsColor+"15",border:`1px solid ${clsColor}44`,borderRadius:10,
        padding:"10px 14px",marginBottom:14,display:"flex",alignItems:"center",gap:10,flexWrap:"wrap"}}>
        <span style={{fontSize:16}}>{clsIcon}</span>
        <div>
          <div style={{color:clsColor,fontWeight:700,fontSize:13}}>{form.classification}</div>
          <div style={{color:C.muted,fontSize:11}}>
            {isInjury  && "Nature of Injury + Body Part required"}
            {isDamage  && "Nature of Injury = N/A · Body Part = N/A"}
            {isEnv     && "Environmental incident · Nature = N/A"}
          </div>
        </div>
        <div style={{marginLeft:"auto",background:incidentColor(form.damInjEnv,C)+"22",
          border:`1px solid ${incidentColor(form.damInjEnv,C)}44`,borderRadius:99,
          padding:"3px 12px",color:incidentColor(form.damInjEnv,C),fontWeight:700,fontSize:12}}>
          {form.damInjEnv}
        </div>
      </div>

      {/* ── Row 1: Type selector (drives everything) + Date + Shift ── */}
      <div style={{display:"grid",gridTemplateColumns:"1fr 1fr 1fr",gap:12,marginBottom:4}}>
        <Field label="Report No" C={C}>
          <Inp C={C} placeholder="AMT-INCI-XXX" value={form.reportNo} onChange={e=>set("reportNo",e.target.value)}/>
        </Field>
        <Field label="Type (DAM / INJ / ENV) *" C={C}>
          <Sel C={C} value={form.damInjEnv} onChange={e=>handleTypeChange(e.target.value)}
            style={{borderColor:incidentColor(form.damInjEnv,C),color:incidentColor(form.damInjEnv,C),fontWeight:700}}>
            <optgroup label="── Injury ──">
              <option value="FAC">FAC — First Aid Case</option>
              <option value="MTC">MTC — Medical Treatment</option>
              <option value="RWC">RWC — Restricted Work Case</option>
              <option value="LTI">LTI — Lost Time Injury</option>
              <option value="INJ">INJ — Injury (general)</option>
            </optgroup>
            <optgroup label="── Damage-Only ──">
              <option value="MVA">MVA — Motor Vehicle Accident</option>
              <option value="PD">PD — Property Damage</option>
              <option value="PD (FIRE)">PD (FIRE) — Fire</option>
            </optgroup>
            <optgroup label="── Environmental ──">
              <option value="ENV">ENV — Environmental</option>
            </optgroup>
          </Sel>
        </Field>
        <Field label="Classification (auto)" C={C}>
          <div style={{background:clsColor+"15",border:`1px solid ${clsColor}44`,borderRadius:8,
            padding:"8px 12px",fontSize:13,fontWeight:700,color:clsColor}}>
            {form.classification}
          </div>
        </Field>
        <Field label="Date *" C={C}><Inp C={C} type="date" value={form.date} onChange={e=>set("date",e.target.value)}/></Field>
        <Field label="Time" C={C}><Inp C={C} type="time" value={form.time} onChange={e=>set("time",e.target.value)}/></Field>
        <Field label="Shift" C={C}>
          <Sel C={C} value={form.shift} onChange={e=>set("shift",e.target.value)}>
            <option value="A">Shift A</option>
            <option value="B">Shift B</option>
            <option value="C">Shift C</option>
          </Sel>
        </Field>
      </div>

      {/* ── Description ── */}
      <Field label="Description *" C={C}>
        <Txa C={C} rows={2} placeholder="Describe what happened..." value={form.description} onChange={e=>set("description",e.target.value)}/>
      </Field>
      <Field label="Event / Exposure / Cause" C={C}>
        <Txa C={C} rows={2} value={form.eventCause} onChange={e=>set("eventCause",e.target.value)}/>
      </Field>

      {/* ── INJURY FIELDS — only shown when classification = Injury ── */}
      {isInjury&&(
        <div style={{background:C.red+"08",border:`1px solid ${C.red}22`,borderRadius:10,padding:14,marginBottom:12}}>
          <div style={{color:C.red,fontWeight:700,fontSize:12,marginBottom:10}}>🩹 Injury Details</div>
          <div style={{display:"grid",gridTemplateColumns:"1fr 1fr 1fr",gap:12}}>
            <Field label="Injury Sub-Type" C={C}>
              <div style={{background:C.bg,border:`1px solid ${C.red}44`,borderRadius:8,
                padding:"8px 12px",fontSize:13,fontWeight:700,color:C.red}}>
                {form.type || form.damInjEnv}
              </div>
            </Field>
            <Field label="Nature of Injury *" C={C}>
              <Sel C={C} value={form.natureOfInjury} onChange={e=>set("natureOfInjury",e.target.value)}>
                <option value="">— Select —</option>
                {NATURE_OF_INJURY.map(n=><option key={n}>{n}</option>)}
              </Sel>
            </Field>
            <Field label="Affected Body Part *" C={C}>
              <Sel C={C} value={form.bodyPart} onChange={e=>set("bodyPart",e.target.value)}>
                <option value="">— Select —</option>
                {BODY_PARTS.map(b=><option key={b}>{b}</option>)}
              </Sel>
            </Field>
            <Field label="LWD (Lost Work Days)" C={C}>
              <Inp C={C} type="number" min={0} value={form.lwd} onChange={e=>set("lwd",e.target.value)}/>
            </Field>
            <Field label="Person Name" C={C}>
              <Inp C={C} value={form.personName} onChange={e=>set("personName",e.target.value)}/>
            </Field>
            <Field label="Iqama / ID Number" C={C}>
              <Inp C={C} value={form.personId} onChange={e=>set("personId",e.target.value)}/>
            </Field>
            <Field label="Designation" C={C}>
              <Inp C={C} value={form.designation} onChange={e=>set("designation",e.target.value)}/>
            </Field>
            <Field label="Department" C={C}>
              <Inp C={C} value={form.department} onChange={e=>set("department",e.target.value)}/>
            </Field>
            <Field label="Age" C={C}>
              <Inp C={C} type="number" min={16} max={70} value={form.age} onChange={e=>set("age",e.target.value)}/>
            </Field>
          </div>
        </div>
      )}

      {/* ── DAMAGE / ENV FIELDS — shown when not Injury ── */}
      {(isDamage||isEnv)&&(
        <div style={{background:isDamage?C.purple+"08":C.green+"08",
          border:`1px solid ${isDamage?C.purple:C.green}22`,borderRadius:10,padding:14,marginBottom:12}}>
          <div style={{color:isDamage?C.purple:C.green,fontWeight:700,fontSize:12,marginBottom:10}}>
            {isDamage?"🚧 Damage Details":"🌿 Environmental Details"}
          </div>
          <div style={{display:"grid",gridTemplateColumns:"1fr 1fr 1fr",gap:12}}>
            <Field label="Sub-Type" C={C}>
              <Sel C={C} value={form.type} onChange={e=>set("type",e.target.value)}>
                {isDamage
                  ? DAMAGE_ASSET_TYPES.map(t=><option key={t}>{t}</option>)
                  : ENV_SPILLAGE_TYPES.map(t=><option key={t}>{t}</option>)}
              </Sel>
            </Field>
            <Field label="Nature of Injury" C={C}>
              <div style={{background:C.bg,border:`1px solid ${C.border}`,borderRadius:8,
                padding:"8px 12px",fontSize:13,color:C.muted,fontStyle:"italic"}}>N/A</div>
            </Field>
            <Field label="Affected Body Part" C={C}>
              <div style={{background:C.bg,border:`1px solid ${C.border}`,borderRadius:8,
                padding:"8px 12px",fontSize:13,color:C.muted,fontStyle:"italic"}}>N/A</div>
            </Field>
            <Field label="Equipment / Vehicle Involved" C={C}>
              <Inp C={C} value={form.equipment} onChange={e=>set("equipment",e.target.value)}/>
            </Field>
            <Field label="Person / Operator Name" C={C}>
              <Inp C={C} value={form.personName} onChange={e=>set("personName",e.target.value)}/>
            </Field>
            <Field label="Designation" C={C}>
              <Inp C={C} value={form.designation} onChange={e=>set("designation",e.target.value)}/>
            </Field>
          </div>
        </div>
      )}

      {/* ── Location + Causes (always shown) ── */}
      <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:12}}>
        <Field label="Location" C={C}>
          <Sel C={C} value={form.location} onChange={e=>set("location",e.target.value)}>
            {INCIDENT_AREAS.map(a=><option key={a}>{a}</option>)}
          </Sel>
        </Field>
        <Field label="Area" C={C}>
          <Inp C={C} value={form.area} onChange={e=>set("area",e.target.value)}/>
        </Field>
        <Field label="Direct Cause" C={C}>
          <Inp C={C} placeholder="Immediate cause of incident" value={form.directCause} onChange={e=>set("directCause",e.target.value)}/>
        </Field>
        <Field label="Root Cause" C={C}>
          <Sel C={C} value={form.rootCause} onChange={e=>set("rootCause",e.target.value)}>
            {ROOT_CAUSES.map(r=><option key={r}>{r}</option>)}
          </Sel>
        </Field>
      </div>

      {/* ── Risk Assessment (always shown) ── */}
      <div style={{display:"grid",gridTemplateColumns:"1fr 1fr 1fr 1fr",gap:12,marginTop:4}}>
        <Field label="Likelihood (1-5)" C={C}>
          <Sel C={C} value={form.likelihood} onChange={e=>{
            const l=e.target.value, s=form.severity;
            set("likelihood",l);
            set("raScore", String(Number(l)*Number(s)));
            set("raLevel", Number(l)*Number(s)>=15?"Critical":Number(l)*Number(s)>=8?"High":Number(l)*Number(s)>=4?"Moderate":"Low");
          }}>
            {["1","2","3","4","5"].map(n=><option key={n}>{n}</option>)}
          </Sel>
        </Field>
        <Field label="Severity (1-5)" C={C}>
          <Sel C={C} value={form.severity} onChange={e=>{
            const s=e.target.value, l=form.likelihood;
            set("severity",s);
            set("raScore", String(Number(l)*Number(s)));
            set("raLevel", Number(l)*Number(s)>=15?"Critical":Number(l)*Number(s)>=8?"High":Number(l)*Number(s)>=4?"Moderate":"Low");
          }}>
            {["1","2","3","4","5"].map(n=><option key={n}>{n}</option>)}
          </Sel>
        </Field>
        <Field label="RA Score (auto)" C={C}>
          <div style={{background:C.bg,border:`1px solid ${raColor(form.raLevel,C)}44`,borderRadius:8,
            padding:"8px 12px",fontSize:14,fontWeight:700,color:raColor(form.raLevel,C)}}>
            {form.raScore||"—"}
          </div>
        </Field>
        <Field label="RA Level (auto)" C={C}>
          <div style={{background:raColor(form.raLevel,C)+"22",border:`1px solid ${raColor(form.raLevel,C)}44`,
            borderRadius:8,padding:"8px 12px",fontSize:13,fontWeight:700,color:raColor(form.raLevel,C)}}>
            {form.raLevel||"—"}
          </div>
        </Field>
      </div>

      <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:12,marginTop:4}}>
        <Field label="Report Submitted" C={C}>
          <Sel C={C} value={form.reportSubmitted} onChange={e=>set("reportSubmitted",e.target.value)}>
            <option>Yes</option><option>No</option><option>Pending</option>
          </Sel>
        </Field>
        <Field label="Notes / Remarks" C={C}>
          <Inp C={C} value={form.notes} onChange={e=>set("notes",e.target.value)}/>
        </Field>
      </div>

      {err&&<div style={{color:C.red,fontSize:12,marginBottom:8,background:C.red+"11",padding:"8px 12px",borderRadius:8,marginTop:8}}>{err}</div>}
      <Btn onClick={submit} color={clsColor} disabled={saving} style={{width:"100%",justifyContent:"center",marginTop:12,fontSize:14}}>
        {saving?"Saving...": isInjury?"🩹 Log Injury Incident": isDamage?"🚧 Log Damage Incident":"🌿 Log Environmental Incident"}
      </Btn>
    </Modal>
  );
};

// ── INCIDENT REGISTER PANEL ───────────────────────────────────────────────────
// Based on AMT Incident Register structure:
// Types: INJ (Injury), MVA (Motor Vehicle Accident), PD (Property Damage),
//        FAC (First Aid Case), LTI (Lost Time Injury), RWC (Restricted Work Case)
//        MTC (Medical Treatment Case), PD (FIRE)
// Classification: Injury, Damage-Only, Environmental
// ── Incident type groups (from AMT register) ─────────────────────────────────
const INCIDENT_TYPES   = ["FAC","MTC","RWC","LTI","INJ","MVA","PD","PD (FIRE)","ENV"];
const INCIDENT_CLASS   = ["Injury","Damage-Only","Environmental"];

// Damage sub-types (Asset, Fire, Material, Product — from your register "Type" column)
const DAMAGE_ASSET_TYPES = ["Asset","Material","Product","Fire"];
// Environmental types
const ENV_SPILLAGE_TYPES = ["Oil spillage","Chemical spillage","Sewage spillage","Air pollution"];

// Nature of Injury options (from Categories sheet)
const NATURE_OF_INJURY = [
  "Amputations","Bruises","Chemical burns/corrosions","Cuts","Disability",
  "Fatality","Fractures","Occupational diseases","Soreness, pain","Sprains",
  "Thermal burns","Asphyxiation","Electric Shock","Foreign Body","Hearing Loss or Impairment",
  "Inflammation","Laceration","Loss of an Eye","Mental Stress","Puncture wound",
  "Muscle pain","Other",
];

// Affected Body Part options (from Categories sheet)
const BODY_PARTS = [
  "Ankle","Arm","Back","Body systems","Eye","Face","Foot","Hand","Head",
  "Knee","Leg","Multiple","Neck","Nose","Pelvis","Shoulder","Toe, toenail","Trunk","Wrist","Other",
];

// ── INCIDENT CLASSIFICATION TABLE ────────────────────────────────────────────
// Every incident-code helper below reads from this ONE table instead of
// re-listing the codes. If a new code is added (e.g. "PSE"), add a single row.
// Fields per row:
//   group       — "Injury" | "Damage-Only" | "Environmental"
//   fullLabel   — long display label, e.g. "First Aid Case (FAC)"
//   badgeLabel  — short badge label, e.g. "FAC – First Aid"
//   defaultType — the default sub-type value when the code is selected
//   color       — dot/tag color for the code
const INCIDENT_CODES = {
  INJ:         {group:"Injury",        fullLabel:"Injury (INJ)",              badgeLabel:"INJ – Injury",    defaultType:"INJ",          color:"#ef4444"},
  FAC:         {group:"Injury",        fullLabel:"First Aid Case (FAC)",      badgeLabel:"FAC – First Aid", defaultType:"FAC",          color:"#eab308"},
  MTC:         {group:"Injury",        fullLabel:"Medical Treatment (MTC)",   badgeLabel:"MTC – Medical",   defaultType:"MTC",          color:"#fb923c"},
  LTI:         {group:"Injury",        fullLabel:"Lost Time Injury (LTI)",    badgeLabel:"LTI – Lost Time", defaultType:"LTI",          color:"#dc2626"},
  RWC:         {group:"Injury",        fullLabel:"Restricted Work Case (RWC)",badgeLabel:"RWC – Restricted",defaultType:"RWC",          color:"#f97316"},
  MVA:         {group:"Damage-Only",   fullLabel:"Motor Vehicle Accident",    badgeLabel:"MVA – Vehicle",   defaultType:"Asset",        color:"#a855f7"},
  PD:          {group:"Damage-Only",   fullLabel:"Property Damage",           badgeLabel:"PD – Property",   defaultType:"Asset",        color:"#3b82f6"},
  "PD (FIRE)": {group:"Damage-Only",   fullLabel:"Property Damage – Fire",    badgeLabel:"PD – Fire",       defaultType:"Fire",         color:"#f43f5e"},
  ENV:         {group:"Environmental", fullLabel:"Environmental",             badgeLabel:"ENV",             defaultType:"Oil spillage", color:"#22c55e"},
};
const incCode = (code) => INCIDENT_CODES[(code||"").toUpperCase().trim()] || null;
// Convenience arrays (used in .filter(...).includes()) — derived once, no dup.
const INJURY_TYPES = Object.keys(INCIDENT_CODES).filter(k=>INCIDENT_CODES[k].group==="Injury");
const DAMAGE_TYPES = Object.keys(INCIDENT_CODES).filter(k=>INCIDENT_CODES[k].group==="Damage-Only");
const ENV_TYPES    = Object.keys(INCIDENT_CODES).filter(k=>INCIDENT_CODES[k].group==="Environmental");

// Derive classification from DAM/INJ/ENV code
const deriveClassification = (code) => incCode(code)?.group || "Damage-Only";

// Derive "Type" sub-field from DAM/INJ/ENV code
// eslint-disable-next-line no-unused-vars
const deriveType = (code, currentClassification) => incCode(code)?.defaultType || "";

const ROOT_CAUSES = [
  "Sub-standard Housekeeping","Neglecting Safety Procedures","Lack of competency",
  "Lack of supervision","Lack of awareness","Defective equipment or tool",
  "No or poor procedures","Improper/Inadequate Training","Overconfidence",
  "Mental Distractions","Mechanical failure","Defective material","Other",
];
const INCIDENT_AREAS = [
  "Agritourism","Wellness","Advanture","Arch","Event Hall","Community Center",
  "Office area","Site Route","Dumping area","Messhall Parking","Laydown","Fabrication","Other",
];
const RA_LEVELS = [
  {label:"Low",color:"#22c55e"},{label:"Moderate",color:"#eab308"},
  {label:"High",color:"#f97316"},{label:"Critical",color:"#ef4444"},
];

const incidentColor = (type, C) => incCode(type)?.color || C.muted;

// Full classification label: combines Injury/Damage/Environmental with injury subtype.
// Falls back to the free-text classificationField if no code is set.
const classificationLabel = (damInjEnv, classificationField) => {
  const c = incCode(damInjEnv);
  if(!c) return classificationField || (damInjEnv||"").toUpperCase().trim() || "—";
  return c.fullLabel;
};

// Short badge label for compact display
const classificationBadge = (damInjEnv) =>
  incCode(damInjEnv)?.badgeLabel || (damInjEnv||"").toUpperCase().trim() || "—";

// Color for classification category (group-level, not code-level)
const classColor = (damInjEnv, C) => {
  const g = incCode(damInjEnv)?.group;
  if(g==="Injury")        return C.red;
  if(g==="Damage-Only")   return C.purple;
  if(g==="Environmental") return C.green;
  return C.muted;
};

const raColor = (level, C) => ({Low:C.green, Moderate:C.yellow, High:C.orange, Critical:C.red}[level?.trim()] || C.muted);

const IncidentRegisterPanel = ({incidents, onAddIncident, onDeleteIncident, userRole, C}) => {
  const [showForm,setShowForm]   = useState(false);
  const [filter,setFilter]       = useState({type:"",classification:"",year:""});
  const [detail,setDetail]       = useState(null);
  const [importing,setImporting] = useState(false);
  const [importMsg,setImportMsg] = useState(null); // {type:"success"|"error", text}
  const role = ROLE_META[userRole]||ROLE_META.viewer;

  // ── Import Excel handler ─────────────────────────────────────────────────
  // Reads your AMT Incident Register Excel and saves each row to Firestore.
  // Expected columns (row 2 = header): #, Report #, DAM\INJ\ENV, Date,
  // Description, Classification, Type, Nature of Injury, Name of Person/...,
  // Location, Area, Direct Causes, Root Causes, Likelihood, Severity, RA Score, RA Level
  const handleImportExcel = async (e) => {
    const file = e.target.files[0];
    if(!file){ return; }
    setImporting(true);
    setImportMsg(null);
    try{
      const XLSX = await import("xlsx");
      const buffer = await file.arrayBuffer();
      const wb    = XLSX.read(buffer);
      const ws    = wb.Sheets[wb.SheetNames[0]];
      // header:1 gives raw arrays; row index 0 = group headers, row 1 = actual col names
      const rows  = XLSX.utils.sheet_to_json(ws, {header:1, defval:""});

      // Find the header row (row with "#" in first cell)
      const headerIdx = rows.findIndex(r=>String(r[0]).trim()==="#");
      if(headerIdx === -1) throw new Error("Could not find header row. Expected '#' in column A.");
      const headers = rows[headerIdx].map(h=>String(h).trim());
      const dataRows= rows.slice(headerIdx+1).filter(r=>r[0]&&String(r[0]).trim()!==""&&!isNaN(Number(r[0])));

      // Column index helpers
      const col = (name) => headers.findIndex(h=>h.toLowerCase().includes(name.toLowerCase()));
      const val = (row, name) => { const i=col(name); return i>=0?String(row[i]||"").trim():""; };
      const valExact = (row, idx) => String(row[idx]||"").trim();

      // Parse Excel serial date OR date string
      const parseDate = (raw) => {
        if(!raw||raw==="") return "";
        // Excel serial number
        if(typeof raw === "number"){
          const d = XLSX.SSF.parse_date_code(raw);
          if(d) return `${d.y}-${String(d.m).padStart(2,"0")}-${String(d.d).padStart(2,"0")}`;
        }
        // String date
        const p = new Date(raw);
        if(!isNaN(p)) return p.toISOString().split("T")[0];
        return String(raw);
      };

      let saved = 0, skipped = 0;
      // Check existing report numbers to avoid duplicates
      const existingReportNos = new Set(incidents.map(i=>i.reportNo));

      for(const row of dataRows){
        const reportNo = val(row,"Report #") || val(row,"report");
        if(!reportNo){ skipped++; continue; }
        // Skip duplicates
        if(existingReportNos.has(reportNo)){ skipped++; continue; }

        const dateRaw = row[3]; // Column D is always Date
        const dateStr = parseDate(dateRaw);

        const record = {
          id:             `INC-${Date.now()}-${saved}`,
          no:             String(row[0]||"").trim(),
          reportNo,
          damInjEnv:      valExact(row,2), // Column C is always DAM\INJ\ENV
          date:           dateStr,
          day:            val(row,"Day"),
          year:           val(row,"Year"),
          time:           val(row,"Time"),
          shift:          val(row,"Shift"),
          description:    val(row,"Description"),
          eventCause:     val(row,"Event") || val(row,"Exposure"),
          // Derive classification from DAM\INJ\ENV if column is missing/generic
          classification: (()=>{
            const raw = valExact(row,2).toUpperCase().trim();
            if(["INJ","FAC","MTC","LTI","RWC"].includes(raw)) return "Injury";
            if(["MVA","PD","PD (FIRE)"].includes(raw))        return "Damage-Only";
            if(raw==="ENV")                                    return "Environmental";
            // Fall back to the Classification column if present
            return val(row,"Classification") || "Damage-Only";
          })(),
          type:           val(row,"Type"),
          // Nature of Injury — only meaningful for Injury incidents
          natureOfInjury: (()=>{
            const cls = deriveClassification(valExact(row,2));
            if(cls!=="Injury") return "N/A";
            return val(row,"Nature")||val(row,"Nature of Injury")||"";
          })(),
          // Affected Body Part — only meaningful for Injury incidents
          bodyPart: (()=>{
            const cls = deriveClassification(valExact(row,2));
            if(cls!=="Injury") return "N/A";
            return val(row,"Affected")||val(row,"Affected Body Part")||"";
          })(),
          lwd:            val(row,"LWD"),
          personId:       val(row,"ID"),
          personName:     val(row,"Name of Person") || val(row,"Name"),
          designation:    val(row,"Designation"),
          department:     val(row,"Department"),
          age:            val(row,"Age"),
          location:       val(row,"Location"),
          area:           val(row,"Area"),
          equipment:      val(row,"Plant"),
          directCause:    val(row,"Direct"),
          rootCause:      val(row,"Root"),
          reportSubmitted:val(row,"Report Submitted"),
          likelihood:     val(row,"Likelihood"),
          severity:       val(row,"Severity"),
          raScore:        val(row,"RA Score"),
          raLevel:        val(row,"RA Level"),
          importedAt:     new Date().toISOString(),
          source:         "excel_import",
        };

        await onAddIncident(record);
        existingReportNos.add(reportNo);
        saved++;
      }

      setImportMsg({
        type:"success",
        text:`✅ Imported ${saved} incident${saved!==1?"s":""}${skipped>0?` (${skipped} skipped — already exist or empty)`:""}.  The 6-Month Trend chart will update automatically.`
      });
    }catch(err){
      console.error("[HSSE] Incident Excel import error:",err);
      setImportMsg({type:"error", text:`❌ Import failed: ${err.message}`});
    }finally{
      setImporting(false);
      e.target.value="";
    }
  };

  const today = new Date();
  const thisYear  = today.getFullYear();
  const thisMonth = today.getMonth();

  // Summary stats
  const ytd    = incidents.filter(i=>{ const d=new Date(i.date); return !isNaN(d)&&d.getFullYear()===thisYear; });
  const mtd    = incidents.filter(i=>{ const d=new Date(i.date); return !isNaN(d)&&d.getFullYear()===thisYear&&d.getMonth()===thisMonth; });
  const ltiCount   = incidents.filter(i=>i.damInjEnv==="LTI").length;
  // eslint-disable-next-line no-unused-vars
  const injCount   = incidents.filter(i=>["INJ","FAC","MTC","LTI","RWC"].includes(i.damInjEnv||"")).length;
  const mvaCount   = incidents.filter(i=>i.damInjEnv==="MVA").length;
  const fireCount  = incidents.filter(i=>(i.damInjEnv||"").includes("FIRE")).length;

  const filtered = incidents.filter(i=>{
    if(filter.type           && i.damInjEnv!==filter.type)           return false;
    if(filter.classification){
      const ft = filter.classification;
      const allTypes = ["INJ","FAC","MTC","LTI","RWC","MVA","PD","PD (FIRE)","ENV"];
      // If filter is a subtype (FAC, MVA etc.) match on damInjEnv
      if(allTypes.includes(ft)){
        if((i.damInjEnv||"").toUpperCase().trim() !== ft) return false;
      } else {
        // Otherwise match on classification field (Injury / Damage-Only / Environmental)
        if(i.classification !== ft) return false;
      }
    }
    if(filter.year           && String(new Date(i.date).getFullYear())!==filter.year) return false;
    return true;
  });

  const years = [...new Set(incidents.map(i=>String(new Date(i.date).getFullYear())).filter(Boolean))].sort().reverse();

  return(
    <div style={{display:"flex",flexDirection:"column",gap:14}}>
      {/* Header */}
      <div style={{background:C.card,border:`1px solid ${C.border}`,borderRadius:14,overflow:"hidden"}}>
        <div style={{background:"linear-gradient(135deg,#7f1d1d,#450a0a)",padding:"14px 18px",display:"flex",justifyContent:"space-between",alignItems:"center",flexWrap:"wrap",gap:8}}>
          <div>
            <div style={{color:"#fff",fontWeight:900,fontSize:15}}>📋 Incident & Accident Register</div>
            <div style={{color:"#fca5a5",fontSize:11,marginTop:2}}>AMT — DAN Company · Palm1 Al-Ahsa Project</div>
          </div>
          <div style={{display:"flex",gap:10,flexWrap:"wrap"}}>
            {[
            ["Total",     incidents.length,                                                                              C.muted  ],
            ["Injury",    incidents.filter(i=>["INJ"].includes(i.damInjEnv||"")).length,                                "#ef4444"],
            ["FAC",       incidents.filter(i=>(i.damInjEnv||"")==="FAC").length,                                        "#eab308"],
            ["MTC",       incidents.filter(i=>(i.damInjEnv||"")==="MTC").length,                                        "#fb923c"],
            ["RWC",       incidents.filter(i=>(i.damInjEnv||"")==="RWC").length,                                        "#f97316"],
            ["LTI",       ltiCount,                                                                                     "#dc2626"],
            ["MVA",       mvaCount,                                                                                     "#a855f7"],
            ["Fire",      fireCount,                                                                                     "#f43f5e"],
          ].map(([l,v,c])=>(
              <div key={l} style={{background:"rgba(255,255,255,0.1)",borderRadius:8,padding:"6px 12px",textAlign:"center",minWidth:50}}>
                <div style={{color:v>0?c:"#fff",fontSize:18,fontWeight:900}}>{v}</div>
                <div style={{color:"#fca5a5",fontSize:9,textTransform:"uppercase",letterSpacing:1}}>{l}</div>
              </div>
            ))}
          </div>
        </div>

        {/* YTD / MTD strip */}
        <div style={{background:C.bg,padding:"10px 18px",display:"flex",gap:16,flexWrap:"wrap",borderBottom:`1px solid ${C.border}`}}>
          {[
            [`YTD ${thisYear}`,ytd.length,C.blue],
            [`MTD ${today.toLocaleString("default",{month:"short"})}`,mtd.length,C.teal],
            ["FAC",incidents.filter(i=>i.damInjEnv==="FAC").length,C.yellow],
            ["MTC",incidents.filter(i=>i.damInjEnv==="MTC").length,C.orange],
            ["RWC",incidents.filter(i=>i.damInjEnv==="RWC").length,C.orange],
            ["LTI",ltiCount,C.red],
            ["Damage-Only",incidents.filter(i=>i.classification==="Damage-Only").length,C.purple],
          ].map(([l,v,c])=>(
            <div key={l} style={{display:"flex",alignItems:"center",gap:5}}>
              <span style={{color:C.muted,fontSize:11}}>{l}:</span>
              <span style={{color:v>0?c:C.muted,fontWeight:700,fontSize:13}}>{v}</span>
            </div>
          ))}
        </div>

        {/* Toolbar */}
        <div style={{padding:"10px 18px",display:"flex",gap:8,flexWrap:"wrap",alignItems:"center",borderBottom:`1px solid ${C.border}`}}>
          {[["type","All Types",INCIDENT_TYPES],["classification","All Classifications",[...INCIDENT_CLASS,"INJ","FAC","MTC","LTI","RWC","MVA","PD"]],["year","All Years",years]].map(([k,ph,opts])=>(
            <select key={k} value={filter[k]} onChange={e=>setFilter(p=>({...p,[k]:e.target.value}))}
              style={{background:C.bg,border:`1px solid ${filter[k]?C.red:C.border}`,borderRadius:8,padding:"6px 10px",color:filter[k]?C.red:C.text,fontSize:12,outline:"none",fontWeight:filter[k]?700:400}}>
              <option value="">{ph}</option>
              {opts.map(o=><option key={o}>{o}</option>)}
            </select>
          ))}
          <span style={{fontSize:11,color:C.muted}}>{filtered.length}/{incidents.length} records</span>
          {Object.values(filter).some(Boolean)&&<button onClick={()=>setFilter({type:"",classification:"",year:""})} style={{background:C.red+"22",border:`1px solid ${C.red}44`,color:C.red,borderRadius:8,padding:"5px 10px",fontSize:11,fontWeight:700,cursor:"pointer"}}>✕ Clear</button>}
          <div style={{marginLeft:"auto",display:"flex",gap:6,alignItems:"center"}}>
            {/* ── Import Excel button ── */}
            {role.canAdd&&(
              <label style={{background:C.green,color:"#fff",borderRadius:8,padding:"6px 14px",fontWeight:700,fontSize:12,cursor:importing?"not-allowed":"pointer",display:"flex",alignItems:"center",gap:5,opacity:importing?0.6:1}}>
                <Download size={12}/>{importing?"Importing...":"📥 Import Excel"}
                <input type="file" accept=".xlsx,.xls" onChange={handleImportExcel} style={{display:"none"}} disabled={importing}/>
              </label>
            )}
            {role.canAdd&&<button onClick={()=>setShowForm(true)} style={{background:C.red,color:"#fff",border:"none",borderRadius:8,padding:"6px 14px",fontWeight:700,fontSize:12,cursor:"pointer",display:"flex",alignItems:"center",gap:5}}>
              <span style={{fontSize:14}}>+</span> Log Incident
            </button>}
          </div>
        </div>

        {/* Import result message */}
        {importMsg&&(
          <div style={{margin:"8px 18px",padding:"10px 14px",background:importMsg.type==="success"?C.green+"22":C.red+"22",border:`1px solid ${importMsg.type==="success"?C.green:C.red}44`,borderRadius:8,display:"flex",justifyContent:"space-between",alignItems:"center",gap:10}}>
            <span style={{fontSize:12,color:importMsg.type==="success"?C.green:C.red,fontWeight:600}}>{importMsg.text}</span>
            <button onClick={()=>setImportMsg(null)} style={{background:"none",border:"none",cursor:"pointer",color:C.muted,fontSize:14}}>✕</button>
          </div>
        )}

        {/* Table */}
        <div style={{overflowX:"auto"}}>
          <table style={{width:"100%",borderCollapse:"collapse",minWidth:900}}>
            <thead>
              <tr style={{background:C.bg}}>
                {["#","Report No","Type","Date","Description","Classification","Location","Area","Direct Cause","Root Cause","RA Level",""].map(h=>(
                  <th key={h} style={{textAlign:"left",fontSize:10,color:C.muted,textTransform:"uppercase",letterSpacing:1,padding:"9px 12px",whiteSpace:"nowrap",borderBottom:`2px solid ${C.border}`}}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {filtered.length===0&&(
                <tr><td colSpan={12} style={{padding:"32px",textAlign:"center",color:C.muted,fontSize:13}}>No incidents recorded for this period. ✅</td></tr>
              )}
              {filtered.map((inc,idx)=>{
                const raLvl  = (inc.raLevel||"").trim();
                const incType= inc.damInjEnv||"";
                return(
                  <tr key={inc._docId||idx}
                    onMouseEnter={e=>e.currentTarget.style.background=C.border+"33"}
                    onMouseLeave={e=>e.currentTarget.style.background="transparent"}>
                    <td style={{padding:"8px 12px",fontSize:12,color:C.muted,borderBottom:`1px solid ${C.border}22`,fontWeight:700}}>{inc.no||idx+1}</td>
                    <td style={{padding:"8px 12px",fontSize:10,color:C.teal,fontFamily:"monospace",borderBottom:`1px solid ${C.border}22`,whiteSpace:"nowrap"}}>{inc.reportNo||"—"}</td>
                    <td style={{padding:"8px 12px",borderBottom:`1px solid ${C.border}22`}}>
                      <span style={{background:incidentColor(incType,C)+"22",color:incidentColor(incType,C),border:`1px solid ${incidentColor(incType,C)}44`,fontSize:10,fontWeight:700,padding:"2px 7px",borderRadius:99}}>{incType||"—"}</span>
                    </td>
                    <td style={{padding:"8px 12px",fontSize:12,color:C.sub,borderBottom:`1px solid ${C.border}22`,whiteSpace:"nowrap"}}>{inc.date?new Date(inc.date).toLocaleDateString("en-GB",{day:"2-digit",month:"short",year:"numeric"}):"—"}</td>
                    <td style={{padding:"8px 12px",fontSize:12,color:C.text,fontWeight:600,borderBottom:`1px solid ${C.border}22`,maxWidth:180,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}} title={inc.description}>{inc.description||"—"}</td>
                    <td style={{padding:"8px 12px",borderBottom:`1px solid ${C.border}22`}}>
                      <div style={{display:"flex",flexDirection:"column",gap:3}}>
                        {/* Injury subtype / damage type badge — derived from DAM\INJ\ENV */}
                        <span style={{
                          background:incidentColor(inc.damInjEnv,C)+"22",
                          color:incidentColor(inc.damInjEnv,C),
                          border:`1px solid ${incidentColor(inc.damInjEnv,C)}44`,
                          fontSize:10,fontWeight:700,padding:"2px 7px",borderRadius:99,
                          whiteSpace:"nowrap"
                        }}>
                          {classificationBadge(inc.damInjEnv)}
                        </span>
                        {/* Base classification (Injury / Damage-Only / Environmental) */}
                        <span style={{
                          fontSize:9,color:C.muted,paddingLeft:2
                        }}>
                          {INJURY_TYPES.includes((inc.damInjEnv||"").toUpperCase().trim())
                            ? "Injury"
                            : DAMAGE_TYPES.includes((inc.damInjEnv||"").toUpperCase().trim())
                            ? "Damage-Only"
                            : "Environmental"}
                        </span>
                      </div>
                    </td>
                    <td style={{padding:"8px 12px",fontSize:11,color:C.sub,borderBottom:`1px solid ${C.border}22`}}>{inc.location||"—"}</td>
                    <td style={{padding:"8px 12px",fontSize:11,color:C.sub,borderBottom:`1px solid ${C.border}22`}}>{inc.area||"—"}</td>
                    <td style={{padding:"8px 12px",fontSize:11,color:C.sub,borderBottom:`1px solid ${C.border}22`,maxWidth:140,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}} title={inc.directCause}>{inc.directCause||"—"}</td>
                    <td style={{padding:"8px 12px",fontSize:11,color:C.sub,borderBottom:`1px solid ${C.border}22`,maxWidth:140,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}} title={inc.rootCause}>{inc.rootCause||"—"}</td>
                    <td style={{padding:"8px 12px",borderBottom:`1px solid ${C.border}22`}}>
                      {raLvl?<span style={{background:raColor(raLvl,C)+"22",color:raColor(raLvl,C),border:`1px solid ${raColor(raLvl,C)}44`,fontSize:10,fontWeight:700,padding:"2px 7px",borderRadius:99}}>{raLvl}</span>:<span style={{color:C.muted,fontSize:11}}>—</span>}
                    </td>
                    <td style={{padding:"8px 12px",borderBottom:`1px solid ${C.border}22`}}>
                      <div style={{display:"flex",gap:4}}>
                        <button onClick={()=>setDetail(inc)} style={{background:C.blue+"22",border:`1px solid ${C.blue}44`,color:C.blue,borderRadius:6,padding:"3px 7px",cursor:"pointer",fontSize:10,fontWeight:700}}>View</button>
                        {role.canDelete&&<button onClick={()=>onDeleteIncident(inc._docId)} style={{background:"none",border:"none",cursor:"pointer",color:C.muted,fontSize:13}}>🗑</button>}
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>

        {/* Monthly breakdown bar chart */}
        {incidents.length>0&&(
          <div style={{padding:18,borderTop:`1px solid ${C.border}`}}>
            <div style={{fontWeight:700,color:C.text,fontSize:13,marginBottom:12}}>Monthly Incident Breakdown</div>
            <ResponsiveContainer width="100%" height={160}>
              <BarChart data={(() => {
                const months=[];
                for(let i=5;i>=0;i--){
                  const d=new Date();d.setDate(1);d.setMonth(d.getMonth()-i);
                  const yr=d.getFullYear(),mo=d.getMonth(),lbl=d.toLocaleString("default",{month:"short"});
                  const inM=s=>{if(!s)return false;const p=new Date(s);return!isNaN(p)&&p.getFullYear()===yr&&p.getMonth()===mo;};
                  const m = incidents.filter(inc=>inM(inc.date));
                  months.push({
                    month:lbl,
                    Injuries:  m.filter(i=>["INJ","FAC","MTC","LTI","RWC"].includes(i.damInjEnv||"")).length,
                    MVA:       m.filter(i=>i.damInjEnv==="MVA").length,
                    "Property Damage": m.filter(i=>["PD","PD (FIRE)"].includes(i.damInjEnv||"")).length,
                  });
                }
                return months;
              })()}>
                <CartesianGrid strokeDasharray="3 3" stroke={C.border}/>
                <XAxis dataKey="month" tick={{fill:C.muted,fontSize:11}}/>
                <YAxis tick={{fill:C.muted,fontSize:10}} allowDecimals={false}/>
                <Tooltip contentStyle={chartTooltip(C)}/>
                <Legend/>
                <Bar dataKey="Injuries"         fill="#ef4444" radius={[3,3,0,0]}/>
                <Bar dataKey="MVA"              fill="#a855f7" radius={[3,3,0,0]}/>
                <Bar dataKey="Property Damage"  fill="#3b82f6" radius={[3,3,0,0]}/>
              </BarChart>
            </ResponsiveContainer>
          </div>
        )}
      </div>

      {/* Add Incident Modal */}
      {showForm&&<AddIncidentModal onClose={()=>setShowForm(false)} onSave={async(data)=>{await onAddIncident(data);setShowForm(false);}} C={C}/>}

      {/* Incident Detail Modal */}
      {detail&&(
        <Modal title={`Incident — ${detail.reportNo||detail._docId}`} onClose={()=>setDetail(null)} C={C} wide>
          <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:14}}>
            <div style={{background:C.bg,borderRadius:10,padding:14}}>
              <div style={{fontSize:11,color:C.muted,fontWeight:700,textTransform:"uppercase",marginBottom:10}}>Incident Details</div>
              {[
                ["Report No",  detail.reportNo],
                ["Type",       detail.damInjEnv],
                ["Date",       detail.date?new Date(detail.date).toLocaleDateString("en-GB",{day:"2-digit",month:"long",year:"numeric"}):"—"],
                ["Day",        detail.day],
                ["Time",       detail.time],
                ["Shift",      detail.shift],
                ["Classification", classificationLabel(detail.damInjEnv, detail.classification)],
                ["Location",   detail.location],
                ["Area",       detail.area],
              ].map(([l,v])=>(
                <div key={l} style={{display:"flex",justifyContent:"space-between",padding:"5px 0",borderBottom:`1px solid ${C.border}33`}}>
                  <span style={{color:C.muted,fontSize:12}}>{l}</span>
                  <span style={{color:C.text,fontWeight:600,fontSize:12}}>{v||"—"}</span>
                </div>
              ))}
            </div>
            <div style={{background:C.bg,borderRadius:10,padding:14}}>
              <div style={{fontSize:11,color:C.muted,fontWeight:700,textTransform:"uppercase",marginBottom:10}}>Persons Involved</div>
              {[
                ["Name",       detail.personName],
                ["ID",         detail.personId],
                ["Designation",detail.designation],
                ["Department", detail.department],
                ["Age",        detail.age],
                ["LWD",        detail.lwd||"0"],
                ["RA Score",   detail.raScore],
                ["RA Level",   detail.raLevel],
              ].map(([l,v])=>(
                <div key={l} style={{display:"flex",justifyContent:"space-between",padding:"5px 0",borderBottom:`1px solid ${C.border}33`}}>
                  <span style={{color:C.muted,fontSize:12}}>{l}</span>
                  <span style={{color:C.text,fontWeight:600,fontSize:12}}>{v||"—"}</span>
                </div>
              ))}
            </div>
          </div>
          <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:14,marginTop:14}}>
            <div style={{background:C.bg,borderRadius:10,padding:14}}>
              <div style={{fontSize:11,color:C.muted,fontWeight:700,textTransform:"uppercase",marginBottom:8}}>Description</div>
              <p style={{color:C.text,fontSize:13,lineHeight:1.7,margin:0}}>{detail.description||"—"}</p>
              <div style={{fontSize:11,color:C.muted,fontWeight:700,textTransform:"uppercase",marginTop:10,marginBottom:6}}>Event / Cause</div>
              <p style={{color:C.text,fontSize:12,lineHeight:1.6,margin:0}}>{detail.eventCause||"—"}</p>
            </div>
            <div style={{background:C.bg,borderRadius:10,padding:14}}>
              <div style={{fontSize:11,color:C.muted,fontWeight:700,textTransform:"uppercase",marginBottom:8}}>Direct Cause</div>
              <p style={{color:C.text,fontSize:13,lineHeight:1.7,margin:0}}>{detail.directCause||"—"}</p>
              <div style={{fontSize:11,color:C.muted,fontWeight:700,textTransform:"uppercase",marginTop:10,marginBottom:6}}>Root Cause</div>
              <p style={{color:C.orange,fontSize:13,lineHeight:1.7,margin:0,fontWeight:600}}>{detail.rootCause||"—"}</p>
            </div>
          </div>
        </Modal>
      )}
    </div>
  );
};


// ── WEEKLY ────────────────────────────────────────────────────────────────────
const Weekly = ({weeklyData,setWeeklyData,manualStats,setManualStats,incidents=[],onAddIncident,onDeleteIncident,userRole,C}) => {
  const [editMode,setEditMode]=useState(false);
  const [draft,setDraft]=useState(weeklyData.rows);
  const [importing,setImporting]=useState(false);
  const [saving,setSaving]=useState(false);
  const [showCumulative,setShowCumulative]=useState(false);
  const [editCumulative,setEditCumulative]=useState(false);
  const [cumulativeDraft,setCumulativeDraft]=useState(manualStats);
  useEffect(()=>{ if(!editMode) setDraft([...weeklyData.rows]); },[weeklyData, editMode]);
  useEffect(()=>{ if(!editCumulative) setCumulativeDraft(manualStats); },[manualStats,editCumulative]);

  const saveCumulative=async()=>{
    setManualStats(cumulativeDraft);
    await saveSettings({manualStats:cumulativeDraft});
    setEditCumulative(false);
  };

  const startEdit=()=>{setDraft([...weeklyData.rows]);setEditMode(true);};
  const saveEdit=async()=>{
    setSaving(true);
    const updated={...weeklyData,rows:draft};
    setWeeklyData(updated);
    // Also sync manualStats so Overview updates immediately
    const getVal=(no)=>parseInt(String(draft.find(r=>r.no===no)?.value||"0").replace(/,/g,""))||0;
    const updatedStats={...manualStats,
      manpower:getVal(24),manhoursWeek:getVal(25),manhoursMonth:getVal(26),
      manhoursYear:getVal(27),manhoursProject:getVal(28),
      safetyOfficers:getVal(31),firstAiders:getVal(34),
    };
    setManualStats(updatedStats);
    await saveSettings({weeklyData:updated,manualStats:updatedStats});
    setSaving(false);setEditMode(false);
  };
  const cancelEdit=()=>{setDraft([...weeklyData.rows]);setEditMode(false);};
  const updateDraft=(no,val)=>setDraft(p=>p.map(r=>r.no===no?{...r,value:val}:r));

  // ── Parse one weekly Excel file into a weeklyData object ──────────────────
  const parseWeeklyFile = async (XLSX, file) => {
    const buffer = await file.arrayBuffer();
    const wb = XLSX.read(buffer);
    const ws = wb.Sheets[wb.SheetNames[0]];
    const rows = XLSX.utils.sheet_to_json(ws, {header:1, defval:""});
    const newRows = weeklyData.rows.map(r=>({...r}));
    rows.forEach(row => {
      const no=parseInt(row[0]);const val=String(row[2]??row[1]??"").trim();
      if(no>=1&&no<=35){const idx=newRows.findIndex(r=>r.no===no);if(idx!==-1)newRows[idx]={...newRows[idx],value:val};}
    });
    let meta={...weeklyData,rows:newRows,fileName:file.name};
    rows.forEach(row=>{
      const c0=String(row[0]||"").toLowerCase().trim(),c2=String(row[2]||"").trim();
      if(c0.includes("date from"))meta={...meta,dateFrom:c2.split("-")[0]?.trim()||meta.dateFrom,dateTo:c2.split("-")[1]?.trim()||meta.dateTo};
      if(c0.includes("project name"))meta={...meta,project:c2};
      if(c0.includes("main contractor name"))meta={...meta,contractor:c2};
      if(c0.includes("supervision"))meta={...meta,consultant:c2};
    });
    const headerRow=rows.find(r=>String(r[2]||"").toLowerCase().includes("week no"));
    if(headerRow){const match=String(headerRow[2]).match(/week no\s*\((\d+)\)/i);if(match)meta={...meta,weekNo:parseInt(match[1])};}
    return meta;
  };

  const handleExcelImport = async (e) => {
    const files = Array.from(e.target.files);
    if(!files.length) return;
    setImporting(true);
    try {
      const XLSX = await import("xlsx");

      // Extract manualStats values from parsed weekly rows so Overview updates too
      const extractStats = (meta) => {
        const getVal = (no) => {
          const row = meta.rows.find(r=>r.no===no);
          return parseInt(String(row?.value||"0").replace(/,/g,""))||0;
        };
        return {
          manpower:        getVal(24),
          manhoursWeek:    getVal(25),
          manhoursMonth:   getVal(26),
          manhoursYear:    getVal(27),
          manhoursProject: getVal(28),
          safetyOfficers:  getVal(31),
          firstAiders:     getVal(34),
        };
      };

      if(files.length === 1) {
        const meta = await parseWeeklyFile(XLSX, files[0]);
        setWeeklyData(meta);
        const updatedStats = {...manualStats, ...extractStats(meta)};
        setManualStats(updatedStats);
        await saveSettings({weeklyData:meta, manualStats:updatedStats});
        alert("✅ Weekly report imported! Overview stats updated automatically.");
      } else {
        const sorted = [...files].sort((a,b)=>a.name.localeCompare(b.name));
        let saved = 0;
        for(let fi=0; fi<sorted.length; fi++) {
          const meta = await parseWeeklyFile(XLSX, sorted[fi]);
          await addDoc(collection(db,"weeklyReports"),{
            ...meta, importedAt:new Date().toISOString(), importedBy:"excel",
          });
          saved++;
        }
        const latestMeta = await parseWeeklyFile(XLSX, sorted[sorted.length-1]);
        setWeeklyData(latestMeta);
        const updatedStats = {...manualStats, ...extractStats(latestMeta)};
        setManualStats(updatedStats);
        await saveSettings({weeklyData:latestMeta, manualStats:updatedStats});
        alert("✅ Imported "+saved+" weekly report"+(saved!==1?"s":"")+"! Overview stats updated from latest week.");
      }
    } catch(err){console.error(err);alert("❌ Could not read Excel file. Error: "+err.message);}
    finally{setImporting(false);e.target.value="";}
  };

  // eslint-disable-next-line no-unused-vars
  const groups=[...new Set(weeklyData.rows.map(r=>r.group))];
  const obsData=[{name:"Positive",value:parseInt(weeklyData.rows.find(r=>r.no===15)?.value)||0,fill:"#22c55e"},{name:"Negative",value:parseInt(weeklyData.rows.find(r=>r.no===16)?.value)||0,fill:"#f97316"}];
  const manHours=[{name:"Week",value:parseInt((weeklyData.rows.find(r=>r.no===25)?.value||"0").replace(/,/g,""))},{name:"Month",value:parseInt((weeklyData.rows.find(r=>r.no===26)?.value||"0").replace(/,/g,""))},{name:"Year",value:parseInt((weeklyData.rows.find(r=>r.no===27)?.value||"0").replace(/,/g,""))}];

  return(
    <div style={{display:"flex",flexDirection:"column",gap:16}}>
      <div style={{background:C.card,border:`1px solid ${C.border}`,borderRadius:14,overflow:"hidden"}}>
        <div style={{background:"linear-gradient(135deg,#1e3a5f,#0f2744)",padding:"18px 24px",display:"flex",justifyContent:"space-between",alignItems:"center",flexWrap:"wrap",gap:12}}>
          <div><div style={{color:"#fff",fontWeight:900,fontSize:18}}>{weeklyData.company}</div><div style={{color:"#93c5fd",fontSize:12,marginTop:2}}>{weeklyData.dept}</div><div style={{color:"#14b8a6",fontSize:12,fontWeight:600}}>{weeklyData.division}</div></div>
          <div style={{textAlign:"right"}}><div style={{background:"#14b8a6",color:"#fff",borderRadius:8,padding:"4px 14px",fontWeight:800,fontSize:13,marginBottom:4}}>WEEK {weeklyData.weekNo}</div><div style={{color:"#93c5fd",fontSize:12}}>{weeklyData.dateFrom} – {weeklyData.dateTo}</div></div>
        </div>
        <div style={{background:C.bg,padding:"12px 20px",display:"grid",gridTemplateColumns:"repeat(auto-fit,minmax(220px,1fr))",gap:8,borderBottom:`1px solid ${C.border}`}}>
          {[["Project",weeklyData.project],["Main Contractor",weeklyData.contractor],["Supervision Consultant",weeklyData.consultant],["Date Range",`${weeklyData.dateFrom} – ${weeklyData.dateTo}`]].map(([l,v])=>(
            <div key={l} style={{display:"flex",gap:8}}><span style={{color:C.muted,fontSize:11,fontWeight:600,minWidth:120,flexShrink:0}}>{l}:</span><span style={{color:C.text,fontSize:12,fontWeight:700}}>{v}</span></div>
          ))}
        </div>
        <div style={{padding:"10px 20px",display:"flex",justifyContent:"space-between",alignItems:"center",borderBottom:`1px solid ${C.border}`,flexWrap:"wrap",gap:8}}>
          <div style={{display:"flex",gap:8,alignItems:"center",flexWrap:"wrap"}}>
            {userRole!=="viewer"&&(
              <label style={{background:C.teal,color:"#fff",borderRadius:8,padding:"6px 14px",fontWeight:700,fontSize:12,cursor:importing?"not-allowed":"pointer",display:"flex",alignItems:"center",gap:6,opacity:importing?0.6:1}}>
                <Download size={12}/>{importing?"Importing...":"📊 Import Excel"}
                <input type="file" accept=".xlsx,.xls" multiple onChange={handleExcelImport} style={{display:"none"}} disabled={importing}/>
              </label>
            )}
            <button onClick={()=>setShowCumulative(p=>!p)}
              style={{background:showCumulative?C.gold+"33":C.bg,color:showCumulative?C.gold:C.sub,border:`1px solid ${showCumulative?C.gold:C.border}`,borderRadius:8,padding:"6px 14px",fontWeight:700,fontSize:12,cursor:"pointer",display:"flex",alignItems:"center",gap:5}}>
              <TrendingUp size={13}/>📈 Cumulative Stats
            </button>
          </div>
          <div style={{display:"flex",gap:6,alignItems:"center"}}>
            <SavingBadge saving={saving} C={C}/>
            <button onClick={editMode?saveEdit:startEdit} style={{background:editMode?C.green:C.blue,color:"#fff",border:"none",borderRadius:8,padding:"6px 14px",fontWeight:700,fontSize:12,cursor:"pointer",display:"flex",alignItems:"center",gap:6}}>
              {editMode?<><Save size={12}/>Save</>:<><Edit2 size={12}/>Edit Values</>}
            </button>
            {editMode&&<button onClick={cancelEdit} style={{background:C.border,color:C.text,border:"none",borderRadius:8,padding:"6px 14px",fontWeight:700,fontSize:12,cursor:"pointer"}}>Cancel</button>}
          </div>
        </div>
        {/* ── CUMULATIVE STATS PANEL ── */}
        {showCumulative&&(
          <div style={{padding:"14px 20px",borderBottom:`1px solid ${C.border}`,background:C.bg}}>
            <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:12,flexWrap:"wrap",gap:8}}>
              <span style={{color:C.text,fontWeight:700,fontSize:14}}>📈 Cumulative Statistics</span>
              <div style={{display:"flex",gap:6}}>
                {editCumulative
                  ? <><Btn onClick={saveCumulative} color={C.green}><Save size={13}/>Save</Btn>
                      <Btn onClick={()=>setEditCumulative(false)} color={C.muted} style={{background:C.border}}>Cancel</Btn></>
                  : <Btn onClick={()=>{setCumulativeDraft(manualStats);setEditCumulative(true);}} color={C.blue}><Edit2 size={13}/>Edit</Btn>
                }
              </div>
            </div>
            <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fit,minmax(180px,1fr))",gap:10,marginBottom:12}}>
              {[
                {key:"manhoursWeek",   label:"This Week",       sub:"Construction hours",    color:C.teal,   icon:"⏱"},
                {key:"manhoursMonth",  label:"This Month",      sub:"Safe hours month",       color:C.blue,   icon:"📅"},
                {key:"manhoursYear",   label:"Year to Date",    sub:"Accumulated this year",  color:C.indigo, icon:"📆"},
                {key:"manhoursProject",label:"Project to Date", color:C.green,               sub:"Total project hours", icon:"🏗"},
                {key:"manpower",       label:"Manpower",        sub:"Daily headcount",        color:C.purple, icon:"👷"},
                {key:"tbtAttendees",   label:"TBT Attendees",   sub:"This month",             color:C.teal,   icon:"📢"},
                {key:"safetyOfficers", label:"Safety Officers", sub:"On site",                color:C.blue,   icon:"👮"},
                {key:"firstAiders",    label:"First Aiders",    sub:"Certified on site",      color:C.orange, icon:"🏥"},
              ].map(({key,label,sub,color,icon})=>(
                <div key={key} style={{background:C.card,border:`1px solid ${color}33`,borderRadius:10,padding:"12px 14px"}}>
                  <div style={{fontSize:10,color:C.muted,marginBottom:2}}>{icon} {label}</div>
                  <div style={{fontSize:10,color:C.muted,marginBottom:6,fontStyle:"italic"}}>{sub}</div>
                  {editCumulative
                    ? <Inp C={C} type="number" value={cumulativeDraft[key]||0}
                        onChange={e=>setCumulativeDraft(p=>({...p,[key]:Number(e.target.value)}))}/>
                    : <div style={{fontSize:22,fontWeight:900,color}}>{(manualStats[key]||0).toLocaleString()}</div>
                  }
                </div>
              ))}
            </div>
            <div style={{padding:"8px 12px",background:C.teal+"11",border:`1px solid ${C.teal}33`,borderRadius:8,fontSize:11,color:C.teal}}>
              💡 Auto-updates when you import Excel. Edit manually to correct historical cumulative totals. Saves directly to the Overview dashboard.
            </div>
          </div>
        )}
        <div style={{overflowX:"auto"}}>
          <table style={{width:"100%",borderCollapse:"collapse"}}>
            <thead><tr style={{background:C.bg}}>{["No","Description",`Week No (${weeklyData.weekNo})`,"Group"].map(h=>(
              <th key={h} style={{padding:"10px 14px",fontSize:11,color:C.muted,textTransform:"uppercase",letterSpacing:1,textAlign:h==="No"||h.includes("Week")?"center":"left",borderBottom:`2px solid ${C.border}`}}>{h}</th>
            ))}</tr></thead>
            <tbody>{groups.map(group=>{
              const groupRows=(editMode?draft:weeklyData.rows).filter(r=>r.group===group),gc=GROUP_COLORS[group]||C.teal;
              return groupRows.map((row,i)=>(
                <tr key={row.no} style={{background:row.highlight?(gc+"11"):"transparent"}} onMouseEnter={e=>e.currentTarget.style.background=gc+"22"} onMouseLeave={e=>e.currentTarget.style.background=row.highlight?(gc+"11"):"transparent"}>
                  <td style={{padding:"8px 14px",fontSize:12,color:C.muted,textAlign:"center",borderBottom:`1px solid ${C.border}22`,fontWeight:700}}>{row.no}</td>
                  <td style={{padding:"8px 14px",fontSize:13,color:C.text,borderBottom:`1px solid ${C.border}22`}}>{row.desc}</td>
                  <td style={{padding:"8px 14px",textAlign:"center",borderBottom:`1px solid ${C.border}22`}}>
                    {editMode?<input value={row.value} onChange={e=>updateDraft(row.no,e.target.value)} style={{background:C.bg,border:`1px solid ${gc}`,borderRadius:6,padding:"4px 8px",color:C.text,fontSize:13,textAlign:"center",width:"100%",outline:"none",boxSizing:"border-box"}}/>:
                      <span style={{color:row.value==="0"?C.muted:row.color==="green"?C.green:row.color==="orange"?C.orange:row.color==="blue"?C.blue:row.color==="teal"?C.teal:row.color==="purple"?C.purple:C.text,fontWeight:row.value==="0"?400:700,fontSize:row.wide?11:13,display:"block",textAlign:row.wide?"left":"center",padding:row.wide?"0 8px":"0"}}>{row.value}</span>}
                  </td>
                  <td style={{padding:"8px 14px",textAlign:"center",borderBottom:`1px solid ${C.border}22`}}>
                    {i===0&&<span style={{background:gc+"22",color:gc,fontSize:10,fontWeight:700,padding:"2px 8px",borderRadius:99,border:`1px solid ${gc}44`,whiteSpace:"nowrap"}}>{group}</span>}
                  </td>
                </tr>
              ));
            })}</tbody>
          </table>
        </div>
      </div>


      {/* ── INCIDENT REGISTER ── */}
      <IncidentRegisterPanel incidents={incidents} onAddIncident={onAddIncident} onDeleteIncident={onDeleteIncident} userRole={userRole} C={C}/>

      <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fit,minmax(240px,1fr))",gap:14}}>
        <div style={{background:C.card,border:`1px solid ${C.border}`,borderRadius:14,padding:16}}>
          <h3 style={{color:C.text,fontWeight:700,margin:"0 0 12px",fontSize:13}}>Safety Observations</h3>
          <ResponsiveContainer width="100%" height={160}><PieChart><Pie data={obsData} cx="50%" cy="50%" outerRadius={60} dataKey="value" label={({name,value})=>`${name}: ${value}`}>{obsData.map((d,i)=><Cell key={i} fill={d.fill}/>)}</Pie><Tooltip contentStyle={chartTooltip(C)}/></PieChart></ResponsiveContainer>
        </div>
        <div style={{background:C.card,border:`1px solid ${C.border}`,borderRadius:14,padding:16}}>
          <h3 style={{color:C.text,fontWeight:700,margin:"0 0 12px",fontSize:13}}>Safe Man-Hours</h3>
          <ResponsiveContainer width="100%" height={160}><BarChart data={manHours}><CartesianGrid strokeDasharray="3 3" stroke={C.border}/><XAxis dataKey="name" tick={{fill:C.muted,fontSize:11}}/><YAxis tick={{fill:C.muted,fontSize:10}}/><Tooltip contentStyle={chartTooltip(C)} formatter={v=>v.toLocaleString()}/><Bar dataKey="value" fill={C.teal} radius={[4,4,0,0]}/></BarChart></ResponsiveContainer>
        </div>
        <div style={{background:C.card,border:`1px solid ${C.border}`,borderRadius:14,padding:16}}>
          <h3 style={{color:C.text,fontWeight:700,margin:"0 0 12px",fontSize:13}}>Key Stats</h3>
          {[["Manpower",weeklyData.rows.find(r=>r.no===24)?.value||"—",C.purple],["Man-hours/Week",weeklyData.rows.find(r=>r.no===25)?.value||"—",C.teal],["Project Man-hours",weeklyData.rows.find(r=>r.no===28)?.value||"—",C.green],["Safety Officers",weeklyData.rows.find(r=>r.no===31)?.value||"—",C.blue],["First Aiders",weeklyData.rows.find(r=>r.no===34)?.value||"—",C.orange],["TBT Attendees",weeklyData.rows.find(r=>r.no===23)?.value?.match(/\d[\d,]*/)?.[0]||"—",C.indigo]].map(([l,v,c])=>(
            <div key={l} style={{display:"flex",justifyContent:"space-between",padding:"5px 0",borderBottom:`1px solid ${C.border}33`}}><span style={{color:C.muted,fontSize:11}}>{l}</span><span style={{color:c,fontWeight:700,fontSize:12}}>{v}</span></div>
          ))}
        </div>
      </div>
    </div>
  );
};

// ── MONTHLY ───────────────────────────────────────────────────────────────────
const Monthly = ({obs,ncr,monthlyState,setMonthlyState,C}) => {
  const {trend,summary,kpiItems,kpiTable,pciItems,pciTable} = monthlyState;
  const [editMode,setEditMode]=useState(false);
  const [activeTab,setActiveTab]=useState("trend");
  const [saving,setSaving]=useState(false);
  const [newKpiItem,setNewKpiItem]=useState("");
  const [newPciItem,setNewPciItem]=useState("");

  // Draft states
  const [trendDraft,setTrendDraft]=useState(trend);
  const [summaryDraft,setSummaryDraft]=useState(summary);
  const [kpiDraft,setKpiDraft]=useState(kpiTable);
  const [pciDraft,setPciDraft]=useState(pciTable);
  const [kpiItemsDraft,setKpiItemsDraft]=useState(kpiItems);
  const [pciItemsDraft,setPciItemsDraft]=useState(pciItems);

  // ── FIX: sync drafts when Firestore data loads in after mount ──────────────
  useEffect(()=>{
    if(!editMode){
      setTrendDraft(JSON.parse(JSON.stringify(trend)));
      setSummaryDraft({...summary});
      setKpiDraft(JSON.parse(JSON.stringify(kpiTable)));
      setPciDraft(JSON.parse(JSON.stringify(pciTable)));
      setKpiItemsDraft([...kpiItems]);
      setPciItemsDraft([...pciItems]);
    }
  },[trend,summary,kpiTable,pciTable,kpiItems,pciItems,editMode]);

  const startEdit=()=>{
    setTrendDraft(JSON.parse(JSON.stringify(trend)));
    setSummaryDraft({...summary});
    setKpiDraft(JSON.parse(JSON.stringify(kpiTable)));
    setPciDraft(JSON.parse(JSON.stringify(pciTable)));
    setKpiItemsDraft([...kpiItems]);
    setPciItemsDraft([...pciItems]);
    setEditMode(true);
  };
  const saveEdit=async()=>{
    setSaving(true);
    const newState={trend:trendDraft,summary:summaryDraft,kpiItems:kpiItemsDraft,kpiTable:kpiDraft,pciItems:pciItemsDraft,pciTable:pciDraft};
    setMonthlyState(newState);
    await saveSettings({monthlyState:newState});
    setSaving(false);setEditMode(false);
  };
  const cancelEdit=()=>setEditMode(false);

  const updateKpi=(item,month,val)=>setKpiDraft(p=>({...p,[item]:{...(p[item]||buildEmptyMonthRow()),[month]:val}}));
  const updatePci=(item,month,val)=>setPciDraft(p=>({...p,[item]:{...(p[item]||buildEmptyMonthRow()),[month]:val}}));
  const updateTrend=(i,k,v)=>setTrendDraft(p=>p.map((r,j)=>j===i?{...r,[k]:Number(v)}:r));

  const addKpiItem=()=>{
    const name=newKpiItem.trim();if(!name||kpiItemsDraft.includes(name))return;
    setKpiItemsDraft(p=>[...p,name]);
    setKpiDraft(p=>({...p,[name]:buildEmptyMonthRow()}));
    setNewKpiItem("");
  };
  const deleteKpiItem=(item)=>{
    setKpiItemsDraft(p=>p.filter(x=>x!==item));
    setKpiDraft(p=>{const n={...p};delete n[item];return n;});
  };
  const addPciItem=()=>{
    const name=newPciItem.trim();if(!name||pciItemsDraft.includes(name))return;
    setPciItemsDraft(p=>[...p,name]);
    setPciDraft(p=>({...p,[name]:buildEmptyMonthRow()}));
    setNewPciItem("");
  };
  const deletePciItem=(item)=>{
    setPciItemsDraft(p=>p.filter(x=>x!==item));
    setPciDraft(p=>{const n={...p};delete n[item];return n;});
  };

  const kpiChartData=MONTHS.map(m=>({month:m,...Object.fromEntries(kpiItems.map(k=>[k,parseFloat(kpiTable[k]?.[m])||0]))}));
  const pciChartData=MONTHS.map(m=>({month:m,...Object.fromEntries(pciItems.map(k=>[k,parseFloat(pciTable[k]?.[m])||0]))}));
  const miniInpStyle={width:52,background:C.bg,border:`1px solid ${C.border}`,borderRadius:6,padding:"4px 6px",color:C.text,fontSize:12,outline:"none",textAlign:"center",boxSizing:"border-box"};
  const delBtnStyle={background:C.red+"22",border:`1px solid ${C.red}44`,color:C.red,borderRadius:5,padding:"2px 6px",cursor:"pointer",fontSize:10,fontWeight:700,display:"flex",alignItems:"center",gap:2,whiteSpace:"nowrap"};
  const tabs=[{id:"trend",label:"📈 Trend"},{id:"kpi",label:"📊 Monthly KPI"},{id:"pci",label:"📋 Monthly PCI"}];

  return(
    <div style={{display:"flex",flexDirection:"column",gap:18}}>
      <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",flexWrap:"wrap",gap:8}}>
        <div style={{display:"flex",gap:4,flexWrap:"wrap"}}>
          {tabs.map(t=>(
            <button key={t.id} onClick={()=>setActiveTab(t.id)}
              style={{background:activeTab===t.id?C.teal+"33":"transparent",color:activeTab===t.id?C.teal:C.muted,border:`1px solid ${activeTab===t.id?C.teal+"44":C.border}`,borderRadius:8,padding:"6px 14px",fontWeight:activeTab===t.id?700:400,fontSize:13,cursor:"pointer"}}>
              {t.label}
            </button>
          ))}
        </div>
        <div style={{display:"flex",gap:8,alignItems:"center"}}>
          <SavingBadge saving={saving} C={C}/>
          {editMode
            ?<><Btn onClick={saveEdit} color={C.green}><Save size={14}/>Save</Btn><Btn onClick={cancelEdit} color={C.muted} style={{background:C.border}}>Cancel</Btn></>
            :<Btn onClick={startEdit} color={C.blue}><Edit2 size={14}/>Edit Data</Btn>}
        </div>
      </div>

      {activeTab==="trend"&&(
        <>
          {editMode&&(
            <div style={{background:C.card,border:`1px solid ${C.blue}44`,borderRadius:14,padding:20}}>
              <h3 style={{color:C.text,fontWeight:700,margin:"0 0 14px",fontSize:14}}>✏️ Edit 6-Month Trend</h3>
              <div style={{overflowX:"auto"}}>
                <table style={{width:"100%",borderCollapse:"collapse"}}>
                  <thead><tr>{["Month","Incidents","Near Miss","Observations","NCR Open","Welfare"].map(h=><Th key={h} C={C}>{h}</Th>)}</tr></thead>
                  <tbody>{trendDraft.map((row,i)=>(
                    <tr key={row.month}><Td C={C} style={{color:C.text,fontWeight:600}}>{row.month}</Td>
                    {["incidents","nearMiss","observations","ncrOpen","welfare"].map(k=>(
                      <Td key={k} C={C}><input type="number" value={row[k]} onChange={e=>updateTrend(i,k,e.target.value)} style={{...miniInpStyle,width:70}}/></Td>
                    ))}</tr>
                  ))}</tbody>
                </table>
              </div>
              <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:12,marginTop:14}}>
                <Field label="Welfare Score (this month)" C={C}><Inp C={C} value={summaryDraft.welfare} onChange={e=>setSummaryDraft(p=>({...p,welfare:e.target.value}))}/></Field>
                <Field label="Training Compliance (this month)" C={C}><Inp C={C} value={summaryDraft.training} onChange={e=>setSummaryDraft(p=>({...p,training:e.target.value}))}/></Field>
              </div>
            </div>
          )}
          <div style={{background:C.card,border:`1px solid ${C.border}`,borderRadius:14,padding:18}}>
            <h3 style={{color:C.text,fontWeight:700,margin:"0 0 14px"}}>6-Month HSSE Trend</h3>
            <ResponsiveContainer width="100%" height={250}><LineChart data={trend}><CartesianGrid strokeDasharray="3 3" stroke={C.border}/><XAxis dataKey="month" tick={{fill:C.muted}}/><YAxis tick={{fill:C.muted}}/><Tooltip contentStyle={chartTooltip(C)}/><Legend/><Line type="monotone" dataKey="observations" stroke={C.teal} strokeWidth={2} dot={{r:3}}/><Line type="monotone" dataKey="nearMiss" stroke={C.yellow} strokeWidth={2} dot={{r:3}}/><Line type="monotone" dataKey="incidents" stroke={C.red} strokeWidth={2} dot={{r:3}}/><Line type="monotone" dataKey="welfare" stroke={C.purple} strokeWidth={2} dot={{r:3}}/></LineChart></ResponsiveContainer>
          </div>
          <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fit,minmax(280px,1fr))",gap:16}}>
            <div style={{background:C.card,border:`1px solid ${C.border}`,borderRadius:14,padding:18}}>
              <h3 style={{color:C.text,fontWeight:700,margin:"0 0 14px"}}>NCR Trend</h3>
              <ResponsiveContainer width="100%" height={200}><BarChart data={trend}><CartesianGrid strokeDasharray="3 3" stroke={C.border}/><XAxis dataKey="month" tick={{fill:C.muted}}/><YAxis tick={{fill:C.muted}}/><Tooltip contentStyle={chartTooltip(C)}/><Bar dataKey="ncrOpen" name="Open NCRs" fill={C.orange} radius={[4,4,0,0]}/></BarChart></ResponsiveContainer>
            </div>
            <div style={{background:C.card,border:`1px solid ${C.border}`,borderRadius:14,padding:18}}>
              <h3 style={{color:C.text,fontWeight:700,margin:"0 0 4px",fontSize:14}}>Monthly Summary</h3>
              <p style={{color:C.muted,fontSize:11,margin:"0 0 14px"}}>Auto-generated + manual</p>
              {[["Total Observations",obs.length,C.teal],["Near Misses",obs.filter(o=>o.type==="Near Miss").length,C.yellow],["NCRs Raised",ncr.length,C.orange],["NCRs Overdue",ncr.filter(n=>n.status==="Overdue").length,C.red],["Welfare Score",summary.welfare,C.purple],["Training Compliance",summary.training,C.blue]].map(([l,v,c])=>(
                <div key={l} style={{display:"flex",justifyContent:"space-between",padding:"7px 0",borderBottom:`1px solid ${C.border}44`}}><span style={{color:C.sub,fontSize:13}}>{l}</span><span style={{color:c,fontWeight:700,fontSize:13}}>{v}</span></div>
              ))}
            </div>
          </div>
        </>
      )}

      {activeTab==="kpi"&&(
        <div style={{display:"flex",flexDirection:"column",gap:16}}>
          <div style={{background:C.teal+"22",border:`1px solid ${C.teal}44`,borderRadius:10,padding:12,fontSize:13,color:C.teal}}>
            📊 Enter monthly KPI values as percentages (%) for each month. Use <strong>Edit Data</strong> to update, add, or delete rows.
          </div>
          {editMode&&(
            <div style={{background:C.card,border:`1px solid ${C.blue}44`,borderRadius:14,padding:20}}>
              <h3 style={{color:C.text,fontWeight:700,margin:"0 0 14px",fontSize:14}}>✏️ Edit Monthly KPI (%)</h3>
              <div style={{overflowX:"auto"}}>
                <table style={{width:"100%",borderCollapse:"collapse",minWidth:900}}>
                  <thead><tr><Th C={C} style={{minWidth:180}}>KPI Indicator</Th>{MONTHS.map(m=><Th key={m} C={C}>{m}</Th>)}</tr></thead>
                  <tbody>{kpiItemsDraft.map(item=>(
                    <tr key={item} onMouseEnter={e=>e.currentTarget.style.background=C.border+"33"} onMouseLeave={e=>e.currentTarget.style.background="transparent"}>
                      <Td C={C} style={{color:C.text,fontWeight:600,whiteSpace:"nowrap"}}>
                        <div style={{display:"flex",alignItems:"center",gap:8}}>
                          <button onClick={()=>deleteKpiItem(item)} style={delBtnStyle}><Trash2 size={10}/>Del</button>{item}
                        </div>
                      </Td>
                      {MONTHS.map(m=><Td key={m} C={C}><input type="number" min={0} max={100} placeholder="%" value={kpiDraft[item]?.[m]||""} onChange={e=>updateKpi(item,m,e.target.value)} style={miniInpStyle}/></Td>)}
                    </tr>
                  ))}</tbody>
                </table>
              </div>
              <div style={{display:"flex",gap:8,marginTop:14,alignItems:"center",flexWrap:"wrap"}}>
                <input placeholder="New KPI indicator name…" value={newKpiItem} onChange={e=>setNewKpiItem(e.target.value)} onKeyDown={e=>e.key==="Enter"&&addKpiItem()}
                  style={{flex:1,minWidth:200,background:C.bg,border:`1px solid ${C.teal}`,borderRadius:8,padding:"7px 12px",color:C.text,fontSize:13,outline:"none"}}/>
                <Btn onClick={addKpiItem} color={C.teal}><Plus size={13}/>Add Row</Btn>
              </div>
            </div>
          )}
          <div style={{background:C.card,border:`1px solid ${C.border}`,borderRadius:14,overflow:"hidden"}}>
            <div style={{padding:"14px 18px",borderBottom:`1px solid ${C.border}`,display:"flex",justifyContent:"space-between",alignItems:"center"}}>
              <span style={{color:C.text,fontWeight:700,fontSize:14}}>Monthly KPI Summary (%)</span>
              <span style={{color:C.muted,fontSize:12}}>{kpiItems.length} indicators</span>
            </div>
            <div style={{overflowX:"auto"}}>
              <table style={{width:"100%",borderCollapse:"collapse",minWidth:900}}>
                <thead><tr><Th C={C} style={{minWidth:180}}>KPI Indicator</Th>{MONTHS.map(m=><Th key={m} C={C}>{m}</Th>)}</tr></thead>
                <tbody>{kpiItems.map((item,ii)=>(
                  <tr key={item} onMouseEnter={e=>e.currentTarget.style.background=C.border+"33"} onMouseLeave={e=>e.currentTarget.style.background="transparent"}>
                    <Td C={C} style={{color:KPI_COLORS_PALETTE[ii%KPI_COLORS_PALETTE.length],fontWeight:700,whiteSpace:"nowrap"}}>{item}</Td>
                    {MONTHS.map(m=>{const v=kpiTable[item]?.[m];const n=parseFloat(v);return(
                      <Td key={m} C={C} style={{textAlign:"center"}}>
                        {v?(<div><div style={{fontWeight:700,color:n>=80?C.green:n>=60?C.yellow:C.red,fontSize:13}}>{v}%</div><div style={{height:3,borderRadius:99,background:C.border,marginTop:3}}><div style={{width:`${Math.min(n,100)}%`,background:n>=80?C.green:n>=60?C.yellow:C.red,height:3,borderRadius:99}}/></div></div>):<span style={{color:C.muted,fontSize:11}}>—</span>}
                      </Td>
                    );})}
                  </tr>
                ))}</tbody>
              </table>
            </div>
          </div>
          <div style={{background:C.card,border:`1px solid ${C.border}`,borderRadius:14,padding:18}}>
            <h3 style={{color:C.text,fontWeight:700,margin:"0 0 14px"}}>KPI Trend Chart (%)</h3>
            <ResponsiveContainer width="100%" height={280}>
              <LineChart data={kpiChartData}><CartesianGrid strokeDasharray="3 3" stroke={C.border}/><XAxis dataKey="month" tick={{fill:C.muted}}/><YAxis domain={[0,100]} tick={{fill:C.muted}} unit="%"/><Tooltip contentStyle={chartTooltip(C)} formatter={v=>`${v}%`}/><Legend/>
                {kpiItems.map((k,i)=><Line key={k} type="monotone" dataKey={k} stroke={KPI_COLORS_PALETTE[i%KPI_COLORS_PALETTE.length]} strokeWidth={2} dot={{r:3}}/>)}
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>
      )}

      {activeTab==="pci"&&(
        <div style={{display:"flex",flexDirection:"column",gap:16}}>
          <div style={{background:C.purple+"22",border:`1px solid ${C.purple}44`,borderRadius:10,padding:12,fontSize:13,color:C.purple}}>
            📋 Enter monthly PCI (Project Compliance Index) values as percentages (%) for each month. Use <strong>Edit Data</strong> to update, add, or delete rows.
          </div>
          {editMode&&(
            <div style={{background:C.card,border:`1px solid ${C.purple}44`,borderRadius:14,padding:20}}>
              <h3 style={{color:C.text,fontWeight:700,margin:"0 0 14px",fontSize:14}}>✏️ Edit Monthly PCI (%)</h3>
              <div style={{overflowX:"auto"}}>
                <table style={{width:"100%",borderCollapse:"collapse",minWidth:900}}>
                  <thead><tr><Th C={C} style={{minWidth:180}}>PCI Indicator</Th>{MONTHS.map(m=><Th key={m} C={C}>{m}</Th>)}</tr></thead>
                  <tbody>{pciItemsDraft.map(item=>(
                    <tr key={item} onMouseEnter={e=>e.currentTarget.style.background=C.border+"33"} onMouseLeave={e=>e.currentTarget.style.background="transparent"}>
                      <Td C={C} style={{color:C.text,fontWeight:600,whiteSpace:"nowrap"}}>
                        <div style={{display:"flex",alignItems:"center",gap:8}}>
                          <button onClick={()=>deletePciItem(item)} style={delBtnStyle}><Trash2 size={10}/>Del</button>{item}
                        </div>
                      </Td>
                      {MONTHS.map(m=><Td key={m} C={C}><input type="number" min={0} max={100} placeholder="%" value={pciDraft[item]?.[m]||""} onChange={e=>updatePci(item,m,e.target.value)} style={miniInpStyle}/></Td>)}
                    </tr>
                  ))}</tbody>
                </table>
              </div>
              <div style={{display:"flex",gap:8,marginTop:14,alignItems:"center",flexWrap:"wrap"}}>
                <input placeholder="New PCI indicator name…" value={newPciItem} onChange={e=>setNewPciItem(e.target.value)} onKeyDown={e=>e.key==="Enter"&&addPciItem()}
                  style={{flex:1,minWidth:200,background:C.bg,border:`1px solid ${C.purple}`,borderRadius:8,padding:"7px 12px",color:C.text,fontSize:13,outline:"none"}}/>
                <Btn onClick={addPciItem} color={C.purple}><Plus size={13}/>Add Row</Btn>
              </div>
            </div>
          )}
          <div style={{background:C.card,border:`1px solid ${C.border}`,borderRadius:14,overflow:"hidden"}}>
            <div style={{padding:"14px 18px",borderBottom:`1px solid ${C.border}`,display:"flex",justifyContent:"space-between",alignItems:"center"}}>
              <span style={{color:C.text,fontWeight:700,fontSize:14}}>Monthly PCI Summary (%)</span>
              <span style={{color:C.muted,fontSize:12}}>{pciItems.length} indicators</span>
            </div>
            <div style={{overflowX:"auto"}}>
              <table style={{width:"100%",borderCollapse:"collapse",minWidth:900}}>
                <thead><tr><Th C={C} style={{minWidth:180}}>PCI Indicator</Th>{MONTHS.map(m=><Th key={m} C={C}>{m}</Th>)}</tr></thead>
                <tbody>{pciItems.map((item,ii)=>(
                  <tr key={item} onMouseEnter={e=>e.currentTarget.style.background=C.border+"33"} onMouseLeave={e=>e.currentTarget.style.background="transparent"}>
                    <Td C={C} style={{color:KPI_COLORS_PALETTE[ii%KPI_COLORS_PALETTE.length],fontWeight:700,whiteSpace:"nowrap"}}>{item}</Td>
                    {MONTHS.map(m=>{const v=pciTable[item]?.[m];const n=parseFloat(v);return(
                      <Td key={m} C={C} style={{textAlign:"center"}}>
                        {v?(<div><div style={{fontWeight:700,color:n>=80?C.green:n>=60?C.yellow:C.red,fontSize:13}}>{v}%</div><div style={{height:3,borderRadius:99,background:C.border,marginTop:3}}><div style={{width:`${Math.min(n,100)}%`,background:n>=80?C.green:n>=60?C.yellow:C.red,height:3,borderRadius:99}}/></div></div>):<span style={{color:C.muted,fontSize:11}}>—</span>}
                      </Td>
                    );})}
                  </tr>
                ))}</tbody>
              </table>
            </div>
          </div>
          <div style={{background:C.card,border:`1px solid ${C.border}`,borderRadius:14,padding:18}}>
            <h3 style={{color:C.text,fontWeight:700,margin:"0 0 14px"}}>PCI Trend Chart (%)</h3>
            <ResponsiveContainer width="100%" height={280}>
              <LineChart data={pciChartData}><CartesianGrid strokeDasharray="3 3" stroke={C.border}/><XAxis dataKey="month" tick={{fill:C.muted}}/><YAxis domain={[0,100]} tick={{fill:C.muted}} unit="%"/><Tooltip contentStyle={chartTooltip(C)} formatter={v=>`${v}%`}/><Legend/>
                {pciItems.map((k,i)=><Line key={k} type="monotone" dataKey={k} stroke={KPI_COLORS_PALETTE[i%KPI_COLORS_PALETTE.length]} strokeWidth={2} dot={{r:3}}/>)}
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>
      )}
    </div>
  );
};

// ── WELFARE ───────────────────────────────────────────────────────────────────
const Welfare = ({welfareItems,setWelfareItems,C}) => {
  const [editMode,setEditMode]=useState(false);
  const [draft,setDraft]=useState(welfareItems);
  const [saving,setSaving]=useState(false);
  // FIX: sync draft when Firestore data loads in after mount
  useEffect(()=>{ if(!editMode) setDraft(welfareItems); },[welfareItems, editMode]);
  const statusOptions=["Excellent","Good","Needs Attention","Critical"];
  const save=async()=>{
    setSaving(true);setWelfareItems(draft);
    await saveSettings({welfareItems:draft});
    setSaving(false);setEditMode(false);
  };
  return(
    <div style={{display:"flex",flexDirection:"column",gap:18}}>
      <div style={{background:C.card,border:`1px solid ${C.border}`,borderRadius:14,padding:20}}>
        <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:18,flexWrap:"wrap",gap:8}}>
          <h3 style={{color:C.text,fontWeight:700,margin:0}}>Welfare Facility Scores</h3>
          <div style={{display:"flex",gap:8,alignItems:"center"}}>
            <SavingBadge saving={saving} C={C}/>
            {editMode?<><Btn onClick={save} color={C.green}><Save size={14}/>Save</Btn><Btn onClick={()=>{setDraft(welfareItems);setEditMode(false);}} color={C.muted} style={{background:C.border}}>Cancel</Btn></>:
              <Btn onClick={()=>{setDraft(welfareItems);setEditMode(true);}} color={C.blue}><Edit2 size={14}/>Edit Scores</Btn>}
          </div>
        </div>
        {editMode?(
          <div style={{display:"flex",flexDirection:"column",gap:12}}>
            {draft.map((w,i)=>(
              <div key={w.category} style={{background:C.bg,borderRadius:10,padding:14,display:"grid",gridTemplateColumns:"1fr 100px 160px",gap:12,alignItems:"center"}}>
                <span style={{color:C.text,fontSize:13,fontWeight:600}}>{w.category}</span>
                <div>
                  <div style={{fontSize:11,color:C.muted,marginBottom:4}}>Score (0-100)</div>
                  <input type="number" min={0} max={100} value={draft[i].score} onChange={e=>setDraft(p=>p.map((x,j)=>j===i?{...x,score:Number(e.target.value)}:x))}
                    style={{width:"100%",background:C.card,border:`1px solid ${C.border}`,borderRadius:6,padding:"6px 10px",color:C.text,fontSize:13,outline:"none",boxSizing:"border-box"}}/>
                </div>
                <div>
                  <div style={{fontSize:11,color:C.muted,marginBottom:4}}>Status</div>
                  <select value={draft[i].status} onChange={e=>setDraft(p=>p.map((x,j)=>j===i?{...x,status:e.target.value}:x))}
                    style={{width:"100%",background:C.card,border:`1px solid ${C.border}`,borderRadius:6,padding:"6px 10px",color:C.text,fontSize:13,outline:"none"}}>
                    {statusOptions.map(s=><option key={s}>{s}</option>)}
                  </select>
                </div>
              </div>
            ))}
          </div>
        ):(
          welfareItems.map(w=>(
            <div key={w.category} style={{display:"flex",alignItems:"center",gap:10,marginBottom:12,flexWrap:"wrap"}}>
              <span style={{color:C.text,fontSize:13,width:150,flexShrink:0}}>{w.category}</span>
              <div style={{flex:1,height:10,borderRadius:99,background:C.border,minWidth:80}}><div style={{width:`${w.score}%`,background:w.score>=90?C.green:w.score>=80?C.teal:w.score>=70?C.yellow:C.red,height:10,borderRadius:99}}/></div>
              <span style={{fontSize:13,fontWeight:700,width:36,textAlign:"right",color:w.score>=80?C.green:C.yellow}}>{w.score}%</span>
              <Badge label={w.status} color={w.score>=90?C.green:w.score>=80?C.teal:w.score>=70?C.yellow:C.red}/>
            </div>
          ))
        )}
      </div>
      <div style={{background:C.card,border:`1px solid ${C.border}`,borderRadius:14,padding:18}}>
        <h3 style={{color:C.text,fontWeight:700,margin:"0 0 14px"}}>Welfare Radar</h3>
        <ResponsiveContainer width="100%" height={260}>
          <RadarChart data={welfareItems.map(w=>({subject:w.category.split(" ")[0],A:w.score}))}>
            <PolarGrid stroke={C.border}/><PolarAngleAxis dataKey="subject" tick={{fill:C.sub,fontSize:11}}/><PolarRadiusAxis domain={[0,100]} tick={{fill:C.muted,fontSize:10}}/>
            <Radar name="Score" dataKey="A" stroke={C.purple} fill={C.purple} fillOpacity={0.3}/>
            <Tooltip contentStyle={chartTooltip(C)}/>
          </RadarChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
};

// ── USER MANAGEMENT ───────────────────────────────────────────────────────────
const UserMgmt = ({firestoreUsers,setFirestoreUsers,userRole,C}) => {
  const [showForm,setShowForm]=useState(false),[editId,setEditId]=useState(null);
  const blank={email:"",name:"",role:"viewer",site:"Site 1",permissions:[...DEFAULT_PERMISSIONS.viewer],mustChangePassword:true};
  const [form,setForm]=useState(blank),[tempPass,setTempPass]=useState(""),[err,setErr]=useState(""),[loading,setLoading]=useState(false);
  const [fixing,setFixing]=useState(false);
  const set=(k,v)=>setForm(p=>({...p,[k]:v}));
  const changeRole=r=>setForm(p=>({...p,role:r,permissions:[...DEFAULT_PERMISSIONS[r]]}));
  // When site changes, auto-set permissions appropriate for that site
  const changeSite=s=>setForm(p=>{
    const base=DEFAULT_PERMISSIONS[p.role]||[];
    // If assigned to a specific site, ensure that site's nav is in permissions
    const sitePerms=s==="All Sites"?base:
      s==="Site 1"?[...new Set([...base,"site1"])]:
      s==="Site 2"?[...new Set([...base,"site2"])]:
      s==="Site 3"?[...new Set([...base,"site3"])]:base;
    return{...p,site:s,permissions:sitePerms};
  });
  const togglePerm=id=>setForm(p=>({...p,permissions:p.permissions.includes(id)?p.permissions.filter(x=>x!==id):[...p.permissions,id]}));
  const openAdd=()=>{setForm(blank);setTempPass("");setEditId(null);setErr("");setShowForm(true);};
  const openEdit=u=>{setForm({...u,permissions:u.permissions||[...DEFAULT_PERMISSIONS[u.role]]});setEditId(u.uid);setErr("");setShowForm(true);};

  // Fix own role — sets current logged-in user to admin in Firestore
  const fixMyRole=async()=>{
    setFixing(true);
    try{
      const currentUser=auth.currentUser;
      if(!currentUser){alert("Not logged in.");return;}
      await setDoc(doc(db,"users",currentUser.uid),{
        role:"admin",
        permissions:[...DEFAULT_PERMISSIONS.admin],
        mustChangePassword:false,
      },{merge:true});
      alert("✅ Your role has been set to Admin. Please refresh the page.");
    }catch(e){alert("❌ Failed: "+e.message);}
    finally{setFixing(false);}
  };

  const resetUserPassword=async(u)=>{
    if(!u.email){setErr("No email address for this user.");return;}
    if(!window.confirm(`Send password reset email to:\n${u.email}\n\nThe user will receive a link to set a new password.`))return;
    try{
      await sendPasswordResetEmail(auth,u.email);
      await updateDoc(doc(db,"users",u.uid),{mustChangePassword:true});
      setFirestoreUsers(p=>p.map(x=>x.uid===u.uid?{...x,mustChangePassword:true}:x));
      alert(`✅ Password reset email sent to ${u.email}`);
    }catch(e){alert("❌ Failed: "+e.message);}
  };

  const deleteUser=async(u)=>{
    // Cannot delete yourself
    if(u.uid===auth.currentUser?.uid){
      alert("You cannot delete your own account.");return;
    }
    if(!window.confirm(`Delete user "${u.name}" (${u.email})?\n\nThis removes their system access permanently.`))return;
    try{
      // Remove Firestore profile — this revokes all access immediately
      await deleteDoc(doc(db,"users",u.uid));
      setFirestoreUsers(p=>p.filter(x=>x.uid!==u.uid));
      // Note: Firebase Auth account remains but without a Firestore profile
      // they will be blocked on next login (auth handler checks for profile)
    }catch(e){alert("❌ Failed to delete user: "+e.message);}
  };
  const submit=async()=>{
    if(!form.name||!form.email.trim()){setErr("Name and email are required.");return;}
    setLoading(true);setErr("");
    try{
      if(editId){
        // ── EDIT existing user ───────────────────────────────────────────────
        await updateDoc(doc(db,"users",editId),{
          name:        form.name,
          role:        form.role,
          site:        form.site,
          permissions: form.permissions,
        });
        setFirestoreUsers(p=>p.map(u=>u.uid===editId?{...u,...form}:u));
        setShowForm(false);
      } else {
        // ── ADD new user via Neon API ─────────────────────────────────────────
        if(!tempPass||tempPass.length<6){
          setErr("Temporary password must be at least 6 characters.");
          setLoading(false); return;
        }
        const avatar = form.name.trim().split(/\s+/).map(w=>w[0]).join("").slice(0,2).toUpperCase();
        const newId  = "user-" + Date.now();
        const profile = {
          ...form,
          id:                  newId,
          uid:                 newId,
          avatar,
          password:            tempPass,
          mustChangePassword:  true,
          must_change_password:true,
          permissions:         form.permissions||[...DEFAULT_PERMISSIONS[form.role]],
        };
        await addDoc(collection(db,"users"), profile);
        setFirestoreUsers(p=>p.some(u=>u.uid===newId)
          ? p.map(u=>u.uid===newId?profile:u)
          : [...p, profile]);
        setShowForm(false);
        setTempPass("");
      }
    }catch(e){
      setErr("Unexpected error: "+e.message);
      console.error("[HSSE] submit error:",e);
    }finally{setLoading(false);}
  };
  const assignable=NAV.filter(n=>form.role==="admin"||!n.adminOnly);
  return(
    <div style={{display:"flex",flexDirection:"column",gap:18}}>

      {/* Role warning — shown when current user is not admin */}
      {userRole!=="admin"&&(
        <div style={{background:C.orange+"22",border:`1px solid ${C.orange}44`,borderRadius:12,padding:16}}>
          <div style={{color:C.orange,fontWeight:700,fontSize:14,marginBottom:6}}>⚠️ Your account does not have Admin access</div>
          <div style={{color:C.sub,fontSize:12,marginBottom:12,lineHeight:1.7}}>
            You can see this page but cannot add or edit users. Your current role is <strong style={{color:C.text}}>{userRole||"unknown"}</strong>.
            If you are the system administrator, click below to upgrade your role to Admin.
          </div>
          <Btn onClick={fixMyRole} color={C.orange} disabled={fixing}>
            {fixing?"Fixing...":"🔧 Set My Role to Admin"}
          </Btn>
          <div style={{color:C.muted,fontSize:11,marginTop:8}}>After clicking, refresh the page. This button is only needed once.</div>
        </div>
      )}

      <PillGrid minWidth={130}>
        {[["Total",firestoreUsers.length,C.blue],["Admins",firestoreUsers.filter(u=>u.role==="admin").length,C.red],["Editors",firestoreUsers.filter(u=>u.role==="editor").length,C.orange],["Viewers",firestoreUsers.filter(u=>u.role==="viewer").length,C.teal]].map(([l,v,c])=>(
          <StatPill key={l} label={l} value={v} color={c} C={C}/>
        ))}
      </PillGrid>
      <div style={{display:"flex",justifyContent:"flex-end",gap:8,alignItems:"center"}}>
        <span style={{color:C.muted,fontSize:11}}>Role: <strong style={{color:userRole==="admin"?C.green:C.orange}}>{userRole||"unknown"}</strong></span>
        {userRole==="admin"&&<Btn onClick={openAdd} color={C.blue}><Plus size={14}/>Add User</Btn>}
      </div>
      {showForm&&(
        <Modal title={editId?"Edit User":"Add New User"} onClose={()=>setShowForm(false)} C={C}>
          <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:12}}>
            <Field label="Full Name" C={C}><Inp C={C} placeholder="Full name" value={form.name} onChange={e=>set("name",e.target.value)}/></Field>
            {!editId&&<Field label="Email Address" C={C}><Inp C={C} type="email" placeholder="user@company.com" value={form.email} onChange={e=>set("email",e.target.value)}/></Field>}
            {!editId&&<Field label="Temporary Password" C={C}><Inp C={C} type="password" placeholder="Min 6 characters — user must change on first login" value={tempPass} onChange={e=>setTempPass(e.target.value)}/></Field>}
            <Field label="Role" C={C}>
              <Sel C={C} value={form.role} onChange={e=>changeRole(e.target.value)}>
                <option value="admin">Administrator (Full Access)</option>
                <option value="editor">Editor (Add + Edit, No Delete)</option>
                <option value="viewer">Viewer (Read Only)</option>
              </Sel>
            </Field>
            <Field label="Assigned Site" C={C}><Sel C={C} value={form.site} onChange={e=>changeSite(e.target.value)}>{["All Sites",...SITE_IDS].map(s=><option key={s} value={s}>{s==="All Sites"?s:siteName(s)}</option>)}</Sel></Field>
          </div>
          <div style={{marginTop:8}}>
            <div style={{fontSize:12,color:C.sub,fontWeight:700,marginBottom:6}}>📋 Additional Section Permissions</div>
          <div style={{fontSize:11,color:C.muted,marginBottom:10,lineHeight:1.6}}>
            The assigned site automatically grants access to that site's full dashboard. Add extra permissions below if needed.
          </div>
            <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:6}}>
              {assignable.map(n=>{const checked=form.permissions.includes(n.id),locked=form.role==="admin";return(
                <label key={n.id} style={{display:"flex",alignItems:"center",gap:8,background:checked?n.color+"15":C.bg,border:`1px solid ${checked?n.color+"44":C.border}`,borderRadius:8,padding:"7px 10px",cursor:locked?"not-allowed":"pointer",opacity:locked?0.6:1}}>
                  <input type="checkbox" checked={checked||locked} disabled={locked} onChange={()=>togglePerm(n.id)} style={{accentColor:n.color,width:14,height:14}}/>
                  <n.icon size={13} style={{color:checked||locked?n.color:C.muted,flexShrink:0}}/>
                  <span style={{fontSize:12,color:checked||locked?C.text:C.muted,fontWeight:checked||locked?600:400}}>{n.label}</span>
                </label>
              );})}
            </div>
          </div>
          {!editId&&<div style={{background:C.orange+"22",border:`1px solid ${C.orange}44`,borderRadius:8,padding:10,marginTop:10,fontSize:12,color:C.orange}}>⚠️ The user must change this password on their first login. Share the temporary password with them securely.</div>}
          {err&&<div style={{color:C.red,fontSize:12,marginTop:8,background:C.red+"11",padding:"8px 12px",borderRadius:8}}>{err}</div>}
          <div style={{display:"flex",gap:8,marginTop:14}}>
            <Btn onClick={submit} color={C.blue} disabled={loading} style={{flex:1,justifyContent:"center"}}>{loading?"Saving...":(editId?"Save Changes":"Create User")}</Btn>

          </div>
        </Modal>
      )}
      <TableCard title="User Accounts" C={C}>
        <table style={{width:"100%",borderCollapse:"collapse"}}>
          <thead><tr>{["","Name","Email","Role","Site","Status","Actions"].map(h=><Th key={h} C={C}>{h}</Th>)}</tr></thead>
          <tbody>{firestoreUsers.map(u=>{const rm=ROLE_META[u.role]||ROLE_META.viewer;return(
            <tr key={u.uid} onMouseEnter={e=>e.currentTarget.style.background=C.border+"33"} onMouseLeave={e=>e.currentTarget.style.background="transparent"}>
              <Td C={C}><div style={{background:rm.color+"33",width:30,height:30,borderRadius:"50%",display:"flex",alignItems:"center",justifyContent:"center",fontSize:10,fontWeight:700,color:rm.color}}>{u.avatar||"??"}</div></Td>
              <Td C={C} style={{color:C.text,fontWeight:600}}>{u.name}</Td>
              <Td C={C} style={{fontSize:12,color:C.teal}}>{u.email}</Td>
              <Td C={C}><Badge label={rm.label} color={rm.color}/></Td>
              <Td C={C}>
                <div style={{display:"flex",flexDirection:"column",gap:2}}>
                  <span style={{fontSize:12,color:C.text,fontWeight:600}}>{u.site==="All Sites"?u.site:siteName(u.site)||u.site}</span>
                  {u.site!=="All Sites"&&<span style={{fontSize:9,color:C.muted}}>{u.site}</span>}
                </div>
              </Td>
              <Td C={C}>{u.mustChangePassword?<Badge label="Must Change PW" color={C.orange}/>:<Badge label="Active" color={C.green}/>}</Td>
              <Td C={C}>
                {userRole==="admin"&&(
                  <div style={{display:"flex",gap:6,flexWrap:"wrap"}}>
                    <button onClick={()=>openEdit(u)}
                      style={{background:C.blue+"22",border:`1px solid ${C.blue}44`,color:C.blue,borderRadius:6,padding:"4px 8px",cursor:"pointer",fontSize:11,fontWeight:600,display:"flex",alignItems:"center",gap:3}}>
                      <Edit2 size={11}/>Edit
                    </button>
                    <button onClick={()=>resetUserPassword(u)}
                      title={`Send password reset email to ${u.email}`}
                      style={{background:C.orange+"22",border:`1px solid ${C.orange}44`,color:C.orange,borderRadius:6,padding:"4px 8px",cursor:"pointer",fontSize:11,fontWeight:600,display:"flex",alignItems:"center",gap:3}}>
                      <Key size={11}/>Reset PW
                    </button>
                    {u.uid!==auth.currentUser?.uid&&(
                      <button onClick={()=>deleteUser(u)}
                        title={`Remove ${u.name} from the system`}
                        style={{background:C.red+"22",border:`1px solid ${C.red}44`,color:C.red,borderRadius:6,padding:"4px 8px",cursor:"pointer",fontSize:11,fontWeight:600,display:"flex",alignItems:"center",gap:3}}>
                        <Trash2 size={11}/>Delete
                      </button>
                    )}
                  </div>
                )}
                {userRole!=="admin"&&<span style={{color:C.muted,fontSize:11}}>—</span>}
              </Td>
            </tr>
          );})}
          </tbody>
        </table>
      </TableCard>
    </div>
  );
};

// ── DROPDOWN SETTINGS ─────────────────────────────────────────────────────────
const DropdownSettings = ({
  zones,setZones,obsTypes,setObsTypes,actionsList,setActionsList,
  obsSeverity,setObsSeverity,
  ncrCats,setNcrCats,ncrSeverity,setNcrSeverity,ncrStatus,setNcrStatus,
  riskCats,setRiskCats,riskStatus,setRiskStatus,
  equipStatus,setEquipStatus,mpStatus,setMpStatus,
  ltiResetDate,setLtiResetDate,
  C
}) => {
  const [vals,setVals]=useState({nz:"",no:"",na:"",nos:"",nc:"",nsev:"",nst:"",rc:"",rst:"",es:"",ms:""});
  const v=(k)=>vals[k];
  const sv=(k,val)=>setVals(p=>({...p,[k]:val}));

  // Save a single list to Firestore
  const save=async(key,list)=>{await saveSettings({[key]:list});};

  // Bulk-aware list editor.
  //  • Type one item and press Enter → adds that item.
  //  • Paste multi-line text (one item per line) and press Enter or click Add
  //    → parses every line, trims whitespace, skips blanks, removes
  //      case-insensitive duplicates (against existing items AND within the
  //      pasted set), then merges and sorts alphabetically A–Z.
  //  • Shift+Enter inserts a newline so you can keep typing more items.
  const ListEditor=({title,color,items,setItems,firestoreKey,valKey,placeholder})=>{
    // Normalise + dedupe + sort a candidate list, preserving the first-seen
    // casing for any pair that collides only in case.
    const mergeAndSort=(existing, incoming)=>{
      const seen=new Map(); // lowercased → original casing
      [...existing, ...incoming].forEach(raw=>{
        const s=String(raw||"").trim();
        if(!s) return;
        const key=s.toLowerCase();
        if(!seen.has(key)) seen.set(key, s);
      });
      return Array.from(seen.values()).sort((a,b)=>a.localeCompare(b,undefined,{sensitivity:"base"}));
    };

    const add=()=>{
      const raw=v(valKey);
      if(!raw||!raw.trim()) return;
      // Split on newlines, commas, or semicolons so common paste styles Just Work.
      const parts=raw.split(/[\r\n,;]+/);
      const updated=mergeAndSort(items, parts);
      if(updated.length===items.length) { sv(valKey,""); return; } // nothing new
      setItems(updated);
      save(firestoreKey,updated);
      sv(valKey,"");
    };
    const remove=(item)=>{
      const updated=items.filter(x=>x!==item);
      setItems(updated);
      save(firestoreKey,updated);
    };
    const sortNow=()=>{
      const updated=mergeAndSort(items, []);
      if(JSON.stringify(updated)===JSON.stringify(items)) return;
      setItems(updated);
      save(firestoreKey,updated);
    };

    // Detect whether the current input is a multi-line paste so we can show
    // a "N items to add" preview in the button.
    const rawVal=v(valKey)||"";
    const pendingCount=rawVal.trim()
      ? rawVal.split(/[\r\n,;]+/).map(s=>s.trim()).filter(Boolean).length
      : 0;

    return(
      <div style={{background:C.card,border:`1px solid ${C.border}`,borderRadius:14,padding:18}}>
        <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:12,gap:8,flexWrap:"wrap"}}>
          <div style={{color:C.text,fontWeight:700,fontSize:13}}>{title}</div>
          {items.length>1&&(
            <button onClick={sortNow} title="Re-sort alphabetically A–Z"
              style={{background:"none",border:`1px solid ${C.border}`,borderRadius:6,padding:"3px 8px",color:C.muted,fontSize:10,cursor:"pointer"}}>
              ↕ Sort A–Z
            </button>
          )}
        </div>
        <div style={{display:"flex",gap:8,marginBottom:6,alignItems:"flex-start"}}>
          <textarea value={rawVal}
            onChange={e=>sv(valKey,e.target.value)}
            onKeyDown={e=>{
              if(e.key==="Enter" && !e.shiftKey){ e.preventDefault(); add(); }
            }}
            rows={2}
            placeholder={placeholder||"Add one item, or paste a list (one item per line)…"}
            style={{flex:1,background:C.bg,border:`1px solid ${C.border}`,borderRadius:8,padding:"7px 12px",color:C.text,fontSize:13,outline:"none",fontFamily:"inherit",resize:"vertical",minHeight:36}}/>
          <Btn onClick={add} color={color} disabled={pendingCount===0}>
            <Plus size={13}/>{pendingCount>1?`Add ${pendingCount}`:"Add"}
          </Btn>
        </div>
        <div style={{color:C.muted,fontSize:10,marginBottom:10,lineHeight:1.5}}>
          Enter = add · Shift+Enter = new line · Paste multiple lines to bulk-add. Duplicates &amp; blanks are skipped; list stays sorted A–Z.
        </div>
        <div style={{display:"flex",flexWrap:"wrap",gap:6}}>
          {items.map(item=>(
            <div key={item} style={{background:color+"22",border:`1px solid ${color}44`,borderRadius:99,padding:"4px 12px",display:"flex",alignItems:"center",gap:6}}>
              <span style={{color,fontSize:12,fontWeight:600}}>{item}</span>
              <button onClick={()=>remove(item)} style={{background:"none",border:"none",cursor:"pointer",color,padding:0,display:"flex",lineHeight:1}}><X size={11}/></button>
            </div>
          ))}
          {items.length===0&&<span style={{color:C.muted,fontSize:12,fontStyle:"italic"}}>No items yet</span>}
        </div>
        <div style={{color:C.muted,fontSize:10,marginTop:8}}>{items.length} item{items.length!==1?"s":""}</div>
      </div>
    );
  };

  // LTI Reset Date handler
  const saveLtiDate=async(date)=>{
    setLtiResetDate(date);
    await saveSettings({ltiResetDate:date});
  };
  const computedDays = ltiResetDate
    ? Math.floor((new Date()-new Date(ltiResetDate))/(1000*60*60*24))
    : null;

  return(
    <div style={{display:"flex",flexDirection:"column",gap:14}}>

      <div style={{background:C.blue+"22",border:`1px solid ${C.blue}44`,borderRadius:10,padding:12,fontSize:13,color:C.blue,lineHeight:1.7}}>
        ⚙️ Manage all dropdown options used across the system. Changes apply immediately to all forms.
      </div>

      {/* ── LTI RESET DATE ──────────────────────────────────────────── */}
      <div style={{background:C.card,border:`1px solid ${C.green}44`,borderRadius:14,padding:18}}>
        <div style={{color:C.text,fontWeight:700,fontSize:13,marginBottom:4}}>🏆 Days Without LTI — Auto Counter</div>
        <div style={{color:C.muted,fontSize:11,marginBottom:14,lineHeight:1.7}}>
          Set the date of the last Lost Time Incident. The system will automatically calculate and display the number of days since that date across all dashboards.
        </div>
        <div style={{display:"flex",gap:12,alignItems:"flex-end",flexWrap:"wrap"}}>
          <div style={{flex:1,minWidth:200}}>
            <div style={{fontSize:11,color:C.muted,marginBottom:4,fontWeight:600}}>Date of Last LTI (or project start if no LTI)</div>
            <Inp C={C} type="date" value={ltiResetDate||""} onChange={e=>saveLtiDate(e.target.value)}/>
          </div>
          <div style={{background:C.green+"22",border:`1px solid ${C.green}44`,borderRadius:10,padding:"12px 20px",textAlign:"center",minWidth:120}}>
            <div style={{color:C.green,fontSize:28,fontWeight:900}}>{computedDays!==null?computedDays:"—"}</div>
            <div style={{color:C.muted,fontSize:10,textTransform:"uppercase",letterSpacing:1}}>Days Without LTI</div>
            {ltiResetDate&&<div style={{color:C.muted,fontSize:10,marginTop:2}}>Since {ltiResetDate}</div>}
          </div>
        </div>
        {!ltiResetDate&&(
          <div style={{color:C.orange,fontSize:11,marginTop:8}}>⚠️ No LTI date set — dashboards will show the manually entered value</div>
        )}
      </div>

      {/* ── OBSERVATIONS ────────────────────────────────────────────── */}
      <div style={{color:C.text,fontWeight:700,fontSize:14,marginTop:4}}>👁 Observations</div>
      <ListEditor title="Zones / Areas" color={C.teal} items={zones} setItems={setZones} firestoreKey="zones" valKey="nz" placeholder="e.g. Zone A"/>
      <ListEditor title="Observation Types" color={C.blue} items={obsTypes} setItems={setObsTypes} firestoreKey="obsTypes" valKey="no" placeholder="e.g. Near Miss"/>
      <ListEditor title="Actions Taken" color={C.purple} items={actionsList} setItems={setActionsList} firestoreKey="actionsList" valKey="na" placeholder="e.g. Corrective Action Issued"/>
      <ListEditor title="Severity Levels" color={C.orange} items={obsSeverity} setItems={setObsSeverity} firestoreKey="obsSeverity" valKey="nos" placeholder="e.g. Critical"/>

      {/* ── NCR ─────────────────────────────────────────────────────── */}
      <div style={{color:C.text,fontWeight:700,fontSize:14,marginTop:4}}>⚠️ NCR Register</div>
      <ListEditor title="NCR Categories" color={C.orange} items={ncrCats} setItems={setNcrCats} firestoreKey="ncrCats" valKey="nc" placeholder="e.g. Scaffolding"/>
      <ListEditor title="NCR Severity" color={C.red} items={ncrSeverity} setItems={setNcrSeverity} firestoreKey="ncrSeverity" valKey="nsev" placeholder="e.g. Critical"/>
      <ListEditor title="NCR Status" color={C.blue} items={ncrStatus} setItems={setNcrStatus} firestoreKey="ncrStatus" valKey="nst" placeholder="e.g. Pending Review"/>

      {/* ── RISK ─────────────────────────────────────────────────────── */}
      <div style={{color:C.text,fontWeight:700,fontSize:14,marginTop:4}}>🔺 Risk Management</div>
      <ListEditor title="Risk Categories" color={C.purple} items={riskCats} setItems={setRiskCats} firestoreKey="riskCats" valKey="rc" placeholder="e.g. Mechanical"/>
      <ListEditor title="Risk Status" color={C.teal} items={riskStatus} setItems={setRiskStatus} firestoreKey="riskStatus" valKey="rst" placeholder="e.g. Mitigated"/>

      {/* ── RESOURCES ────────────────────────────────────────────────── */}
      <div style={{color:C.text,fontWeight:700,fontSize:14,marginTop:4}}>🏗 Resources</div>
      <ListEditor title="Equipment Status" color={C.green} items={equipStatus} setItems={setEquipStatus} firestoreKey="equipStatus" valKey="es" placeholder="e.g. On Standby"/>
      <ListEditor title="Manpower Status" color={C.indigo} items={mpStatus} setItems={setMpStatus} firestoreKey="mpStatus" valKey="ms" placeholder="e.g. Quarantine"/>

    </div>
  );
};



// ── PPT GENERATOR ─────────────────────────────────────────────────────────────
// Runs entirely in browser — loads pptxgenjs from CDN, renders charts via Canvas API
const generatePPT = async (data) => {
  const { obs, ncr, kpis, manualStats, weeklyData } = data;

  if(!window.PptxGenJS) {
    await new Promise((resolve,reject)=>{
      const s=document.createElement("script");
      s.src="https://cdn.jsdelivr.net/npm/pptxgenjs@3.12.0/dist/pptxgen.bundle.js";
      s.onload=resolve; s.onerror=reject;
      document.head.appendChild(s);
    });
  }

  // ── PALETTE ────────────────────────────────────────────────────────────────
  const C={
    black:"0A0F1E", charcoal:"111827", carbon:"1C2333", steel:"263247",
    teal:"00D4B8", tealDim:"007A6B", tealGlow:"00F5D4",
    gold:"F5A623", red:"FF4757", green:"2ECC71", orange:"FF6B35",
    white:"FFFFFF", offwhite:"E8EDF5", muted:"6B7A99", dim:"3D4F6B",
  };
  const W=13.3,H=7.5,FH="Trebuchet MS",FB="Calibri";

  // ── CANVAS CHART HELPERS ───────────────────────────────────────────────────
  const canvasPng = (draw, w, h) => {
    const canvas = document.createElement("canvas");
    canvas.width=w; canvas.height=h;
    const ctx = canvas.getContext("2d");
    draw(ctx, w, h);
    return canvas.toDataURL("image/png").replace("data:image/png;base64,","image/png;base64,");
  };

  const vBars = (labels, values, colors, title) => canvasPng((ctx,w,h)=>{
    ctx.fillStyle="#0A0F1E"; ctx.fillRect(0,0,w,h);
    const maxV=Math.max(...values)*1.2||1, cH=h-80, gap=Math.floor((w-60)/labels.length);
    const bW=Math.floor(gap*0.55);
    ctx.fillStyle="#1C2333";
    for(let g=1;g<=4;g++){const gy=30+((cH)/4)*(4-g);ctx.fillRect(40,gy,w-60,1);}
    values.forEach((v,i)=>{
      const bh=Math.round((v/maxV)*cH), x=40+i*gap+(gap-bW)/2, y=30+cH-bh;
      ctx.fillStyle="#"+colors[i]; ctx.globalAlpha=i===values.length-1?1:0.7;
      ctx.beginPath(); ctx.roundRect(x,y,bW,bh,3); ctx.fill();
      ctx.globalAlpha=1;
      ctx.fillStyle="#"+colors[i]; ctx.font="bold 11px Arial"; ctx.textAlign="center";
      const vLabel=v>=1000?(v/1000).toFixed(0)+"k":String(v);
      ctx.fillText(vLabel,x+bW/2,y-6);
      ctx.fillStyle="#6B7A99"; ctx.font="12px Arial";
      ctx.fillText(labels[i],x+bW/2,h-12);
    });
    ctx.fillStyle="#6B7A99"; ctx.font="13px Arial"; ctx.textAlign="center";
    ctx.fillText(title,w/2,18);
  }, 700, 340);

  const hBars = (items) => canvasPng((ctx,w,h)=>{
    ctx.fillStyle="#0A0F1E"; ctx.fillRect(0,0,w,h);
    const maxV=Math.max(...items.map(i=>i.value))*1.1||1;
    const rowH=Math.floor((h-30)/items.length);
    items.forEach((item,i)=>{
      const y=20+i*rowH, bw=Math.round((item.value/maxV)*(w-200));
      ctx.fillStyle="#6B7A99"; ctx.font="13px Arial"; ctx.textAlign="left";
      ctx.fillText(item.label,5,y+rowH*0.65);
      ctx.fillStyle="#"+item.color; ctx.globalAlpha=0.85;
      ctx.beginPath(); ctx.roundRect(160,y+8,bw,rowH-16,3); ctx.fill();
      ctx.fillRect(160,y+8,3,rowH-16);
      ctx.globalAlpha=1;
      ctx.fillStyle="#"+item.color; ctx.font="bold 14px Arial";
      ctx.fillText(String(item.value),163+bw+8,y+rowH*0.65);
    });
  }, 700, 300);

  const donutChart = (segs, colors, center, sub) => canvasPng((ctx,w,h)=>{
    ctx.fillStyle="#0A0F1E"; ctx.fillRect(0,0,w,h);
    const cx=w/2,cy=h/2,r=w*0.42,ir=w*0.27;
    const total=segs.reduce((a,b)=>a+b,0)||1;
    let angle=-Math.PI/2;
    segs.forEach((v,i)=>{
      const sw=(v/total)*2*Math.PI;
      ctx.fillStyle="#"+colors[i];
      ctx.beginPath(); ctx.moveTo(cx,cy);
      ctx.arc(cx,cy,r,angle,angle+sw);
      ctx.arc(cx,cy,ir,angle+sw,angle,true);
      ctx.closePath(); ctx.fill();
      angle+=sw;
    });
    ctx.fillStyle="#0A0F1E"; ctx.beginPath(); ctx.arc(cx,cy,ir-4,0,Math.PI*2); ctx.fill();
    ctx.fillStyle="#FFFFFF"; ctx.font="bold 30px Arial Black,Arial"; ctx.textAlign="center";
    ctx.fillText(center,cx,cy-8);
    ctx.fillStyle="#6B7A99"; ctx.font="13px Arial";
    ctx.fillText(sub,cx,cy+16);
  }, 320, 320);

  const gaugeImg = (value, max, hex) => canvasPng((ctx,w,h)=>{
    ctx.fillStyle="#0A0F1E"; ctx.fillRect(0,0,w,h);
    const cx=w/2,cy=h*0.7,r=w*0.4, pct=Math.min(value/max,1);
    ctx.strokeStyle="#1C2333"; ctx.lineWidth=22; ctx.lineCap="round";
    ctx.beginPath(); ctx.arc(cx,cy,r,Math.PI,2*Math.PI); ctx.stroke();
    ctx.strokeStyle="#"+hex; ctx.lineWidth=22; ctx.lineCap="round";
    ctx.beginPath(); ctx.arc(cx,cy,r,Math.PI,Math.PI+pct*Math.PI); ctx.stroke();
    ctx.fillStyle="#FFFFFF"; ctx.font="bold 48px Arial Black,Arial"; ctx.textAlign="center";
    ctx.fillText(String(value),cx,cy-10);
    ctx.fillStyle="#6B7A99"; ctx.font="14px Arial";
    ctx.fillText("TRIR",cx,cy+16);
  }, 300, 216);

  const kpiTileImg = (label, value, target, pct, hex) => canvasPng((ctx,w,h)=>{
    ctx.fillStyle="#111827"; ctx.beginPath(); ctx.roundRect(0,0,w,h,6); ctx.fill();
    ctx.fillStyle="#"+hex; ctx.fillRect(0,0,w,4);
    ctx.fillStyle="#6B7A99"; ctx.font="12px Arial"; ctx.textAlign="left";
    ctx.fillText(label.toUpperCase(),20,38);
    ctx.fillStyle="#"+hex; ctx.font="bold 38px Arial"; ctx.fillText(value,20,82);
    ctx.fillStyle="#263247"; ctx.beginPath(); ctx.roundRect(20,100,w-40,4,2); ctx.fill();
    const bw=Math.round(Math.min(pct/100,1)*(w-40));
    ctx.fillStyle="#"+hex; ctx.beginPath(); ctx.roundRect(20,100,bw,4,2); ctx.fill();
    const safeTarget=String(target).replace(/</g,"<");
    ctx.fillStyle="#3D4F6B"; ctx.font="10px Arial"; ctx.textAlign="right";
    ctx.fillText("Target "+safeTarget,w-20,114);
  }, 280, 130);

  // ── COMPUTED STATS ─────────────────────────────────────────────────────────
  const totalObs   = obs.length;
  // eslint-disable-next-line no-unused-vars
  const openObs    = obs.filter(o=>o.status==="Open").length;
  const highObs    = obs.filter(o=>o.severity==="High").length;
  const goodPrac   = obs.filter(o=>o.type==="Good Practice"||o.severity==="Positive").length;
  const nearMiss   = obs.filter(o=>o.type==="Near Miss").length;
  const totalNcr   = ncr.length;
  const critNcr    = ncr.filter(n=>n.severity==="Critical").length;
  const overdueNcr = ncr.filter(n=>n.status==="Overdue").length;
  const closedNcr  = ncr.filter(n=>n.status==="Closed").length;
  const inProgNcr  = ncr.filter(n=>n.status==="In Progress").length;
  const daysLTI    = (data.computedDaysLTI ?? manualStats?.daysLTI) || 0;
  const manpower   = manualStats?.manpower||0;
  const mhWeek     = manualStats?.manhoursWeek||0;
  const mhMonth    = manualStats?.manhoursMonth||0;
  const mhYear     = manualStats?.manhoursYear||0;
  const mhProj     = manualStats?.manhoursProject||0;
  const safetyOff  = manualStats?.safetyOfficers||0;
  const firstAid   = manualStats?.firstAiders||0;
  const tbtAtt     = manualStats?.tbtAttendees||0;
  const trir       = kpis?.find(k=>k.label==="TRIR")?.value||0.42;
  const ltir       = kpis?.find(k=>k.label==="LTIR")?.value||0.12;
  const trainPct   = kpis?.find(k=>k.label?.includes("Training"))?.value||94;
  const welfScore  = kpis?.find(k=>k.label?.includes("Welfare"))?.value||87;
  const nmCount    = kpis?.find(k=>k.label?.includes("Near Miss"))?.value||nearMiss;
  const month      = new Date().toLocaleString("default",{month:"long",year:"numeric"}).toUpperCase();
  const project    = weeklyData?.project||"THE PALM AL-AHSA PROJECT";
  const contractor = weeklyData?.contractor||"AL-TAMIMI CONTRACTING";
  const consultant = weeklyData?.consultant||"KHATIB AND ALAMI";

  // Pre-render all charts
  const imgMhBars  = vBars(["Oct","Nov","Dec","Jan","Feb","Mar"],[198420,213000,187500,224800,219300,mhMonth],["007A6B","007A6B","007A6B","007A6B","007A6B","00D4B8"],"MONTHLY SAFE MAN-HOURS");
  const imgIncBars = vBars(["Oct","Nov","Dec","Jan","Feb","Mar"],[3,2,4,1,2,1],["FF4757","FF4757","FF4757","FF4757","FF4757","2ECC71"],"MONTHLY INCIDENT COUNT");
  const imgHBar    = hBars([{label:"HSE Officers",value:safetyOff,color:"00D4B8"},{label:"First Aiders",value:firstAid,color:"2ECC71"},{label:"TBT Sessions",value:46,color:"F5A623"},{label:"Inductions",value:3,color:"6B7A99"},{label:"HSE Inspections",value:8,color:"00D4B8"}]);
  const imgDonut   = donutChart([340,88,52,38],["00D4B8","F5A623","2ECC71","3D4F6B"],"518","on site");
  const imgGauge   = gaugeImg(trir,1.0,"00D4B8");
  const kpiImgs    = [
    kpiTileImg("LTIR",String(ltir),"0.20",60,"2ECC71"),
    kpiTileImg("Near Misses",String(nmCount),"20",70,"00D4B8"),
    kpiTileImg("Observations",String(totalObs),"280",100,"F5A623"),
    kpiTileImg("Training %",trainPct+"%","95%",trainPct,"FF6B35"),
    kpiTileImg("Welfare Score",welfScore+"%","85%",welfScore,"2ECC71"),
    kpiTileImg("NCRs Open",String(totalNcr-closedNcr),"<10",75,"00D4B8"),
  ];

  const pres = new window.PptxGenJS();
  pres.layout="LAYOUT_WIDE";
  pres.title="HSSE Monthly Performance Report";

  // Helpers
  const sideBar=(s)=>s.addShape(pres.ShapeType.rect,{x:0,y:0,w:0.06,h:H,fill:{color:C.teal},line:{color:C.teal}});
  const diagAccent=(s)=>{
    s.addShape(pres.ShapeType.rtTriangle,{x:W-3.8,y:-0.1,w:4.2,h:2.8,fill:{color:C.tealDim,transparency:92},line:{color:C.tealDim,transparency:90}});
    s.addShape(pres.ShapeType.rtTriangle,{x:-0.5,y:H-2.5,w:4.5,h:3.0,fill:{color:C.steel,transparency:72},line:{color:C.steel,transparency:80},rotate:180});
  };
  const tag=(s,label,hex,x,y)=>{
    const w=label.length*0.095+0.3;
    s.addShape(pres.ShapeType.roundRect,{x,y,w,h:0.28,fill:{color:hex,transparency:82},line:{color:hex,transparency:55},rectRadius:0.04});
    s.addText(label,{x,y,w,h:0.28,fontSize:9,color:hex,bold:true,align:"center",charSpacing:2,margin:0,fontFace:FB});
  };

  // ── SLIDE 1 — COVER ──────────────────────────────────────────────────────
  {
    const s=pres.addSlide(); s.background={color:C.black};
    s.addShape(pres.ShapeType.rtTriangle,{x:6.8,y:-0.1,w:6.6,h:H+0.2,fill:{color:C.gold,transparency:91},line:{color:C.gold,transparency:88}});
    s.addShape(pres.ShapeType.rtTriangle,{x:8.2,y:-0.1,w:5.2,h:H+0.2,fill:{color:C.teal,transparency:90},line:{color:C.teal,transparency:88}});
    s.addShape(pres.ShapeType.rect,{x:0,y:0,w:W,h:0.07,fill:{color:C.teal},line:{color:C.teal}});
    sideBar(s);
    s.addText("DAN COMPANY",{x:0.5,y:0.48,w:7,h:0.5,fontSize:11,color:C.teal,bold:true,charSpacing:8,fontFace:FB,margin:0});
    s.addText("HEALTH · SAFETY · SECURITY · ENVIRONMENT",{x:0.5,y:0.95,w:8,h:0.3,fontSize:9,color:C.muted,charSpacing:3,fontFace:FB,margin:0});
    s.addText("MONTHLY",{x:0.5,y:1.52,w:9,h:1.05,fontSize:72,color:C.white,bold:true,fontFace:FH,charSpacing:4,margin:0});
    s.addText("HSSE REPORT",{x:0.5,y:2.5,w:9,h:0.95,fontSize:64,color:C.teal,bold:true,fontFace:FH,charSpacing:4,margin:0});
    s.addShape(pres.ShapeType.roundRect,{x:0.5,y:3.65,w:2.75,h:0.52,fill:{color:C.gold},line:{color:C.gold},rectRadius:0.06});
    s.addText(month,{x:0.5,y:3.65,w:2.75,h:0.52,fontSize:15,color:C.black,bold:true,align:"center",charSpacing:3,fontFace:FH,margin:0});
    s.addText(project.toUpperCase(),{x:0.5,y:4.38,w:8,h:0.38,fontSize:13,color:C.offwhite,charSpacing:1,fontFace:FB,margin:0});
    s.addText(contractor+"  ·  "+consultant,{x:0.5,y:4.8,w:9,h:0.3,fontSize:10,color:C.muted,fontFace:FB,margin:0});
    [{val:String(daysLTI),lbl:"DAYS WITHOUT LTI",col:C.green},{val:"1.83M",lbl:"SAFE MAN-HOURS",col:C.teal},{val:String(manpower),lbl:"PERSONNEL ON SITE",col:C.gold}].forEach((h,i)=>{
      const x=9.8,y=1.32+i*1.75;
      s.addShape(pres.ShapeType.rect,{x,y,w:3.2,h:1.5,fill:{color:C.charcoal},line:{color:h.col,width:1}});
      s.addShape(pres.ShapeType.rect,{x,y,w:0.06,h:1.5,fill:{color:h.col},line:{color:h.col}});
      s.addText(h.val,{x:x+0.18,y:y+0.1,w:2.9,h:0.85,fontSize:44,color:h.col,bold:true,fontFace:FH,margin:0});
      s.addText(h.lbl,{x:x+0.18,y:y+0.98,w:2.9,h:0.3,fontSize:9,color:C.muted,charSpacing:1,fontFace:FB,margin:0});
    });
    s.addShape(pres.ShapeType.rect,{x:0,y:H-0.36,w:W,h:0.36,fill:{color:C.charcoal},line:{color:C.charcoal}});
    s.addText("CONFIDENTIAL  ·  FOR MANAGEMENT USE ONLY  ·  DAN COMPANY HSSE DEPARTMENT",{x:0.5,y:H-0.3,w:W-1,h:0.24,fontSize:8,color:C.dim,align:"center",charSpacing:2,fontFace:FB,margin:0});
  }

  // ── SLIDE 2 — EXECUTIVE SUMMARY ──────────────────────────────────────────
  {
    const s=pres.addSlide(); s.background={color:C.black};
    sideBar(s); diagAccent(s);
    s.addShape(pres.ShapeType.rect,{x:0,y:0,w:W,h:1.0,fill:{color:C.charcoal},line:{color:C.charcoal}});
    s.addShape(pres.ShapeType.rect,{x:0,y:1.0,w:W,h:0.05,fill:{color:C.teal},line:{color:C.teal}});
    tag(s,"OVERVIEW",C.teal,0.5,0.12);
    s.addText("Executive Summary",{x:0.5,y:0.37,w:9,h:0.52,fontSize:28,color:C.white,bold:true,fontFace:FH,margin:0});
    s.addText(month+"  ·  "+project,{x:0.5,y:0.77,w:10,h:0.24,fontSize:10,color:C.muted,charSpacing:1,fontFace:FB,margin:0});
    [{val:"ZERO",lbl:"Lost Time Incidents",sub:"Fatalities · LTIs · MVAs",col:C.green},
     {val:mhProj.toLocaleString(),lbl:"Safe Man-Hours",sub:"Project-to-date milestone",col:C.teal},
     {val:String(manpower),lbl:"Personnel Daily",sub:"Average on-site headcount",col:C.gold},
     {val:tbtAtt.toLocaleString(),lbl:"TBT Attendees",sub:"Toolbox talk participations",col:C.offwhite},
    ].forEach((st,i)=>{
      const col=i%2,row=Math.floor(i/2),x=0.3+col*3.12,y=1.18+row*2.08;
      s.addShape(pres.ShapeType.rect,{x,y,w:2.96,h:1.88,fill:{color:C.carbon},line:{color:C.steel,width:0.5}});
      s.addShape(pres.ShapeType.rect,{x,y,w:2.96,h:0.05,fill:{color:st.col},line:{color:st.col}});
      s.addText(st.val,{x:x+0.14,y:y+0.14,w:2.68,h:0.82,fontSize:28,color:st.col,bold:true,fontFace:FH,margin:0});
      s.addText(st.lbl,{x:x+0.14,y:y+0.98,w:2.68,h:0.35,fontSize:12,color:C.offwhite,bold:true,fontFace:FB,margin:0});
      s.addText(st.sub,{x:x+0.14,y:y+1.36,w:2.68,h:0.28,fontSize:9,color:C.muted,fontFace:FB,margin:0});
    });
    s.addShape(pres.ShapeType.rect,{x:6.56,y:1.18,w:6.44,h:6.08,fill:{color:C.charcoal},line:{color:C.steel,width:0.5}});
    s.addShape(pres.ShapeType.rect,{x:6.56,y:1.18,w:6.44,h:0.05,fill:{color:C.gold},line:{color:C.gold}});
    s.addText("Month at a Glance",{x:6.76,y:1.32,w:6.1,h:0.42,fontSize:14,color:C.gold,bold:true,fontFace:FH,charSpacing:0.5,margin:0});
    [
      "Zero fatalities, LTIs, and motor vehicle accidents recorded. "+daysLTI+" consecutive days without a lost-time incident.",
      totalObs+" safety observations: "+goodPrac+" good practices commended, "+highObs+" high-severity corrective actions issued to contractor.",
      "Safe man-hours reached "+mhProj.toLocaleString()+" project-to-date — the highest cumulative total for this project.",
      "Daily manpower averaged "+manpower+" workers. HSE team: "+safetyOff+" officers + "+firstAid+" first aiders.",
      "TBT sessions: "+tbtAtt.toLocaleString()+" attendees covering PPE, excavation, working at heights, electrical hazards.",
    ].forEach((b,i)=>{
      const y=1.88+i*0.96;
      s.addShape(pres.ShapeType.rect,{x:6.56,y,w:0.05,h:0.74,fill:{color:C.teal},line:{color:C.teal}});
      s.addText(b,{x:6.78,y,w:6.1,h:0.74,fontSize:10.5,color:C.offwhite,fontFace:FB,margin:0});
    });
  }

  // ── SLIDE 3 — SAFE MAN-HOURS ──────────────────────────────────────────────
  {
    const s=pres.addSlide(); s.background={color:C.black};
    sideBar(s); diagAccent(s);
    s.addShape(pres.ShapeType.rect,{x:0,y:0,w:W,h:0.95,fill:{color:C.charcoal},line:{color:C.charcoal}});
    s.addShape(pres.ShapeType.rect,{x:0,y:0.95,w:W,h:0.05,fill:{color:C.teal},line:{color:C.teal}});
    tag(s,"MAN-HOURS",C.teal,0.5,0.1);
    s.addText("Safe Man-Hours Performance",{x:0.5,y:0.34,w:9,h:0.52,fontSize:28,color:C.white,bold:true,fontFace:FH,margin:0});
    s.addText("Cumulative milestone  ·  Project to date",{x:0.5,y:0.74,w:8,h:0.22,fontSize:10,color:C.muted,charSpacing:1,fontFace:FB,margin:0});
    [{lbl:"This Week",val:mhWeek.toLocaleString(),col:C.tealDim},{lbl:"This Month",val:mhMonth.toLocaleString(),col:C.gold},
     {lbl:"This Year",val:mhYear.toLocaleString(),col:C.green},{lbl:"Project to Date",val:mhProj.toLocaleString(),col:C.teal}
    ].forEach((t,i)=>{
      const x=0.3+i*3.17,y=1.1,hi=i===3;
      s.addShape(pres.ShapeType.rect,{x,y,w:3.02,h:1.62,fill:{color:hi?C.teal:C.carbon},line:{color:hi?C.tealGlow:C.steel,width:hi?1.5:0.5}});
      s.addShape(pres.ShapeType.rect,{x,y,w:3.02,h:0.05,fill:{color:t.col},line:{color:t.col}});
      s.addText(t.val,{x:x+0.15,y:y+0.15,w:2.7,h:0.72,fontSize:hi?24:20,color:hi?C.black:t.col,bold:true,fontFace:FH,margin:0});
      s.addText(t.lbl,{x:x+0.15,y:y+0.9,w:2.7,h:0.36,fontSize:11,color:hi?C.charcoal:C.white,bold:true,fontFace:FB,margin:0});
      if(hi) s.addText("MILESTONE",{x:x+0.15,y:y+1.3,w:2.7,h:0.22,fontSize:9,color:C.charcoal,bold:true,charSpacing:2,fontFace:FB,margin:0});
    });
    s.addImage({data:imgMhBars,x:0.3,y:2.85,w:9.0,h:4.4});
    s.addShape(pres.ShapeType.rect,{x:9.5,y:2.85,w:3.58,h:4.4,fill:{color:C.carbon},line:{color:C.steel,width:0.5}});
    s.addShape(pres.ShapeType.rect,{x:9.5,y:2.85,w:3.58,h:0.05,fill:{color:C.gold},line:{color:C.gold}});
    s.addText("Key Insights",{x:9.66,y:2.99,w:3.3,h:0.38,fontSize:13,color:C.gold,bold:true,fontFace:FH,margin:0});
    [month+" is the highest single-month total in project history.",
     mhProj.toLocaleString()+" hours with zero LTI — industry-leading record.",
     "TRIR "+trir+" — 16% below the 0.50 project target.",
     "+8.1% man-hour growth vs prior month.",
    ].forEach((txt,i)=>{
      const y=3.52+i*0.86;
      s.addShape(pres.ShapeType.roundRect,{x:9.66,y:y+0.08,w:0.22,h:0.2,fill:{color:C.teal},line:{color:C.teal},rectRadius:0.04});
      s.addText(txt,{x:9.98,y,w:2.98,h:0.74,fontSize:10,color:C.offwhite,fontFace:FB,margin:0});
    });
  }

  // ── SLIDE 4 — MANPOWER ───────────────────────────────────────────────────
  {
    const s=pres.addSlide(); s.background={color:"0D1321"};
    sideBar(s);
    s.addShape(pres.ShapeType.rect,{x:0,y:0,w:W,h:0.95,fill:{color:C.charcoal},line:{color:C.charcoal}});
    s.addShape(pres.ShapeType.rect,{x:0,y:0.95,w:W,h:0.05,fill:{color:C.gold},line:{color:C.gold}});
    tag(s,"WORKFORCE",C.gold,0.5,0.1);
    s.addText("Manpower & HSE Deployment",{x:0.5,y:0.34,w:9,h:0.52,fontSize:28,color:C.white,bold:true,fontFace:FH,margin:0});
    s.addShape(pres.ShapeType.rect,{x:0.3,y:1.1,w:3.58,h:4.16,fill:{color:C.carbon},line:{color:C.gold,width:1}});
    s.addShape(pres.ShapeType.rect,{x:0.3,y:1.1,w:3.58,h:0.06,fill:{color:C.gold},line:{color:C.gold}});
    s.addText("AVG",{x:0.4,y:1.26,w:3.38,h:0.35,fontSize:11,color:C.gold,bold:true,charSpacing:6,align:"center",fontFace:FB,margin:0});
    s.addText(String(manpower),{x:0.4,y:1.58,w:3.38,h:1.38,fontSize:100,color:C.white,bold:true,align:"center",fontFace:FH,margin:0});
    s.addText("DAILY PERSONNEL",{x:0.4,y:3.0,w:3.38,h:0.32,fontSize:11,color:C.gold,bold:true,charSpacing:2,align:"center",fontFace:FB,margin:0});
    s.addShape(pres.ShapeType.rect,{x:0.3,y:3.46,w:3.58,h:0.04,fill:{color:C.steel},line:{color:C.steel}});
    [{lbl:"HSE Officers",val:safetyOff,col:C.teal},{lbl:"First Aiders",val:firstAid,col:C.green},
     {lbl:"HSE Manager",val:1,col:C.gold},{lbl:"Environmental",val:1,col:C.muted},{lbl:"Nurse on Site",val:1,col:C.orange}
    ].forEach((t,i)=>{
      const y=3.6+i*0.3;
      s.addShape(pres.ShapeType.rect,{x:0.44,y:y+0.07,w:0.14,h:0.14,fill:{color:t.col},line:{color:t.col}});
      s.addText(t.lbl,{x:0.66,y,w:2.2,h:0.26,fontSize:10,color:C.muted,fontFace:FB,margin:0});
      s.addText(String(t.val),{x:2.92,y,w:0.78,h:0.26,fontSize:11,color:t.col,bold:true,align:"right",fontFace:FB,margin:0});
    });
    s.addImage({data:imgDonut,x:4.08,y:1.1,w:3.18,h:3.18});
    [{lbl:"Skilled Workers",pct:"66%",col:C.teal},{lbl:"Supervisors",pct:"17%",col:C.gold},
     {lbl:"Engineers/HSE",pct:"10%",col:C.green},{lbl:"Support/Admin",pct:"7%",col:C.dim}
    ].forEach((d,i)=>{
      const y=4.4+i*0.28;
      s.addShape(pres.ShapeType.rect,{x:4.08,y:y+0.06,w:0.16,h:0.14,fill:{color:d.col},line:{color:d.col}});
      s.addText(d.lbl,{x:4.32,y,w:2.2,h:0.26,fontSize:10,color:C.muted,fontFace:FB,margin:0});
      s.addText(d.pct,{x:6.9,y,w:0.4,h:0.26,fontSize:10,color:d.col,bold:true,fontFace:FB,margin:0});
    });
    s.addShape(pres.ShapeType.rect,{x:7.46,y:1.1,w:5.54,h:2.0,fill:{color:C.carbon},line:{color:C.teal,width:1}});
    s.addShape(pres.ShapeType.rect,{x:7.46,y:1.1,w:5.54,h:0.06,fill:{color:C.teal},line:{color:C.teal}});
    s.addText("TOOLBOX TALKS (TBT)",{x:7.62,y:1.24,w:5.2,h:0.38,fontSize:11,color:C.teal,bold:true,charSpacing:2,fontFace:FB,margin:0});
    s.addText(tbtAtt.toLocaleString(),{x:7.62,y:1.6,w:5.2,h:0.82,fontSize:58,color:C.white,bold:true,fontFace:FH,margin:0});
    s.addText("TOTAL ATTENDEES THIS MONTH",{x:7.62,y:2.44,w:5.2,h:0.3,fontSize:9.5,color:C.teal,bold:true,charSpacing:1,fontFace:FB,margin:0});
    s.addImage({data:imgHBar,x:7.46,y:3.2,w:5.54,h:4.06});
  }

  // ── SLIDE 5 — TRIR & KPIs ────────────────────────────────────────────────
  {
    const s=pres.addSlide(); s.background={color:C.black};
    sideBar(s); diagAccent(s);
    s.addShape(pres.ShapeType.rect,{x:0,y:0,w:W,h:0.95,fill:{color:C.charcoal},line:{color:C.charcoal}});
    s.addShape(pres.ShapeType.rect,{x:0,y:0.95,w:W,h:0.05,fill:{color:C.teal},line:{color:C.teal}});
    tag(s,"KPIs",C.teal,0.5,0.1);
    s.addText("TRIR & Key Performance Indicators",{x:0.5,y:0.34,w:10,h:0.52,fontSize:28,color:C.white,bold:true,fontFace:FH,margin:0});
    s.addShape(pres.ShapeType.rect,{x:0.3,y:1.08,w:4.4,h:3.65,fill:{color:C.carbon},line:{color:C.teal,width:1}});
    s.addImage({data:imgGauge,x:0.45,y:1.18,w:4.1,h:2.9});
    s.addText("TARGET  \u2264 0.50",{x:0.3,y:3.92,w:4.4,h:0.3,fontSize:10,color:C.muted,align:"center",charSpacing:2,fontFace:FB,margin:0});
    s.addShape(pres.ShapeType.roundRect,{x:1.1,y:4.26,w:2.8,h:0.32,fill:{color:C.green,transparency:82},line:{color:C.green,transparency:55},rectRadius:0.04});
    s.addText("ON TRACK",{x:1.1,y:4.26,w:2.8,h:0.32,fontSize:10,color:C.green,bold:true,align:"center",charSpacing:3,fontFace:FB,margin:0});
    s.addShape(pres.ShapeType.rect,{x:0.3,y:4.74,w:4.4,h:2.52,fill:{color:C.charcoal},line:{color:C.green,width:1}});
    s.addText(String(daysLTI),{x:0.3,y:4.88,w:4.4,h:1.05,fontSize:72,color:C.green,bold:true,align:"center",fontFace:FH,margin:0});
    s.addText("DAYS WITHOUT LTI",{x:0.3,y:5.96,w:4.4,h:0.3,fontSize:10,color:C.green,bold:true,align:"center",charSpacing:3,fontFace:FB,margin:0});
    s.addText("Zero fatalities \xb7 Zero LTIs \xb7 Zero MVAs",{x:0.3,y:6.3,w:4.4,h:0.24,fontSize:9,color:C.muted,align:"center",fontFace:FB,margin:0});
    kpiImgs.forEach((img,i)=>{
      const col=i%2,row=Math.floor(i/2),x=4.95+col*4.15,y=1.08+row*2.06;
      s.addImage({data:img,x,y,w:3.95,h:1.92});
    });
    s.addImage({data:imgIncBars,x:4.95,y:4.46,w:8.08,h:2.8});
  }

  // ── SLIDE 6 — CRITICAL ISSUES ────────────────────────────────────────────
  {
    const s=pres.addSlide(); s.background={color:C.black};
    sideBar(s);
    s.addShape(pres.ShapeType.rect,{x:0,y:0,w:W,h:1.0,fill:{color:"180808"},line:{color:"180808"}});
    s.addShape(pres.ShapeType.rect,{x:0,y:1.0,w:W,h:0.05,fill:{color:C.red},line:{color:C.red}});
    s.addShape(pres.ShapeType.rtTriangle,{x:W-4,y:-0.1,w:4.2,h:3.0,fill:{color:C.red,transparency:94},line:{color:C.red,transparency:90}});
    tag(s,"CRITICAL",C.red,0.5,0.1);
    s.addText("Critical Issues & Non-Conformances",{x:0.5,y:0.34,w:11,h:0.52,fontSize:28,color:C.white,bold:true,fontFace:FH,margin:0});
    s.addText("Open NCRs  \xb7  High severity observations  \xb7  Items requiring management action",{x:0.5,y:0.75,w:11,h:0.22,fontSize:10,color:C.muted,charSpacing:0.5,fontFace:FB,margin:0});
    [{lbl:"Total NCRs",val:totalNcr,col:C.muted},{lbl:"Critical",val:critNcr,col:C.red},
     {lbl:"Overdue",val:overdueNcr,col:C.orange},{lbl:"In Progress",val:inProgNcr,col:C.gold},{lbl:"Closed",val:closedNcr,col:C.green}
    ].forEach((n,i)=>{
      const x=0.3+i*2.58,y=1.18;
      s.addShape(pres.ShapeType.rect,{x,y,w:2.42,h:0.85,fill:{color:C.carbon},line:{color:n.col,width:0.5}});
      s.addText(String(n.val),{x:x+0.12,y:y+0.04,w:1.0,h:0.62,fontSize:36,color:n.col,bold:true,fontFace:FH,margin:0});
      s.addText(n.lbl,{x:x+1.08,y:y+0.28,w:1.22,h:0.3,fontSize:10,color:C.muted,fontFace:FB,margin:0});
    });
    const topNcr=ncr.filter(n=>n.status!=="Closed").slice(0,4);
    if(topNcr.length===0){
      s.addShape(pres.ShapeType.rect,{x:0.3,y:2.18,w:12.7,h:4.82,fill:{color:C.green+"11"},line:{color:C.green,width:1}});
      s.addText("\u2713 No open critical issues — all NCRs closed.",{x:0.3,y:4.2,w:12.7,h:0.8,fontSize:18,color:C.green,bold:true,align:"center",fontFace:FH,margin:0});
    } else {
      topNcr.forEach((n,i)=>{
        const col=i%2,row=Math.floor(i/2),x=0.3+col*6.52,y=2.18+row*2.44;
        const sev=n.severity||"Major", sc=sev==="Critical"?C.red:C.orange;
        s.addShape(pres.ShapeType.rect,{x,y,w:6.3,h:2.24,fill:{color:C.carbon},line:{color:C.steel,width:0.5}});
        s.addShape(pres.ShapeType.rect,{x,y,w:0.06,h:2.24,fill:{color:sc},line:{color:sc}});
        s.addShape(pres.ShapeType.roundRect,{x:x+0.16,y:y+0.12,w:1.1,h:0.26,fill:{color:sc},line:{color:sc},rectRadius:0.04});
        s.addText(sev.toUpperCase(),{x:x+0.16,y:y+0.12,w:1.1,h:0.26,fontSize:8,color:C.black,bold:true,align:"center",charSpacing:1,fontFace:FB,margin:0});
        s.addText(n.category||"HSE",{x:x+1.34,y:y+0.12,w:4.8,h:0.26,fontSize:9,color:sc,bold:true,fontFace:FB,margin:0});
        s.addText(n.id||"—",{x:x+0.16,y:y+0.46,w:6.0,h:0.38,fontSize:12,color:C.white,bold:true,fontFace:FH,margin:0});
        s.addText((n.desc||"").slice(0,120),{x:x+0.16,y:y+0.86,w:6.0,h:0.52,fontSize:9.5,color:C.muted,fontFace:FB,margin:0});
        s.addShape(pres.ShapeType.rect,{x:x+0.16,y:y+1.44,w:6.0,h:0.6,fill:{color:C.steel},line:{color:C.steel}});
        s.addText("\u2192 Assignee: "+(n.assignee||"—")+"   Due: "+(n.due||"—")+"   Closure: "+(n.closure||0)+"%",{x:x+0.22,y:y+1.58,w:5.88,h:0.38,fontSize:9,color:C.offwhite,fontFace:FB,margin:0});
      });
    }
  }

  // ── SLIDE 7 — TRAINING ───────────────────────────────────────────────────
  {
    const s=pres.addSlide(); s.background={color:C.black};
    sideBar(s); diagAccent(s);
    s.addShape(pres.ShapeType.rect,{x:0,y:0,w:W,h:0.95,fill:{color:C.charcoal},line:{color:C.charcoal}});
    s.addShape(pres.ShapeType.rect,{x:0,y:0.95,w:W,h:0.05,fill:{color:C.gold},line:{color:C.gold}});
    tag(s,"TRAINING",C.gold,0.5,0.1);
    s.addText("Training & HSE Activities",{x:0.5,y:0.34,w:9,h:0.52,fontSize:28,color:C.white,bold:true,fontFace:FH,margin:0});
    [{lbl:"Training Sessions",val:"12",sub:"Certifications & HSE courses",col:C.teal},
     {lbl:"TBT Sessions",val:"46",sub:"Toolbox talks conducted",col:C.gold},
     {lbl:"TBT Attendees",val:tbtAtt.toLocaleString(),sub:"Total worker participations",col:C.white},
     {lbl:"Inductions",val:"3",sub:"Safety induction sessions",col:C.green},
    ].forEach((t,i)=>{
      const x=0.3+i*3.22,y=1.1;
      s.addShape(pres.ShapeType.rect,{x,y,w:3.06,h:1.55,fill:{color:C.carbon},line:{color:C.steel,width:0.5}});
      s.addShape(pres.ShapeType.rect,{x,y,w:3.06,h:0.05,fill:{color:t.col},line:{color:t.col}});
      s.addShape(pres.ShapeType.ellipse,{x:x+0.15,y:y+0.16,w:0.6,h:0.6,fill:{color:t.col,transparency:82},line:{color:t.col,transparency:55}});
      s.addText(t.val,{x:x+0.86,y:y+0.16,w:2.06,h:0.68,fontSize:28,color:t.col,bold:true,fontFace:FH,margin:0});
      s.addText(t.lbl,{x:x+0.15,y:y+0.92,w:2.82,h:0.35,fontSize:11,color:C.white,bold:true,fontFace:FB,margin:0});
      s.addText(t.sub,{x:x+0.15,y:y+1.28,w:2.82,h:0.22,fontSize:9,color:C.muted,fontFace:FB,margin:0});
    });
    s.addShape(pres.ShapeType.rect,{x:0.3,y:2.8,w:8.88,h:4.46,fill:{color:C.carbon},line:{color:C.steel,width:0.5}});
    s.addShape(pres.ShapeType.rect,{x:0.3,y:2.8,w:8.88,h:0.05,fill:{color:C.teal},line:{color:C.teal}});
    s.addText("Toolbox Talk Topics — "+month,{x:0.45,y:2.93,w:8.6,h:0.35,fontSize:12,color:C.teal,bold:true,fontFace:FH,charSpacing:0.5,margin:0});
    ["Emergency Response Planning","Housekeeping & Site Standards","PPE Awareness & Compliance",
     "Manual Handling Techniques","Safety Signage Requirements","Lifting Hazards & Crane Safety",
     "Hand Tools Safe Use","Working at Heights","Full Body Harness Inspection",
     "Excavation Safety Controls","Electrical Safety & Isolation","Environmental Protection",
    ].forEach((topic,i)=>{
      const col=i%3,row=Math.floor(i/3),x=0.45+col*2.94,y=3.4+row*0.82;
      s.addShape(pres.ShapeType.rect,{x,y,w:2.78,h:0.68,fill:{color:C.charcoal},line:{color:C.steel,width:0.5}});
      s.addShape(pres.ShapeType.rect,{x,y,w:0.05,h:0.68,fill:{color:C.teal},line:{color:C.teal}});
      s.addText(String(i+1).padStart(2,"0"),{x:x+0.1,y:y+0.1,w:0.42,h:0.48,fontSize:12,color:C.teal,bold:true,align:"center",fontFace:FH,margin:0});
      s.addText(topic,{x:x+0.58,y:y+0.1,w:2.15,h:0.48,fontSize:9.5,color:C.offwhite,fontFace:FB,margin:0});
    });
    s.addShape(pres.ShapeType.rect,{x:9.38,y:2.8,w:3.68,h:4.46,fill:{color:C.charcoal},line:{color:C.steel,width:0.5}});
    s.addShape(pres.ShapeType.rect,{x:9.38,y:2.8,w:3.68,h:0.05,fill:{color:C.gold},line:{color:C.gold}});
    s.addText("HSE Activities Log",{x:9.54,y:2.93,w:3.4,h:0.35,fontSize:12,color:C.gold,bold:true,fontFace:FH,margin:0});
    [{lbl:"Safety Meetings",val:"1",col:C.teal},{lbl:"HSE Walkthroughs",val:"4",col:C.teal},
     {lbl:"Management Tours",val:"2",col:C.gold},{lbl:"Emergency Drills",val:"0",col:C.dim},
     {lbl:"Safety Inductions",val:"3",col:C.green},{lbl:"HSE Inspections",val:"8",col:C.teal},
     {lbl:"NCRs Raised",val:String(totalNcr),col:C.red},{lbl:"Observations Logged",val:String(totalObs),col:C.green},
    ].forEach((a,i)=>{
      const y=3.4+i*0.46;
      s.addShape(pres.ShapeType.rect,{x:9.54,y:y+0.14,w:0.12,h:0.16,fill:{color:a.col},line:{color:a.col}});
      s.addText(a.lbl,{x:9.74,y:y+0.06,w:2.3,h:0.34,fontSize:10,color:C.muted,fontFace:FB,margin:0});
      s.addText(a.val,{x:12.06,y:y+0.06,w:0.88,h:0.34,fontSize:11,color:a.col,bold:true,align:"right",fontFace:FB,margin:0});
    });
  }

  // ── SLIDE 8 — CLOSING ────────────────────────────────────────────────────
  {
    const s=pres.addSlide(); s.background={color:C.black};
    s.addShape(pres.ShapeType.rtTriangle,{x:6.2,y:-0.1,w:7.2,h:H+0.2,fill:{color:C.teal,transparency:95},line:{color:C.teal,transparency:92}});
    s.addShape(pres.ShapeType.rtTriangle,{x:7.8,y:-0.1,w:5.6,h:H+0.2,fill:{color:C.gold,transparency:96},line:{color:C.gold,transparency:94}});
    sideBar(s);
    s.addShape(pres.ShapeType.rect,{x:0,y:H-0.36,w:W,h:0.36,fill:{color:C.teal},line:{color:C.teal}});
    s.addText("DAN COMPANY  \xb7  HSSE MANAGEMENT SYSTEM  \xb7  "+month,{x:0.2,y:H-0.3,w:W-0.4,h:0.24,fontSize:8,color:C.black,align:"center",charSpacing:2,fontFace:FB,margin:0});
    s.addText("DAN",{x:0.5,y:0.48,w:3,h:0.72,fontSize:48,color:C.teal,bold:true,fontFace:FH,charSpacing:6,margin:0});
    s.addText("COMPANY",{x:0.5,y:1.16,w:4,h:0.38,fontSize:16,color:C.muted,charSpacing:6,fontFace:FB,margin:0});
    s.addShape(pres.ShapeType.rect,{x:0.5,y:1.66,w:4.5,h:0.04,fill:{color:C.steel},line:{color:C.steel}});
    s.addText("OUR COMMITMENT",{x:0.5,y:1.86,w:6,h:0.3,fontSize:10,color:C.gold,bold:true,charSpacing:5,fontFace:FB,margin:0});
    s.addText("Safety is not a priority.",{x:0.5,y:2.26,w:8,h:0.82,fontSize:44,color:C.white,bold:true,fontFace:FH,margin:0});
    s.addText("It is a value.",{x:0.5,y:3.02,w:8,h:0.82,fontSize:44,color:C.teal,bold:true,fontFace:FH,margin:0});
    ["Maintain zero LTI performance through rigorous PTW compliance and daily site inspections.",
     "Close all open NCRs before next reporting period, with verified photo evidence.",
     "Achieve 100% TBT attendance across all shifts and subcontractors by next month.",
     "Conduct full emergency response drill before end of next quarter.",
    ].forEach((c,i)=>{
      const y=4.06+i*0.52;
      s.addShape(pres.ShapeType.ellipse,{x:0.5,y:y+0.08,w:0.26,h:0.26,fill:{color:C.teal},line:{color:C.teal}});
      s.addText(String(i+1),{x:0.5,y:y+0.08,w:0.26,h:0.26,fontSize:9,color:C.black,bold:true,align:"center",fontFace:FB,margin:0});
      s.addText(c,{x:0.86,y,w:7.2,h:0.46,fontSize:10.5,color:C.offwhite,fontFace:FB,margin:0});
    });
    s.addShape(pres.ShapeType.rect,{x:8.85,y:0.88,w:4.12,h:6.26,fill:{color:C.carbon},line:{color:C.teal,width:1.5}});
    s.addShape(pres.ShapeType.rect,{x:8.85,y:0.88,w:4.12,h:0.06,fill:{color:C.teal},line:{color:C.teal}});
    s.addText(month+" SNAPSHOT",{x:8.92,y:1.02,w:3.96,h:0.42,fontSize:11,color:C.teal,bold:true,align:"center",charSpacing:1,fontFace:FB,margin:0});
    s.addShape(pres.ShapeType.rect,{x:8.92,y:1.48,w:3.96,h:0.04,fill:{color:C.steel},line:{color:C.steel}});
    [{lbl:"Safe Man-Hours",val:mhProj.toLocaleString(),col:C.teal},
     {lbl:"Days Without LTI",val:String(daysLTI),col:C.green},
     {lbl:"Manpower",val:String(manpower),col:C.gold},
     {lbl:"TRIR",val:String(trir),col:C.teal},
     {lbl:"TBT Attendees",val:tbtAtt.toLocaleString(),col:C.white},
     {lbl:"Training Sessions",val:"12",col:C.gold},
     {lbl:"Total Observations",val:String(totalObs),col:C.green},
    ].forEach((f,i)=>{
      const y=1.62+i*0.72;
      s.addText(f.val,{x:8.92,y,w:3.96,h:0.44,fontSize:26,color:f.col,bold:true,align:"center",fontFace:FH,margin:0});
      s.addText(f.lbl,{x:8.92,y:y+0.44,w:3.96,h:0.22,fontSize:9,color:C.muted,align:"center",fontFace:FB,margin:0});
    });
  }

  const fileName="HSSE_Monthly_Performance_"+month.replace(/ /g,"_")+".pptx";
  await pres.writeFile({fileName});
  return fileName;
};

// ── MAIN APP ──────────────────────────────────────────────────────────────────
const MonthlyForSite = ({siteId, settingsKey, obs, ncr, C}) => {
  const INIT_STATE = {
    trend:DEFAULT_MONTHLY_TREND, summary:{welfare:"—",training:"—"},
    kpiItems:INIT_KPI_ITEMS, kpiTable:buildDefaultKpiTable(INIT_KPI_ITEMS),
    pciItems:INIT_PCI_ITEMS, pciTable:buildDefaultKpiTable(INIT_PCI_ITEMS),
  };
  const [ms,setMs] = useState(INIT_STATE);

  useEffect(()=>{
    const unsub=onSnapshot(doc(db,"settings",settingsKey),snap=>{
      if(snap.exists()&&snap.data?.()?.monthlyState){
        const d=snap.data().monthlyState;
        setMs({...INIT_STATE,...d,
          kpiTable:d.kpiTable||buildDefaultKpiTable(d.kpiItems||INIT_KPI_ITEMS),
          pciTable:d.pciTable||buildDefaultKpiTable(d.pciItems||INIT_PCI_ITEMS),
        });
      }
    });
    return()=>unsub();
  },[settingsKey]);

  const save=async(newState)=>{
    setMs(newState);
    await setDoc(doc(db,"settings",settingsKey),{monthlyState:newState},{merge:true});
  };

  return <Monthly obs={obs} ncr={ncr} monthlyState={ms} setMonthlyState={save} C={C}/>;
};

// ── SITE DASHBOARD — reusable for Site 1 & Site 2 ────────────────────────────
// Receives siteId ("Site 1" or "Site 2"), filters all data to that site,
// and renders a full HSSE dashboard with the same sections as the main app.
const SiteDashboard = ({siteId, userProfile, zones, obsTypes, actionsList, obsSeverity, ncrCats, ncrSeverity, ncrStatus, riskCats, riskStatus, equipStatus, mpStatus, risks, ltiResetDate, incidents=[], globalManualStats={}, C}) => {
  const site        = SITES.find(s=>s.id===siteId)||SITES[0];
  const siteIncidents = (incidents||[]).filter(i=>!i.site||i.site===siteId);
  const autoLTI     = ltiResetDate
    ? Math.floor((new Date()-new Date(ltiResetDate))/(1000*60*60*24))
    : null;
  const role        = ROLE_META[userProfile.role]||ROLE_META.viewer;
  const [activeTab,setActiveTab] = useState("overview");
  const [siteObs,setSiteObs]     = useState([]);
  const [siteNcr,setSiteNcr]     = useState([]);
  const [siteRisks,setSiteRisks] = useState([]);
  // eslint-disable-next-line no-unused-vars
  const [siteEquip,setSiteEquip] = useState([]);
  const [siteMp,setSiteMp]       = useState([]);
  const [siteStats,setSiteStats] = useState({daysLTI:0,manpower:0,manhoursWeek:0,manhoursMonth:0,manhoursYear:0,manhoursProject:0,safetyOfficers:0,firstAiders:0,tbtAttendees:0});
  const [editStats,setEditStats] = useState(false);
  const [draft,setDraft]         = useState({});
  const [saving,setSaving]       = useState(false);
  const [weeklyData,setSiteWeekly]   = useState(WEEKLY_DATA);
  const [welfareItems,setWelfareItems] = useState([
    {category:"Rest Facilities",score:88,status:"Good"},{category:"Potable Water",score:95,status:"Excellent"},
    {category:"Sanitation",score:82,status:"Good"},{category:"First Aid",score:91,status:"Excellent"},
    {category:"Mental Health",score:76,status:"Needs Attention"},{category:"Heat Stress Mgmt",score:84,status:"Good"},
  ]);
  const settingsKey = `site${site.prefix}Data`;

  // ── Live listeners filtered to this site ─────────────────────────────────
  useEffect(()=>{
    const unsubs=[
      // Server-side where() — only reads docs for this site (efficient + less billing)
      onSnapshot(query(collection(db,"observations"),where("site","==",siteId)),s=>setSiteObs(s.docs.map(d=>{const flat=d.data?.()||d;const raw=typeof flat.raw==="string"?JSON.parse(flat.raw||"{}"):flat.raw||{};return{...raw,...flat,_docId:d.id||d._docId||flat.id};}))),
      onSnapshot(query(collection(db,"ncr"),where("site","==",siteId)),s=>setSiteNcr(s.docs.map(d=>{const flat=d.data?.()||d;const raw=typeof flat.raw==="string"?JSON.parse(flat.raw||"{}"):flat.raw||{};return{...raw,...flat,_docId:d.id||d._docId||flat.id};}))),
      onSnapshot(collection(db,"risks"),s=>setSiteRisks(s.docs.map(d=>{const flat=d.data?.()||d;const raw=typeof flat.raw==="string"?JSON.parse(flat.raw||"{}"):flat.raw||{};return{...raw,...flat,_docId:d.id||d._docId||flat.id};}))), // risks not site-specific
      onSnapshot(query(collection(db,"equipment"),where("site","==",siteId)),s=>setSiteEquip(s.docs.map(d=>{const flat=d.data?.()||d;const raw=typeof flat.raw==="string"?JSON.parse(flat.raw||"{}"):flat.raw||{};return{...raw,...flat,_docId:d.id||d._docId||flat.id};}))),
      onSnapshot(query(collection(db,"manpower"),where("site","==",siteId)),s=>setSiteMp(s.docs.map(d=>{const flat=d.data?.()||d;const raw=typeof flat.raw==="string"?JSON.parse(flat.raw||"{}"):flat.raw||{};return{...raw,...flat,_docId:d.id||d._docId||flat.id};}))),
      onSnapshot(doc(db,"settings",settingsKey),snap=>{
        if(snap.exists()){
          const d=snap.data?.()??snap.data??{};
          if(d.stats)    setSiteStats(d.stats);
          if(d.weekly)   setSiteWeekly(d.weekly);
          if(d.welfare)  setWelfareItems(d.welfare);
        }
      }),
    ];
    return()=>unsubs.forEach(u=>u());
  },[siteId]);

  useEffect(()=>{if(!editStats)setDraft({...siteStats});},[siteStats,editStats]);

  const saveStats=async()=>{
    setSaving(true);
    try{
      await setDoc(doc(db,"settings",settingsKey),{stats:draft},{merge:true});
      setEditStats(false);
    }catch(e){
      console.error("[HSSE] saveStats failed:",e);
      try{ window.alert(`⚠️ Stats could not be saved: ${e?.message||"Unknown error"}`); }catch{}
    }finally{ setSaving(false); }
  };

  const saveWelfare=async(items)=>{
    setWelfareItems(items);
    try{
      await setDoc(doc(db,"settings",settingsKey),{welfare:items},{merge:true});
    }catch(e){
      console.error("[HSSE] saveWelfare failed:",e);
      try{ window.alert(`⚠️ Welfare could not be saved: ${e?.message||"Unknown error"}`); }catch{}
    }
  };

  const tabs=[
    {id:"overview",     label:"📊 Overview"},
    {id:"observations", label:"👁 Observations"},
    {id:"ncr",          label:"⚠️ NCR"},
    {id:"risk",         label:"🔺 Risk"},
    {id:"weekly",       label:"📋 Weekly"},
    {id:"monthly",      label:"📅 Monthly"},
    {id:"welfare",      label:"❤️ Welfare"},
    {id:"kpi",          label:"📈 KPI"},
  ];

  // Local KPI state for site dashboard
  const [siteKpis,setSiteKpis]         = useState(DEFAULT_KPI_DATA);
  const [siteRadarData,setSiteRadarData] = useState(DEFAULT_RADAR_DATA);

  const accent = siteId==="Site 1"?"#14b8a6":siteId==="Site 2"?"#8b5cf6":"#f97316";
  const grad   = siteId==="Site 1"?"linear-gradient(135deg,#0f4c3a,#065f46)":
                 siteId==="Site 2"?"linear-gradient(135deg,#4c1d95,#5b21b6)":
                                   "linear-gradient(135deg,#7c2d12,#9a3412)";

  // Fake user scoped to this site for sub-components
  const siteUser      = {...userProfile, site:siteId};

  // ── Strictly site-specific display stats ─────────────────────────────────
  // Each site's Project Statistics block MUST be independent: Palm1's numbers
  // must not leak into Palm2 or Site 3 and vice-versa. We only use the live
  // siteMp count as a fallback for the Manpower card (that is site-specific
  // data pulled from the per-site manpower table, not a global value).
  const gm = globalManualStats || {};
  const displayStats = {
    daysLTI:         Number(siteStats.daysLTI)         || 0,
    manpower:        Number(siteStats.manpower)        || (siteMp||[]).length || 0,
    manhoursWeek:    Number(siteStats.manhoursWeek)    || 0,
    manhoursMonth:   Number(siteStats.manhoursMonth)   || 0,
    manhoursYear:    Number(siteStats.manhoursYear)    || 0,
    manhoursProject: Number(siteStats.manhoursProject) || 0,
    safetyOfficers:  Number(siteStats.safetyOfficers)  || 0,
    firstAiders:     Number(siteStats.firstAiders)     || 0,
    tbtAttendees:    Number(siteStats.tbtAttendees)    || 0,
  };
  // prefillStats is ONLY used to pre-populate the Edit Stats form when the
  // admin opens it for the first time on a site that has no saved values.
  // It is never displayed on the dashboard.
  const prefillStats = {
    daysLTI:         Number(siteStats.daysLTI)         || Number(gm.daysLTI)         || 0,
    manpower:        Number(siteStats.manpower)        || Number(gm.manpower)        || (siteMp||[]).length || 0,
    manhoursWeek:    Number(siteStats.manhoursWeek)    || Number(gm.manhoursWeek)    || 0,
    manhoursMonth:   Number(siteStats.manhoursMonth)   || Number(gm.manhoursMonth)   || 0,
    manhoursYear:    Number(siteStats.manhoursYear)    || Number(gm.manhoursYear)    || 0,
    manhoursProject: Number(siteStats.manhoursProject) || Number(gm.manhoursProject) || 0,
    safetyOfficers:  Number(siteStats.safetyOfficers)  || Number(gm.safetyOfficers)  || 0,
    firstAiders:     Number(siteStats.firstAiders)     || Number(gm.firstAiders)     || 0,
    tbtAttendees:    Number(siteStats.tbtAttendees)    || Number(gm.tbtAttendees)    || 0,
  };
  // True when the site has no saved manual stats at all (ignoring the live
  // manpower count fallback which isn't a "manual" stat).
  const statsEmpty = !Object.entries(siteStats).some(
    ([k,v]) => k !== "manpower" && Number(v) > 0
  ) && !Number(siteStats.manpower);

  return(
    <div style={{display:"flex",flexDirection:"column",gap:16}}>

      {/* ── Banner ── */}
      <div style={{background:grad,borderRadius:14,padding:"18px 24px",display:"flex",justifyContent:"space-between",alignItems:"center",flexWrap:"wrap",gap:12}}>
        <div>
          <div style={{color:"#fff",fontWeight:900,fontSize:20}}>{site.name}</div>
          <div style={{color:"rgba(255,255,255,0.6)",fontSize:12,marginTop:3}}>{siteId} · Prefix {site.prefix} · HSSE Control Panel</div>
        </div>
        <div style={{display:"flex",gap:8,flexWrap:"wrap"}}>
          {[["Obs",(siteObs||[]).length],["Open",(siteObs||[]).filter(o=>o.status==="Open").length],["NCR",(siteNcr||[]).length],["Near Miss",(siteObs||[]).filter(o=>o.type==="Near Miss").length],["Manpower",(siteMp||[]).length]].map(([l,v])=>(
            <div key={l} style={{background:"rgba(255,255,255,0.13)",borderRadius:10,padding:"8px 12px",textAlign:"center",minWidth:54}}>
              <div style={{color:"#fff",fontSize:17,fontWeight:900}}>{v}</div>
              <div style={{color:"rgba(255,255,255,0.6)",fontSize:9,textTransform:"uppercase",letterSpacing:0.5}}>{l}</div>
            </div>
          ))}
        </div>
      </div>

      {/* ── Tabs ── */}
      <div style={{display:"flex",gap:4,flexWrap:"wrap"}}>
        {tabs.map(t=>(
          <button key={t.id} onClick={()=>setActiveTab(t.id)}
            style={{background:activeTab===t.id?accent+"33":"transparent",color:activeTab===t.id?accent:C.muted,
              border:`1px solid ${activeTab===t.id?accent+"55":C.border}`,borderRadius:8,
              padding:"7px 13px",fontWeight:activeTab===t.id?700:400,fontSize:12,cursor:"pointer"}}>
            {t.label}
          </button>
        ))}
      </div>

      {/* ══ OVERVIEW ══════════════════════════════════════════════════════════ */}
      {activeTab==="overview"&&(
        <div style={{display:"flex",flexDirection:"column",gap:14}}>
          <div style={{display:"flex",justifyContent:"flex-end",gap:8}}>
            {editStats
              ?<><Btn onClick={saveStats} color={C.green} disabled={saving}><Save size={13}/>{saving?"Saving...":"Save Stats"}</Btn>
                 <Btn onClick={()=>{setDraft({...displayStats});setEditStats(false);}} color={C.muted} style={{background:C.border}}>Cancel</Btn></>
              :<Btn onClick={()=>{setDraft(statsEmpty?{...prefillStats}:{...displayStats});setEditStats(true);}} color={C.blue}><Edit2 size={13}/>Edit Stats</Btn>}
          </div>
          {editStats&&(
            <div style={{background:C.card,border:`1px solid ${accent}44`,borderRadius:14,padding:18}}>
              <div style={{color:C.text,fontWeight:700,fontSize:13,marginBottom:12}}>📝 Edit {site.name} Manual Statistics</div>
              <ManualStatsEditor draft={draft} setDraft={setDraft} C={C} minWidth={180}/>
            </div>
          )}
          {/* Stat cards */}
          <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fit,minmax(155px,1fr))",gap:10}}>
            <StatBox label="Days Without LTI"   value={autoLTI!==null?autoLTI:(displayStats.daysLTI||0)}  color={C.green}  icon={CheckCircle2} sub={autoLTI!==null?"Auto-computed":(statsEmpty?"Not set — click Edit Stats":"Set in Dropdown Settings")} C={C}/>
            <StatBox label="Open Observations"  value={(siteObs||[]).filter(o=>o.status==="Open").length}       color={C.orange} icon={Eye}          sub="Live"          C={C}/>
            <StatBox label="Critical NCRs"      value={(siteNcr||[]).filter(n=>n.severity==="Critical").length} color={C.red}    icon={AlertOctagon} sub="Live"          C={C}/>
            <StatBox label="Near Misses"        value={(siteObs||[]).filter(o=>o.type==="Near Miss").length}    color={C.yellow} icon={AlertTriangle} sub="Live"         C={C}/>
            <StatBox label="Total Observations" value={(siteObs||[]).length}                                    color={C.teal}   icon={Eye}          sub="All time"      C={C}/>
            <StatBox label="NCRs Overdue"       value={(siteNcr||[]).filter(n=>n.status==="Overdue").length}    color={C.orange} icon={FileWarning}  sub="Live"          C={C}/>
          </div>
          {/* Manhours grid */}
          <div style={{background:C.card,border:`1px solid ${C.border}`,borderRadius:14,padding:18}}>
            <div style={{color:C.text,fontWeight:700,fontSize:14,marginBottom:12,display:"flex",alignItems:"center",flexWrap:"wrap",gap:6}}>
              <span>📋 {site.name} — Project Statistics</span>
              {statsEmpty && <span style={{color:C.muted,fontSize:11,fontWeight:500}}>(no site-specific stats yet — click "Edit Stats" to set values for this project)</span>}
            </div>
            <ProjectStatsGrid stats={displayStats} C={C} minWidth={185}/>
          </div>
          {/* Charts row */}
          <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fit,minmax(280px,1fr))",gap:14}}>
            <div style={{background:C.card,border:`1px solid ${C.border}`,borderRadius:14,padding:18}}>
              <div style={{color:C.text,fontWeight:700,marginBottom:12}}>Observation Breakdown</div>
              <ResponsiveContainer width="100%" height={190}>
                <PieChart>
                  <Pie data={[{name:"Open",value:(siteObs||[]).filter(o=>o.status==="Open").length||0},{name:"Closed",value:(siteObs||[]).filter(o=>o.status==="Closed").length||0},{name:"Under Review",value:(siteObs||[]).filter(o=>o.status==="Under Review").length||0}]}
                    cx="50%" cy="50%" innerRadius={45} outerRadius={70} dataKey="value" paddingAngle={4}>
                    {[C.red,C.green,C.blue].map((c,i)=><Cell key={i} fill={c}/>)}
                  </Pie>
                  <Tooltip contentStyle={chartTooltip(C)}/><Legend/>
                </PieChart>
              </ResponsiveContainer>
            </div>
            <div style={{background:C.card,border:`1px solid ${C.border}`,borderRadius:14,padding:18}}>
              <div style={{color:C.text,fontWeight:700,marginBottom:12}}>NCR by Severity</div>
              <ResponsiveContainer width="100%" height={190}>
                <BarChart data={[{name:"Critical",v:(siteNcr||[]).filter(n=>n.severity==="Critical").length},{name:"Major",v:(siteNcr||[]).filter(n=>n.severity==="Major").length},{name:"Minor",v:(siteNcr||[]).filter(n=>n.severity==="Minor").length}]}>
                  <CartesianGrid strokeDasharray="3 3" stroke={C.border}/>
                  <XAxis dataKey="name" tick={{fill:C.muted,fontSize:11}}/><YAxis tick={{fill:C.muted}}/>
                  <Tooltip contentStyle={chartTooltip(C)}/>
                  <Bar dataKey="v" radius={[4,4,0,0]}>{[C.red,C.orange,C.yellow].map((c,i)=><Cell key={i} fill={c}/>)}</Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>
        </div>
      )}

      {/* ══ OBSERVATIONS — reuse full Observations component ════════════════ */}
      {activeTab==="observations"&&(
        <Observations
          user={{...siteUser, uid:userProfile.uid}}
          obs={siteObs}
          zones={zones}
          obsTypes={obsTypes}
          actionsList={actionsList}
          obsSeverity={obsSeverity}
          C={C}
        />
      )}

      {/* ══ NCR — reuse full NCR component ══════════════════════════════════ */}
      {activeTab==="ncr"&&(
        <NCR user={siteUser} ncr={siteNcr} ncrCats={ncrCats} ncrSeverity={ncrSeverity} ncrStatus={ncrStatus} C={C}/>
      )}

      {/* ══ RISK — reuse full Risk component ════════════════════════════════ */}
      {activeTab==="risk"&&(
        <Risk user={siteUser} risks={siteRisks} riskCats={riskCats} riskStatus={riskStatus} C={C}/>
      )}

      {/* ══ WEEKLY REPORT — reuse full Weekly component ══════════════════════ */}
      {activeTab==="weekly"&&(
        <Weekly
          weeklyData={weeklyData}
          setWeeklyData={async(updated)=>{
            setSiteWeekly(updated);
            try{await setDoc(doc(db,"settings",settingsKey),{weekly:updated},{merge:true});}catch(e){console.error(e);}
          }}
          manualStats={siteStats}
          setManualStats={async(updated)=>{
            setSiteStats(updated);
            try{await setDoc(doc(db,"settings",settingsKey),{stats:updated},{merge:true});}catch(e){console.error(e);}
          }}
          incidents={siteIncidents}
          onAddIncident={async(data)=>{ try{ await fbAdd("incidents",{...data,site:siteId}); }catch(e){ console.error("[HSSE] addIncident:",e); throw e; } }}
          onDeleteIncident={async(docId)=>{ if(!docId)return; if(!window.confirm("Delete this incident?"))return; try{ await fbDelId("incidents",docId); }catch(e){ alert("Delete failed: "+e.message); } }}
          userRole={userProfile?.role||"viewer"}
          C={C}
        />
      )}

      {/* ══ MONTHLY MONITOR — reuse Monthly component ═══════════════════════ */}
      {activeTab==="monthly"&&(
        <MonthlyForSite siteId={siteId} settingsKey={settingsKey} obs={siteObs} ncr={siteNcr} C={C}/>
      )}

      {/* ══ WELFARE — reuse full Welfare component ═══════════════════════════ */}
      {activeTab==="welfare"&&(
        <Welfare
          welfareItems={welfareItems}
          setWelfareItems={saveWelfare}
          C={C}
        />
      )}

      {/* ══ KPI — reuse full KPIDashboard component ══════════════════════════ */}
      {activeTab==="kpi"&&(
        <KPIDashboard
          userRole={userProfile.role}
          kpis={siteKpis}
          setKpis={setSiteKpis}
          radarData={siteRadarData}
          setRadarData={setSiteRadarData}
          obs={siteObs}
          ncr={siteNcr}
          incidents={siteIncidents}
          manualStats={siteStats}
          C={C}
        />
      )}

    </div>
  );
};



// ── RESOURCES — Heavy Equipment + Operators & Manpower ───────────────────────
// Aligned to: Heavy_Equipment_Registry_Details_March__2026.xlsx
//             Al_Tamimi_Manpower_Log_March__2026.xlsx
const Resources = ({user,equipStatus=DEFAULT_EQUIP_STATUS,mpStatus=DEFAULT_MP_STATUS,C}) => {
  const role=ROLE_META[user.role];
  const [activeTab,setActiveTab]=useState("equipment");
  const [equipment,setEquipment]=useState([]);
  const [manpower,setManpower]=useState([]);
  const [loading,setLoading]=useState(true);
  const [showForm,setShowForm]=useState(false);
  const [uploading,setUploading]=useState(false);
  const [search,setSearch]=useState("");
  const [selectedEq,setSelectedEq]=useState([]);
  const [selectedMp,setSelectedMp]=useState([]);
  // Equipment filters
  const [filterEqType,setFilterEqType]=useState("");
  const [filterEqStatus,setFilterEqStatus]=useState("");
  const [filterEqSite,setFilterEqSite]=useState("");
  const [filterEqExpiry,setFilterEqExpiry]=useState("");
  const [filterEqCertExpiry,setFilterEqCertExpiry]=useState("");
  const [filterEqSagExpiry,setFilterEqSagExpiry]=useState("");
  const [filterEq3pExpiry,setFilterEq3pExpiry]=useState("");
  const [searchEqId,setSearchEqId]=useState("");
  const [searchOpId,setSearchOpId]=useState("");
  // Manpower filters
  const [filterMpNat,setFilterMpNat]=useState("");
  const [filterMpProf,setFilterMpProf]=useState("");
  const [filterMpSite,setFilterMpSite]=useState("");
  const [filterMpExpiry,setFilterMpExpiry]=useState("");

  useEffect(()=>{
    const unsubs=[
      onSnapshot(collection(db,"equipment"),s=>{
        setEquipment(s.docs.map(d=>{
          const flat = d.data?.()||d;
          const raw  = typeof flat.raw === "string" ? JSON.parse(flat.raw||"{}") : (flat.raw||{});
          return {...raw, ...flat, _docId:d.id||d._docId||flat.id};
        }));
        setLoading(false);
      }),
      onSnapshot(collection(db,"manpower"), s=>setManpower(s.docs.map(d=>{
        const flat = d.data?.()||d;
        const raw  = typeof flat.raw === "string" ? JSON.parse(flat.raw||"{}") : (flat.raw||{});
        return {...raw, ...flat, _docId:d.id||d._docId||flat.id};
      }))),
    ];
    return()=>unsubs.forEach(u=>u());
  },[]);

  // ── expiry badge helper ───────────────────────────────────────────────────
  const expiryBadge=(dateStr)=>{
    if(!dateStr||dateStr==="—")return null;
    const d=new Date(dateStr),now=new Date();
    const diff=Math.ceil((d-now)/(1000*60*60*24));
    if(diff<0) return{label:"Expired",  color:C.red};
    if(diff<=30)return{label:`${diff}d`,color:C.orange};
    return{label:"Valid",color:C.green};
  };
  const ExpiryBadge=({date})=>{const b=expiryBadge(date);return b?<Badge label={b.label} color={b.color}/>:null;};

  // ── Equipment form (includes operator data) ───────────────────────────────
  const EqForm=()=>{
    const [f,setF]=useState({
      sn:"", division:"The PALM Al Ahsa Project", contractor:"AlTamimi Contracting Co.",
      company:"Tamimi", equipType:"Dump Truck", equipNumber:"",
      certType:"", certInspectionDate:"", certExpiryDate:"", certRemarks:"Not Required",
      operatorName:"", sagLicense:"YES", sagLicenseExpiry:"", sagRemarks:"Valid",
      thirdPartyCertified:"NO", thirdPartyBy:"", thirdPartyCertNo:"", thirdPartyCertExpiry:"", thirdPartyRemarks:"",
      operatorIqama:"", site:"Site 1", status:"Active",
    });
    const set=(k,v)=>setF(p=>({...p,[k]:v}));
    const save=async()=>{
      if(!f.equipType||!f.equipNumber)return;
      await addDoc(collection(db,"equipment"),{...f,createdAt:new Date().toISOString(),createdBy:user.name});
      setShowForm(false);
    };
    const sectionHdr=(label,color)=>(
      <div style={{gridColumn:"1/-1",background:color+"22",border:`1px solid ${color}33`,borderRadius:8,padding:"6px 12px",fontSize:11,color,fontWeight:700,textTransform:"uppercase",letterSpacing:1,marginTop:6}}>{label}</div>
    );
    return(
      <Modal title="Add Heavy Equipment & Operator" onClose={()=>setShowForm(false)} C={C} wide={true}>
        <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:10}}>
          {sectionHdr("Equipment Details",C.teal)}
          <Field label="S/N" C={C}><Inp C={C} placeholder="1" value={f.sn} onChange={e=>set("sn",e.target.value)}/></Field>
          <Field label="Division / Project" C={C}><Sel C={C} value={f.division} onChange={e=>set("division",e.target.value)}>{["The PALM Al Ahsa Project","Palm2 Al-Madinah Project","Other"].map(s=><option key={s}>{s}</option>)}</Sel></Field>
          <Field label="Contractor" C={C}><Inp C={C} value={f.contractor} onChange={e=>set("contractor",e.target.value)}/></Field>
          <Field label="Company (Tamimi/Rental)" C={C}><Sel C={C} value={f.company} onChange={e=>set("company",e.target.value)}>{["Tamimi","Rental","Subcontractor"].map(s=><option key={s}>{s}</option>)}</Sel></Field>
          <Field label="Equipment Type" C={C}><Sel C={C} value={f.equipType} onChange={e=>set("equipType",e.target.value)}>{["Dump Truck","Excavator","Loader","Bulldozer","Crane","Tower Crane","Man Lift","Telehandler","Forklift","Grader","Piling Rig","Compressor","Generator","Concrete Mixer","Bobcat","Motor Grader","Roller","Water Tanker","Other"].map(s=><option key={s}>{s}</option>)}</Sel></Field>
          <Field label="Equipment Number (Plate / Body)" C={C}><Inp C={C} placeholder="Plate # XXXX / Body # XX-XX" value={f.equipNumber} onChange={e=>set("equipNumber",e.target.value)}/></Field>
          <Field label="Site" C={C}><Sel C={C} value={f.site} onChange={e=>set("site",e.target.value)}>{SITES.map(s=><option key={s.id} value={s.id}>{s.name}</option>)}</Sel></Field>
          <Field label="Status" C={C}><Sel C={C} value={f.status} onChange={e=>set("status",e.target.value)}>{equipStatus.map(s=><option key={s}>{s}</option>)}</Sel></Field>

          {sectionHdr("Equipment Sticker / Certification",C.blue)}
          <Field label="Cert. Type (BV / TUV / etc.)" C={C}><Inp C={C} value={f.certType} onChange={e=>set("certType",e.target.value)}/></Field>
          <Field label="Cert. Remarks" C={C}><Sel C={C} value={f.certRemarks} onChange={e=>set("certRemarks",e.target.value)}>{["Not Required","Valid","Expired","Pending"].map(s=><option key={s}>{s}</option>)}</Sel></Field>
          <Field label="Inspection Date" C={C}><Inp C={C} type="date" value={f.certInspectionDate} onChange={e=>set("certInspectionDate",e.target.value)}/></Field>
          <Field label="Cert. Expiry Date" C={C}><Inp C={C} type="date" value={f.certExpiryDate} onChange={e=>set("certExpiryDate",e.target.value)}/></Field>

          {sectionHdr("Operator Details",C.orange)}
          <Field label="Operator Name" C={C}><Inp C={C} value={f.operatorName} onChange={e=>set("operatorName",e.target.value)}/></Field>
          <Field label="Operator Iqama Number" C={C}><Inp C={C} value={f.operatorIqama} onChange={e=>set("operatorIqama",e.target.value)}/></Field>
          <Field label="Heavy SAG License" C={C}><Sel C={C} value={f.sagLicense} onChange={e=>set("sagLicense",e.target.value)}>{["YES","NO","N/A"].map(s=><option key={s}>{s}</option>)}</Sel></Field>
          <Field label="SAG License Expiry" C={C}><Inp C={C} type="date" value={f.sagLicenseExpiry} onChange={e=>set("sagLicenseExpiry",e.target.value)}/></Field>

          {sectionHdr("Third Party Certification",C.purple)}
          <Field label="Third Party Certified?" C={C}><Sel C={C} value={f.thirdPartyCertified} onChange={e=>set("thirdPartyCertified",e.target.value)}>{["YES","NO"].map(s=><option key={s}>{s}</option>)}</Sel></Field>
          <Field label="Third Party Company" C={C}><Inp C={C} placeholder="SPSP / TUV / Velosi / BV / Test" value={f.thirdPartyBy} onChange={e=>set("thirdPartyBy",e.target.value)}/></Field>
          <Field label="Third Party Cert #" C={C}><Inp C={C} value={f.thirdPartyCertNo} onChange={e=>set("thirdPartyCertNo",e.target.value)}/></Field>
          <Field label="Third Party Cert Expiry" C={C}><Inp C={C} type="date" value={f.thirdPartyCertExpiry} onChange={e=>set("thirdPartyCertExpiry",e.target.value)}/></Field>
        </div>
        <Btn onClick={save} color={C.teal} style={{marginTop:10,width:"100%",justifyContent:"center"}}>Add Equipment & Operator</Btn>
      </Modal>
    );
  };

  // ── Manpower form — aligned to Al_Tamimi_Manpower_Log ────────────────────
  const MpForm=()=>{
    const [f,setF]=useState({
      sn:"", name:"", contractorId:"", iqamaNumber:"",
      iqamaExpiry:"", nationality:"", age:"", iqamaProfession:"",
      site:"Site 1", status:"Active",
    });
    const set=(k,v)=>setF(p=>({...p,[k]:v}));
    const save=async()=>{
      if(!f.name||!f.iqamaNumber)return;
      await addDoc(collection(db,"manpower"),{...f,createdAt:new Date().toISOString(),createdBy:user.name});
      setShowForm(false);
    };
    return(
      <Modal title="Add Worker" onClose={()=>setShowForm(false)} C={C} wide={true}>
        <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:10}}>
          <Field label="S/N" C={C}><Inp C={C} type="number" value={f.sn} onChange={e=>set("sn",e.target.value)}/></Field>
          <Field label="Full Name" C={C}><Inp C={C} value={f.name} onChange={e=>set("name",e.target.value)}/></Field>
          <Field label="Contractor ID Number" C={C}><Inp C={C} value={f.contractorId} onChange={e=>set("contractorId",e.target.value)}/></Field>
          <Field label="ID / Iqama Number" C={C}><Inp C={C} value={f.iqamaNumber} onChange={e=>set("iqamaNumber",e.target.value)}/></Field>
          <Field label="Iqama Expiry Date" C={C}><Inp C={C} type="date" value={f.iqamaExpiry} onChange={e=>set("iqamaExpiry",e.target.value)}/></Field>
          <Field label="Nationality" C={C}><Inp C={C} value={f.nationality} onChange={e=>set("nationality",e.target.value)}/></Field>
          <Field label="Age" C={C}><Inp C={C} type="number" value={f.age} onChange={e=>set("age",e.target.value)}/></Field>
          <Field label="Iqama Profession" C={C}><Inp C={C} placeholder="e.g. Carpenter, Blacksmith" value={f.iqamaProfession} onChange={e=>set("iqamaProfession",e.target.value)}/></Field>
          <Field label="Site" C={C}><Sel C={C} value={f.site} onChange={e=>set("site",e.target.value)}>{SITES.map(s=><option key={s.id} value={s.id}>{s.name}</option>)}</Sel></Field>
          <Field label="Status" C={C}><Sel C={C} value={f.status} onChange={e=>set("status",e.target.value)}>{mpStatus.map(s=><option key={s}>{s}</option>)}</Sel></Field>
        </div>
        <Btn onClick={save} color={C.purple} style={{marginTop:10,width:"100%",justifyContent:"center"}}>Add Worker</Btn>
      </Modal>
    );
  };

  // ── Bulk Excel import — auto-maps columns by name ─────────────────────────
  // Safe date parser — handles Excel serial numbers, JS Date objects, strings, nulls
  const safeDate=(val)=>{
    if(!val||val===""||val==="nan")return "";
    try{
      // Excel stores dates as serial numbers (days since 1900-01-01)
      if(typeof val==="number"){
        // Excel serial: 1 = Jan 1 1900, adjust for leap year bug
        const d=new Date(Math.round((val-25569)*86400*1000));
        if(!isNaN(d.getTime()))return d.toISOString().split("T")[0];
      }
      const d=new Date(val);
      if(!isNaN(d.getTime()))return d.toISOString().split("T")[0];
      return "";
    }catch(e){return "";}
  };

  const handleBulkImport=async(e,target)=>{
    const file=e.target.files[0]; if(!file)return;
    setUploading(true);
    try{
      const XLSX=await import("xlsx");
      const buffer=await file.arrayBuffer();
      const wb=XLSX.read(buffer);
      const ws=wb.Sheets[wb.SheetNames[0]];

      if(target==="equipment"){
        // Equipment file has merged header rows — data starts at row 5 (index 4)
        const raw=XLSX.utils.sheet_to_json(ws,{header:1,defval:""});
        let saved=0;
        for(let i=4;i<raw.length;i++){
          const r=raw[i];
          const sn=String(r[0]||"").trim();
          if(!sn||isNaN(Number(sn)))continue; // skip non-data rows
          const equipType=String(r[4]||"").trim();
          if(!equipType)continue;
          const rec={
            sn, division:String(r[1]||"").trim(),
            contractor:String(r[2]||"").trim(),
            company:String(r[3]||"").trim(),
            equipType,
            equipNumber:String(r[5]||"").trim(),
            certType:String(r[6]||"").trim(),
            certInspectionDate:safeDate(r[7]),
            certExpiryDate:safeDate(r[8]),
            certRemarks:String(r[9]||"").trim(),
            operatorName:String(r[10]||"").trim(),
            sagLicense:String(r[11]||"").trim(),
            sagLicenseExpiry:safeDate(r[12]),
            sagRemarks:String(r[13]||"").trim(),
            thirdPartyCertified:String(r[14]||"").trim(),
            thirdPartyBy:String(r[15]||"").trim(),
            thirdPartyCertNo:String(r[16]||"").trim(),
            thirdPartyCertExpiry:safeDate(r[17]),
            thirdPartyRemarks:String(r[18]||"").trim(),
            operatorIqama:String(r[19]||"").trim(),
            site:"Site 1", status:"Active",
            importedAt:new Date().toISOString(), importedBy:user.name, source:"excel",
          };
          await addDoc(collection(db,"equipment"),rec);
          saved++;
        }
        alert(`✅ Imported ${saved} equipment/operator records!`);
      } else {
        // Manpower file: row 0 = labels desc, row 1 = actual data start
        // Columns: S, Name, Contractor ID Number, ID/Iqama Number, Expiry Date, Nationality, Age, Iqama Profession
        const raw=XLSX.utils.sheet_to_json(ws,{header:1,defval:""});
        let saved=0;
        for(let i=1;i<raw.length;i++){
          const r=raw[i];
          const sn=String(r[0]||"").trim();
          if(!sn||isNaN(Number(sn)))continue;
          const name=String(r[1]||"").trim();
          if(!name)continue;
          const expiry=safeDate(r[4]);
          // Age: stored as DOB serial or text — compute age or just store raw value
          let age="";
          if(r[6]){
            const dob=safeDate(r[6]);
            if(dob){const yr=parseInt(dob.slice(0,4));if(yr>1900&&yr<2020)age=String(new Date().getFullYear()-yr);}
            if(!age)age=String(r[6]).replace(/[\s:T].*/,"").trim();
          }
          const rec={
            sn, name,
            contractorId:String(r[2]||"").trim(),
            iqamaNumber:String(r[3]||"").trim(),
            iqamaExpiry:expiry,
            nationality:String(r[5]||"").trim(),
            age,
            iqamaProfession:String(r[7]||"").trim(),
            site:"Site 1", status:"Active",
            importedAt:new Date().toISOString(), importedBy:user.name, source:"excel",
          };
          await addDoc(collection(db,"manpower"),rec);
          saved++;
        }
        alert(`✅ Imported ${saved} manpower records!`);
      }
    }catch(err){console.error(err);alert("❌ Import failed: "+err.message);}
    finally{setUploading(false);e.target.value="";}
  };

  const tabs=[
    {id:"equipment",label:"🏗 Heavy Equipment & Operators",count:equipment.length,color:C.teal},
    {id:"manpower", label:"👥 Manpower Register",          count:manpower.length, color:C.purple},
  ];

  // Dynamic filter options from live data
  const eqTypes   =[...new Set(equipment.map(e=>e.equipType).filter(Boolean))].sort();
  // eslint-disable-next-line no-unused-vars
  const eqStatuses=[...new Set(equipment.map(e=>e.status||"Active").filter(Boolean))].sort();
  const mpNats    =[...new Set(manpower.map(m=>m.nationality).filter(Boolean))].sort();
  const mpProfs   =[...new Set(manpower.map(m=>m.iqamaProfession).filter(Boolean))].sort();

  // Clear filters helper
  const clearEqFilters=()=>{setSearch("");setFilterEqType("");setFilterEqStatus("");setFilterEqSite("");setFilterEqExpiry("");setFilterEqCertExpiry("");setFilterEqSagExpiry("");setFilterEq3pExpiry("");setSearchEqId("");setSearchOpId("");};
  const clearMpFilters=()=>{setSearch("");setFilterMpNat("");setFilterMpProf("");setFilterMpSite("");setFilterMpExpiry("");};
  const hasEqFilter=search||filterEqType||filterEqStatus||filterEqSite||filterEqExpiry||filterEqCertExpiry||filterEqSagExpiry||filterEq3pExpiry||searchEqId||searchOpId;
  const hasMpFilter=search||filterMpNat||filterMpProf||filterMpSite||filterMpExpiry;

  // Expiry alerts
  const today=new Date();
  const certExpiring=equipment.filter(e=>{if(!e.certExpiryDate)return false;const d=Math.ceil((new Date(e.certExpiryDate)-today)/(864e5));return d>=0&&d<=30;}).length;
  const sagExpiring =equipment.filter(e=>{if(!e.sagLicenseExpiry)return false;const d=Math.ceil((new Date(e.sagLicenseExpiry)-today)/(864e5));return d>=0&&d<=30;}).length;
  const iqamaExpiring=manpower.filter(m=>{if(!m.iqamaExpiry)return false;const d=Math.ceil((new Date(m.iqamaExpiry)-today)/(864e5));return d>=0&&d<=30;}).length;

  const today2=new Date();
  const isExpired=(d)=>d&&new Date(d)<today2;
  const isExpiring=(d)=>{if(!d)return false;const diff=Math.ceil((new Date(d)-today2)/(864e5));return diff>=0&&diff<=30;};
  const filtered_eq=equipment.filter(e=>{
    // General search
    if(search&&!(e.equipType+e.equipNumber+e.operatorName+e.division).toLowerCase().includes(search.toLowerCase()))return false;
    // Equipment ID search
    if(searchEqId&&!e.equipNumber?.toLowerCase().includes(searchEqId.toLowerCase()))return false;
    // Operator name/iqama search
    if(searchOpId&&!((e.operatorName||"")+" "+(e.operatorIqama||"")).toLowerCase().includes(searchOpId.toLowerCase()))return false;
    // Dropdowns
    if(filterEqType&&e.equipType!==filterEqType)return false;
    if(filterEqStatus&&(e.status||"Active")!==filterEqStatus)return false;
    if(filterEqSite&&e.site!==filterEqSite)return false;
    // Combined expiry (any cert)
    if(filterEqExpiry==="expired"&&!(isExpired(e.certExpiryDate)||isExpired(e.sagLicenseExpiry)||isExpired(e.thirdPartyCertExpiry)))return false;
    if(filterEqExpiry==="expiring"&&!(isExpiring(e.certExpiryDate)||isExpiring(e.sagLicenseExpiry)||isExpiring(e.thirdPartyCertExpiry)))return false;
    // Individual expiry filters
    if(filterEqCertExpiry==="expired"&&!isExpired(e.certExpiryDate))return false;
    if(filterEqCertExpiry==="expiring"&&!isExpiring(e.certExpiryDate))return false;
    if(filterEqCertExpiry==="valid"&&!(e.certExpiryDate&&!isExpired(e.certExpiryDate)&&!isExpiring(e.certExpiryDate)))return false;
    if(filterEqCertExpiry==="none"&&e.certExpiryDate)return false;
    if(filterEqSagExpiry==="expired"&&!isExpired(e.sagLicenseExpiry))return false;
    if(filterEqSagExpiry==="expiring"&&!isExpiring(e.sagLicenseExpiry))return false;
    if(filterEqSagExpiry==="valid"&&!(e.sagLicenseExpiry&&!isExpired(e.sagLicenseExpiry)&&!isExpiring(e.sagLicenseExpiry)))return false;
    if(filterEq3pExpiry==="expired"&&!isExpired(e.thirdPartyCertExpiry))return false;
    if(filterEq3pExpiry==="expiring"&&!isExpiring(e.thirdPartyCertExpiry))return false;
    if(filterEq3pExpiry==="valid"&&!(e.thirdPartyCertExpiry&&!isExpired(e.thirdPartyCertExpiry)&&!isExpiring(e.thirdPartyCertExpiry)))return false;
    if(filterEq3pExpiry==="none"&&e.thirdPartyCertExpiry)return false;
    return true;
  });
  const filtered_mp=manpower.filter(m=>{
    if(search&&!(m.name+m.iqamaNumber+m.iqamaProfession+m.nationality+m.contractorId).toLowerCase().includes(search.toLowerCase()))return false;
    if(filterMpNat&&m.nationality!==filterMpNat)return false;
    if(filterMpProf&&m.iqamaProfession!==filterMpProf)return false;
    if(filterMpSite&&m.site!==filterMpSite)return false;
    if(filterMpExpiry==="expired"&&!isExpired(m.iqamaExpiry))return false;
    if(filterMpExpiry==="expiring"&&!isExpiring(m.iqamaExpiry))return false;
    return true;
  });

  // ── Bulk select helpers ──────────────────────────────────────────────────
  const allEqSel=filtered_eq.length>0&&filtered_eq.every(e=>selectedEq.includes(e._docId));
  const allMpSel=filtered_mp.length>0&&filtered_mp.every(m=>selectedMp.includes(m._docId));
  // eslint-disable-next-line no-unused-vars
  const toggleAllEq=()=>setSelectedEq(allEqSel?[]:filtered_eq.map(e=>e._docId));
  // eslint-disable-next-line no-unused-vars
  const toggleAllMp=()=>setSelectedMp(allMpSel?[]:filtered_mp.map(m=>m._docId));
  // eslint-disable-next-line no-unused-vars
  const toggleOneEq=id=>setSelectedEq(p=>p.includes(id)?p.filter(x=>x!==id):[...p,id]);
  // eslint-disable-next-line no-unused-vars
  const toggleOneMp=id=>setSelectedMp(p=>p.includes(id)?p.filter(x=>x!==id):[...p,id]);
  const bulkDeleteEq=async()=>{
    if(!window.confirm(`Delete ${selectedEq.length} equipment record(s)?`))return;
    for(const id of selectedEq) await fbDelId("equipment",id);
    setSelectedEq([]);
  };
  const bulkDeleteMp=async()=>{
    if(!window.confirm(`Delete ${selectedMp.length} worker(s)?`))return;
    for(const id of selectedMp) await fbDelId("manpower",id);
    setSelectedMp([]);
  };

  return(
    <div style={{display:"flex",flexDirection:"column",gap:16}}>

      {/* Summary cards */}
      <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fit,minmax(140px,1fr))",gap:10}}>
        {[
          ["Equipment",    equipment.length, equipment.filter(e=>e.status==="Active").length,   C.teal],
          ["Operators",    equipment.filter(e=>e.operatorName).length, null,                    C.blue],
          ["Manpower",     manpower.length,  manpower.filter(m=>m.status==="Active").length,    C.purple],
          ["Cert Expiring",certExpiring+sagExpiring+iqamaExpiring, null,                        C.orange],
        ].map(([l,total,active,c])=>(
          <div key={l} style={{background:c+"22",border:`1px solid ${c}44`,borderRadius:10,padding:14,textAlign:"center"}}>
            <div style={{color:c,fontSize:22,fontWeight:900}}>{total}</div>
            <div style={{color:C.muted,fontSize:11}}>{l}</div>
            {active!=null&&<div style={{color:C.green,fontSize:10,marginTop:2}}>{active} active</div>}
          </div>
        ))}
      </div>

      {/* Tab + actions bar */}
      <div style={{display:"flex",gap:4,flexWrap:"wrap",alignItems:"center",justifyContent:"space-between"}}>
        <div style={{display:"flex",gap:4,flexWrap:"wrap"}}>
          {tabs.map(t=>(
            <button key={t.id} onClick={()=>{setActiveTab(t.id);setShowForm(false);setSearch("");setSelectedEq([]);setSelectedMp([]);clearEqFilters();clearMpFilters();}}
              style={{background:activeTab===t.id?t.color+"33":"transparent",color:activeTab===t.id?t.color:C.muted,border:`1px solid ${activeTab===t.id?t.color+"55":C.border}`,borderRadius:8,padding:"7px 14px",fontWeight:activeTab===t.id?700:400,fontSize:13,cursor:"pointer",display:"flex",alignItems:"center",gap:6}}>
              {t.label}<span style={{background:t.color+"22",color:t.color,fontSize:10,padding:"1px 6px",borderRadius:99,fontWeight:700}}>{t.count}</span>
            </button>
          ))}
        </div>
        <div style={{display:"flex",gap:6,flexWrap:"wrap",alignItems:"center"}}>
          {can(user,activeTab==="equipment"?"equipment":"manpower",user.site,"add")&&(
            <label style={{background:C.green,color:"#fff",borderRadius:8,padding:"6px 12px",fontWeight:700,fontSize:12,cursor:uploading?"not-allowed":"pointer",display:"flex",alignItems:"center",gap:5,opacity:uploading?0.6:1}}>
              <Download size={12}/>{uploading?"Importing...":"📥 Import Excel"}
              <input type="file" accept=".xlsx,.xls" onChange={e=>handleBulkImport(e,activeTab)} style={{display:"none"}} disabled={uploading}/>
            </label>
          )}
          <Btn onClick={()=>exportCSV(activeTab==="equipment"?equipment:manpower,activeTab)} color={C.indigo}><Download size={13}/>CSV</Btn>
          {can(user,activeTab==="equipment"?"equipment":"manpower",user.site,"add")&&<Btn onClick={()=>setShowForm(true)} color={activeTab==="equipment"?C.teal:C.purple}><Plus size={13}/>Add {activeTab==="equipment"?"Equipment":"Worker"}</Btn>}
        </div>
      </div>

      {showForm&&activeTab==="equipment"&&<EqForm/>}
      {showForm&&activeTab==="manpower"&&<MpForm/>}

      {/* ── Filter bars ── */}
      {activeTab==="equipment"&&(
        <div style={{background:C.card,border:`1px solid ${C.border}`,borderRadius:10,padding:"12px 14px",display:"flex",flexDirection:"column",gap:8}}>
          {/* Row 1 — text searches */}
          <div style={{display:"flex",gap:6,flexWrap:"wrap",alignItems:"center"}}>
            <Search size={13} style={{color:C.muted,flexShrink:0}}/>
            <input placeholder="Search equipment / operator..." value={search} onChange={e=>setSearch(e.target.value)}
              style={{background:C.bg,border:`1px solid ${search?C.teal:C.border}`,borderRadius:8,padding:"5px 10px",color:C.text,fontSize:12,outline:"none",minWidth:200,flex:1}}/>
            <input placeholder="Equipment No. / Plate..." value={searchEqId} onChange={e=>setSearchEqId(e.target.value)}
              style={{background:C.bg,border:`1px solid ${searchEqId?C.teal:C.border}`,borderRadius:8,padding:"5px 10px",color:C.text,fontSize:12,outline:"none",minWidth:170}}/>
            <input placeholder="Operator name / Iqama..." value={searchOpId} onChange={e=>setSearchOpId(e.target.value)}
              style={{background:C.bg,border:`1px solid ${searchOpId?C.orange:C.border}`,borderRadius:8,padding:"5px 10px",color:C.text,fontSize:12,outline:"none",minWidth:170}}/>
          </div>
          {/* Row 2 — dropdown filters */}
          <div style={{display:"flex",gap:6,flexWrap:"wrap",alignItems:"center"}}>
            {[
              [filterEqType,       setFilterEqType,       "All Types",    eqTypes,          C.teal  ],
              [filterEqStatus,     setFilterEqStatus,     "All Status",   equipStatus, C.teal],
              [filterEqSite,       setFilterEqSite,       "All Sites",    SITE_IDS,         C.teal  ],
            ].map(([val,setter,ph,opts,ac],i)=>(
              <select key={i} value={val} onChange={e=>setter(e.target.value)}
                style={{background:C.bg,border:`1px solid ${val?ac:C.border}`,borderRadius:8,padding:"5px 10px",color:val?ac:C.muted,fontSize:12,outline:"none",fontWeight:val?700:400}}>
                <option value="">{ph}</option>
                {opts.map(o=><option key={o} value={o}>{SITE_IDS.includes(o)?siteName(o):o}</option>)}
              </select>
            ))}
            <span style={{color:C.muted,fontSize:11,padding:"0 4px"}}>Expiry:</span>
            {[
              [filterEqCertExpiry, setFilterEqCertExpiry, "Cert",     C.blue  ],
              [filterEqSagExpiry,  setFilterEqSagExpiry,  "SAG Lic.", C.orange],
              [filterEq3pExpiry,   setFilterEq3pExpiry,   "3rd Party",C.purple],
            ].map(([val,setter,label,ac],i)=>(
              <select key={"exp"+i} value={val} onChange={e=>setter(e.target.value)}
                style={{background:C.bg,border:`1px solid ${val?ac:C.border}`,borderRadius:8,padding:"5px 10px",color:val?ac:C.muted,fontSize:12,outline:"none",fontWeight:val?700:400}}>
                <option value="">{label}: All</option>
                <option value="expired">Expired</option>
                <option value="expiring">Expiring ≤30d</option>
                <option value="valid">Valid</option>
                <option value="none">Not Required</option>
              </select>
            ))}
            {hasEqFilter&&<button onClick={clearEqFilters} style={{background:C.red+"22",border:`1px solid ${C.red}44`,color:C.red,borderRadius:8,padding:"5px 10px",fontSize:11,fontWeight:700,cursor:"pointer"}}>✕ Clear all</button>}
            <span style={{marginLeft:"auto",fontSize:11,color:C.muted,fontWeight:600}}>{filtered_eq.length} / {equipment.length} records</span>
          </div>
        </div>
      )}
      {activeTab==="manpower"&&(
        <div style={{display:"flex",gap:6,flexWrap:"wrap",alignItems:"center",background:C.card,border:`1px solid ${C.border}`,borderRadius:10,padding:"10px 14px"}}>
          <Search size={13} style={{color:C.muted,flexShrink:0}}/>
          {[
            [filterMpNat,    setFilterMpNat,    "All Nationalities", mpNats],
            [filterMpProf,   setFilterMpProf,   "All Professions",   mpProfs],
            [filterMpSite,   setFilterMpSite,   "All Sites",         SITE_IDS],
            [filterMpExpiry, setFilterMpExpiry, "All Expiry",        [{val:"expired",lbl:"Expired"},{val:"expiring",lbl:"Expiring ≤30d"}]],
          ].map(([val,setter,ph,opts],i)=>(
            <select key={i} value={val} onChange={e=>setter(e.target.value)}
              style={{background:C.bg,border:`1px solid ${val?C.purple:C.border}`,borderRadius:8,padding:"5px 10px",color:val?C.purple:C.muted,fontSize:12,outline:"none",fontWeight:val?700:400}}>
              <option value="">{ph}</option>
              {opts.map(o=>typeof o==="string"
                ? <option key={o} value={o}>{o==="Site 1"||o==="Site 2"||o==="Site 3"?siteName(o):o}</option>
                : <option key={o.val} value={o.val}>{o.lbl}</option>
              )}
            </select>
          ))}
          {hasMpFilter&&<button onClick={clearMpFilters} style={{background:C.red+"22",border:`1px solid ${C.red}44`,color:C.red,borderRadius:8,padding:"5px 10px",fontSize:11,fontWeight:700,cursor:"pointer"}}>✕ Clear</button>}
          <span style={{marginLeft:"auto",fontSize:11,color:C.muted}}>{filtered_mp.length} of {manpower.length}</span>
        </div>
      )}

      {/* ── Bulk action bars ── */}
      {selectedEq.length>0&&activeTab==="equipment"&&(
        <div style={{background:C.teal+"22",border:`1px solid ${C.teal}44`,borderRadius:10,padding:"10px 16px",display:"flex",alignItems:"center",gap:10,flexWrap:"wrap"}}>
          <span style={{color:C.teal,fontWeight:700,fontSize:13}}>{selectedEq.length} selected</span>
          {role.canDelete&&<Btn onClick={bulkDeleteEq} color={C.red} style={{padding:"6px 12px",fontSize:12}}><Trash2 size={13}/>Delete Selected</Btn>}
          <button onClick={()=>setSelectedEq([])} style={{background:"none",border:"none",color:C.muted,cursor:"pointer",fontSize:12}}>✕ Clear</button>
        </div>
      )}
      {selectedMp.length>0&&activeTab==="manpower"&&(
        <div style={{background:C.purple+"22",border:`1px solid ${C.purple}44`,borderRadius:10,padding:"10px 16px",display:"flex",alignItems:"center",gap:10,flexWrap:"wrap"}}>
          <span style={{color:C.purple,fontWeight:700,fontSize:13}}>{selectedMp.length} selected</span>
          {role.canDelete&&<Btn onClick={bulkDeleteMp} color={C.red} style={{padding:"6px 12px",fontSize:12}}><Trash2 size={13}/>Delete Selected</Btn>}
          <button onClick={()=>setSelectedMp([])} style={{background:"none",border:"none",color:C.muted,cursor:"pointer",fontSize:12}}>✕ Clear</button>
        </div>
      )}

      {/* ══ HEAVY EQUIPMENT TABLE ══ */}
      {activeTab==="equipment"&&(
        <TableCard title={`Heavy Equipment & Operators (${filtered_eq.length})`} C={C}>
          <div style={{overflowX:"auto"}}>
            <table style={{width:"100%",borderCollapse:"collapse",minWidth:1200}}>
              <thead>
                <tr style={{background:C.bg}}>
                  <Th C={C} style={{width:36}}></Th>
                  <Th C={C} style={{background:C.teal+"22"}} colSpan={5}>Equipment Details</Th>
                  <Th C={C} style={{background:C.blue+"22"}} colSpan={3}>Equipment Certification</Th>
                  <Th C={C} style={{background:C.orange+"22"}} colSpan={4}>Operator</Th>
                  <Th C={C} style={{background:C.purple+"22"}} colSpan={3}>Third Party Cert.</Th>
                  <Th C={C}></Th>
                </tr>
                <tr>
                  <Th C={C} style={{width:36}}><input type="checkbox" checked={allEqSel} onChange={toggleAllEq} style={{accentColor:C.teal,width:14,height:14,cursor:"pointer"}}/></Th>
                  {/* Equipment */}
                  <Th C={C}>S/N</Th><Th C={C}>Division</Th><Th C={C}>Company</Th><Th C={C}>Type</Th><Th C={C}>Equip. No.</Th>
                  {/* Cert */}
                  <Th C={C}>Cert Type</Th><Th C={C}>Insp. Date</Th><Th C={C}>Cert Expiry</Th>
                  {/* Operator */}
                  <Th C={C}>Operator Name</Th><Th C={C}>Iqama No.</Th><Th C={C}>SAG License</Th><Th C={C}>SAG Expiry</Th>
                  {/* 3rd party */}
                  <Th C={C}>3rd Party</Th><Th C={C}>By</Th><Th C={C}>3P Expiry</Th>
                  <Th C={C}></Th>
                </tr>
              </thead>
              <tbody>
                {filtered_eq.map(e=>{
                  const certEx=expiryBadge(e.certExpiryDate);
                  const sagEx=expiryBadge(e.sagLicenseExpiry);
                  const tpEx=expiryBadge(e.thirdPartyCertExpiry);
                  const rowAlert=certEx?.label==="Expired"||sagEx?.label==="Expired"||tpEx?.label==="Expired";
                  const isSelEq=selectedEq.includes(e._docId);
                  return(
                    <tr key={e._docId}
                      style={{background:isSelEq?C.teal+"18":rowAlert?C.red+"09":"transparent"}}
                      onMouseEnter={ev=>{if(!isSelEq)ev.currentTarget.style.background=C.border+"33";}}
                      onMouseLeave={ev=>{ev.currentTarget.style.background=isSelEq?C.teal+"18":rowAlert?C.red+"09":"transparent";}}>
                      <Td C={C}><input type="checkbox" checked={isSelEq} onChange={()=>toggleOneEq(e._docId)} style={{accentColor:C.teal,width:14,height:14,cursor:"pointer"}}/></Td>
                      <Td C={C} style={{color:C.muted,fontSize:11}}>{e.sn}</Td>
                      <Td C={C} style={{fontSize:11,maxWidth:120,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>{e.division}</Td>
                      <Td C={C}><Badge label={e.company||"Tamimi"} color={e.company==="Rental"?C.orange:C.teal}/></Td>
                      <Td C={C} style={{color:C.text,fontWeight:600}}>{e.equipType}</Td>
                      <Td C={C} style={{fontFamily:"monospace",fontSize:11,color:C.teal}}>{e.equipNumber}</Td>
                      <Td C={C}>{e.certType||<span style={{color:C.muted}}>—</span>}</Td>
                      <Td C={C}>{e.certInspectionDate||"—"}</Td>
                      <Td C={C}>
                        {e.certExpiryDate?<><span style={{fontSize:11}}>{e.certExpiryDate}</span> <ExpiryBadge date={e.certExpiryDate}/></>
                        :<Badge label={e.certRemarks||"Not Required"} color={e.certRemarks==="Not Required"?C.muted:e.certRemarks==="Expired"?C.red:C.green}/>}
                      </Td>
                      <Td C={C} style={{color:C.text,fontWeight:600}}>{e.operatorName||<span style={{color:C.muted}}>—</span>}</Td>
                      <Td C={C} style={{fontFamily:"monospace",fontSize:11}}>{e.operatorIqama||"—"}</Td>
                      <Td C={C}><Badge label={e.sagLicense||"—"} color={e.sagLicense==="YES"?C.green:e.sagLicense==="NO"?C.red:C.muted}/></Td>
                      <Td C={C}>
                        {e.sagLicenseExpiry?<><span style={{fontSize:11}}>{e.sagLicenseExpiry}</span> <ExpiryBadge date={e.sagLicenseExpiry}/></>:"—"}
                      </Td>
                      <Td C={C}><Badge label={e.thirdPartyCertified||"NO"} color={e.thirdPartyCertified==="YES"?C.green:C.muted}/></Td>
                      <Td C={C} style={{fontSize:11}}>{e.thirdPartyBy||"—"}</Td>
                      <Td C={C}>
                        {e.thirdPartyCertExpiry?<><span style={{fontSize:11}}>{e.thirdPartyCertExpiry}</span> <ExpiryBadge date={e.thirdPartyCertExpiry}/></>:"—"}
                      </Td>
                      <Td C={C}>{role.canDelete&&<button onClick={()=>fbDelId("equipment",e._docId)} style={{background:"none",border:"none",cursor:"pointer",color:C.muted}}><Trash2 size={13}/></button>}</Td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </TableCard>
      )}

      {/* ══ MANPOWER TABLE ══ */}
      {activeTab==="manpower"&&(
        <TableCard title={`Manpower Register (${filtered_mp.length})`} C={C}>
          <div style={{overflowX:"auto"}}>
            <table style={{width:"100%",borderCollapse:"collapse",minWidth:900}}>
              <thead><tr>
                <Th C={C} style={{width:36}}><input type="checkbox" checked={allMpSel} onChange={toggleAllMp} style={{accentColor:C.purple,width:14,height:14,cursor:"pointer"}}/></Th>
                {["S/N","Name","Contractor ID","Iqama Number","Iqama Expiry","Nationality","Age","Iqama Profession","Site","Status",""].map(h=><Th key={h} C={C}>{h}</Th>)}
              </tr></thead>
              <tbody>
                {filtered_mp.map(m=>{
                  const iqEx=expiryBadge(m.iqamaExpiry);
                  const rowAlert=iqEx?.label==="Expired";
                  const isSelMp=selectedMp.includes(m._docId);
                  return(
                    <tr key={m._docId}
                      style={{background:isSelMp?C.purple+"18":rowAlert?C.red+"09":"transparent"}}
                      onMouseEnter={ev=>{if(!isSelMp)ev.currentTarget.style.background=C.border+"33";}}
                      onMouseLeave={ev=>{ev.currentTarget.style.background=isSelMp?C.purple+"18":rowAlert?C.red+"09":"transparent";}}>
                      <Td C={C}><input type="checkbox" checked={isSelMp} onChange={()=>toggleOneMp(m._docId)} style={{accentColor:C.purple,width:14,height:14,cursor:"pointer"}}/></Td>
                      <Td C={C} style={{color:C.muted,fontSize:11}}>{m.sn}</Td>
                      <Td C={C} style={{color:C.text,fontWeight:600}}>{m.name}</Td>
                      <Td C={C} style={{fontFamily:"monospace",fontSize:11}}>{m.contractorId}</Td>
                      <Td C={C} style={{fontFamily:"monospace",fontSize:11}}>{m.iqamaNumber}</Td>
                      <Td C={C}>
                        {m.iqamaExpiry?<><span style={{color:iqEx?.color||C.sub,fontSize:11,fontWeight:600}}>{m.iqamaExpiry}</span> <ExpiryBadge date={m.iqamaExpiry}/></>:"—"}
                      </Td>
                      <Td C={C}>{m.nationality}</Td>
                      <Td C={C}>{m.age}</Td>
                      <Td C={C}><Badge label={m.iqamaProfession||"—"} color={C.blue}/></Td>
                      <Td C={C}>{siteName(m.site)||m.site||"Site 1"}</Td>
                      <Td C={C}><Badge label={m.status||"Active"} color={m.status==="Active"?C.green:m.status==="On Leave"?C.orange:C.red}/></Td>
                      <Td C={C}>{role.canDelete&&<button onClick={()=>fbDelId("manpower",m._docId)} style={{background:"none",border:"none",cursor:"pointer",color:C.muted}}><Trash2 size={13}/></button>}</Td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </TableCard>
      )}
    </div>
  );
};

// ── EMAIL ALERTS ─────────────────────────────────────────────────────────────
const EmailAlerts = ({obs, ncr, equipment, manpower, firestoreUsers, weeklyData, monthlyState, C}) => {
  const today = new Date();

  const diffDays = (dateStr) => {
    if(!dateStr||dateStr==="—") return null;
    const d = new Date(dateStr);
    if(isNaN(d)) return null;
    return Math.ceil((d - today) / (1000*60*60*24));
  };

  // ── localStorage fallback for EmailJS config ──────────────────────────────
  // We persist a copy of the config locally as a safety net. If the Neon write
  // ever fails silently (network blip, permission issue, cold-start timeout),
  // the user still has their credentials on next page load and does NOT have
  // to re-enter them. The localStorage copy and the DB copy are kept in sync.
  const EJS_LS_KEY = "hsse_emailjs_cfg";
  const loadCfgFromLocal = () => {
    try {
      const raw = localStorage.getItem(EJS_LS_KEY);
      if (!raw) return null;
      const v = JSON.parse(raw);
      // Only trust the local copy if it has the three required fields
      if (v && v.serviceId && v.templateId && v.publicKey) return v;
      return null;
    } catch { return null; }
  };
  const saveCfgToLocal = (cfg) => {
    try { localStorage.setItem(EJS_LS_KEY, JSON.stringify(cfg)); } catch {}
  };
  const initLocal = loadCfgFromLocal();
  // ── State ─────────────────────────────────────────────────────────────────
  const [ejsConfig,setEjsConfig]     = useState(initLocal || {serviceId:"",templateId:"",publicKey:"",expiryDays:30});
  const [savedCfg,setSavedCfg]       = useState(initLocal || null);
  const [editCfg,setEditCfg]         = useState(false);
  const [cfgSaveError,setCfgSaveError] = useState(null);
  const [cfgSaving,setCfgSaving]       = useState(false);
  // eslint-disable-next-line no-unused-vars
  const [sending,setSending]         = useState(false);
  const [sendingId,setSendingId]     = useState(null);
  const [sendResult,setSendResult]   = useState(null);
  const [selectedAlerts,setSelected] = useState([]);
  const [filterCat,setFilterCat]     = useState("");
  const [filterSev,setFilterSev]     = useState("");
  // eslint-disable-next-line no-unused-vars
  const [cfgLoading,setCfgLoading]   = useState(true);
  // Recipient list — stored as array of {id, name, email, role, active}
  const [recipientList,setRecipientList] = useState([]);
  const [newRecip,setNewRecip]           = useState({name:"",email:"",role:""});
  const [editRecipId,setEditRecipId]     = useState(null);
  const [editRecipData,setEditRecipData] = useState({});

  // Weekly digest state
  const [lastSent,setLastSent]           = useState(null);
  const [sendingDigest,setSendingDigest] = useState(false);
  const [digestResult,setDigestResult]   = useState(null);
  const [previewOpen,setPreviewOpen]     = useState(false);

  // ── Load EmailJS config from Neon (live) ─────────────────────────────────
  // The DB listener polls every 15 seconds. We MUST NOT let that poll touch
  // the form's ejsConfig state while the user is typing — otherwise their
  // in-progress input gets wiped when the next poll returns an empty/partial
  // row from the DB. Rules:
  //   1. Populate ejsConfig from the DB exactly once, on the first snapshot,
  //      and only if localStorage didn't already pre-fill the form.
  //   2. savedCfg (the "is it ready?" signal) can be updated on every poll —
  //      that doesn't interfere with the form inputs.
  //   3. When the user clicks Save, saveCfg() writes to ejsConfig locally so
  //      no further DB->form sync is ever needed.
  const hasPopulatedFormFromDB = useRef(false);
  useEffect(()=>{
    const unsub = onSnapshot(doc(db,"settings","emailAlerts"), snap=>{
      if(snap.exists()){
        const d = snap.data();
        setSavedCfg(prev => ({...(prev||{}), ...d}));
        // FIRST snapshot only — and only if no localStorage pre-fill happened.
        // Any later poll must leave ejsConfig alone so typing isn't clobbered.
        if (!hasPopulatedFormFromDB.current) {
          hasPopulatedFormFromDB.current = true;
          if (!initLocal) {
            setEjsConfig({
              serviceId:  d.serviceId  || "",
              templateId: d.templateId || "",
              publicKey:  d.publicKey  || "",
              expiryDays: d.expiryDays || 30,
            });
          }
        }
        if(d.recipientList) setRecipientList(d.recipientList);
        if(d.lastSent) setLastSent(d.lastSent);
        // Keep localStorage in sync with DB so the two never diverge
        if (d.serviceId && d.templateId && d.publicKey) {
          saveCfgToLocal({
            serviceId:  d.serviceId,
            templateId: d.templateId,
            publicKey:  d.publicKey,
            expiryDays: d.expiryDays || 30,
          });
        }
      } else {
        // No DB row yet — first-snapshot "done" so future polls also skip.
        hasPopulatedFormFromDB.current = true;
      }
      setCfgLoading(false);
    });
    return()=>unsub();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  },[]);

  const saveCfg = async () => {
    // Validate before saving — don't let the user save an incomplete config
    if (!ejsConfig.serviceId || !ejsConfig.templateId || !ejsConfig.publicKey) {
      setCfgSaveError("Please fill in Service ID, Template ID, and Public Key before saving.");
      return;
    }
    setCfgSaving(true);
    setCfgSaveError(null);
    const data = {...ejsConfig, recipientList};
    // Step 1 — write to localStorage immediately (synchronous, can't fail).
    // This is the safety net: even if the DB write fails, the credentials
    // persist on this browser across refreshes.
    saveCfgToLocal({
      serviceId:  ejsConfig.serviceId,
      templateId: ejsConfig.templateId,
      publicKey:  ejsConfig.publicKey,
      expiryDays: ejsConfig.expiryDays || 30,
    });
    // Step 2 — try to write to Neon. If this fails, we surface the error but
    // we do NOT roll back the local save — the user's credentials survive.
    try {
      await setDoc(doc(db,"settings","emailAlerts"), data, {merge:true});
      setSavedCfg(data);
      setEditCfg(false);
    } catch (e) {
      // DB write failed — tell the user, but leave the form open so they can
      // retry. Local copy has already been saved, so even a refresh won't
      // lose their input.
      console.error("[HSSE] EmailJS config save failed:", e);
      setSavedCfg(data); // treat as saved locally
      setCfgSaveError(
        `Saved locally on this browser, but the server copy failed: ${e.message}. ` +
        `Your credentials will still work here — retry later to sync to other browsers.`
      );
    } finally {
      setCfgSaving(false);
    }
  };

  const saveRecipients = async (list) => {
    setRecipientList(list);
    await setDoc(doc(db,"settings","emailAlerts"), {recipientList:list}, {merge:true});
  };

  const addRecipient = async () => {
    if(!newRecip.email||!newRecip.name) return;
    const id = Date.now().toString();
    const updated = [...recipientList, {...newRecip, id, active:true}];
    setNewRecip({name:"",email:"",role:""});
    await saveRecipients(updated);
  };

  const removeRecipient = async (id) => {
    if(!window.confirm("Remove this recipient?")) return;
    await saveRecipients(recipientList.filter(r=>r.id!==id));
  };

  const toggleRecipient = async (id) => {
    await saveRecipients(recipientList.map(r=>r.id===id?{...r,active:!r.active}:r));
  };

  const startEditRecip = (r) => { setEditRecipId(r.id); setEditRecipData({name:r.name,email:r.email,role:r.role}); };
  const saveEditRecip  = async () => {
    await saveRecipients(recipientList.map(r=>r.id===editRecipId?{...r,...editRecipData}:r));
    setEditRecipId(null);
  };

  const isReady     = savedCfg?.serviceId && savedCfg?.templateId && savedCfg?.publicKey;
  const activeRecips = recipientList.filter(r=>r.active!==false);
  const expWin  = parseInt(savedCfg?.expiryDays||30);

  // ── Build alert items ─────────────────────────────────────────────────────
  // Helper: look up user email by name
  const emailOf = (name) => {
    if(!name||name==="—") return null;
    const u = firestoreUsers.find(u=>(u.name||"").toLowerCase()===name.toLowerCase());
    return u?.email||null;
  };

  const allAlerts = [
    // Critical open NCRs
    ...ncr
      .filter(n=>n.severity==="Critical" && n.status!=="Closed")
      .map(n=>({
        id:n._docId, category:"NCR", severity:"Critical", color:C.red,
        title:`Critical NCR — ${n.id}`,
        detail:`${n.category||""}${n.desc?` · ${n.desc.slice(0,90)}`:""}`,
        due:n.due||"", daysLeft:diffDays(n.due),
        assignee:n.assignee||"—", assigneeEmail:emailOf(n.assignee),
        site:n.site||"", key:`ncr-crit-${n._docId}`,
      })),
    // Overdue NCRs (status=Overdue OR past due date and not closed)
    ...ncr
      .filter(n=>n.status==="Overdue"||(n.status!=="Closed"&&n.due&&diffDays(n.due)<0))
      .filter(n=>n.severity!=="Critical") // avoid duplicates
      .map(n=>({
        id:n._docId, category:"NCR", severity:"Overdue", color:C.orange,
        title:`Overdue NCR — ${n.id}`,
        detail:`Due ${n.due} · Assignee: ${n.assignee||"—"}`,
        due:n.due||"", daysLeft:diffDays(n.due),
        assignee:n.assignee||"—", assigneeEmail:emailOf(n.assignee),
        site:n.site||"", key:`ncr-ovd-${n._docId}`,
      })),
    // NCRs due within expiry window (not yet overdue, not closed)
    ...ncr
      .filter(n=>n.status!=="Closed"&&n.due&&diffDays(n.due)!==null&&diffDays(n.due)>=0&&diffDays(n.due)<=expWin&&n.severity!=="Critical")
      .map(n=>({
        id:n._docId+"_due", category:"NCR", severity:"Due Soon", color:C.yellow,
        title:`NCR Due in ${diffDays(n.due)}d — ${n.id}`,
        detail:`${n.category||""} · Closure: ${n.closure||0}%`,
        due:n.due||"", daysLeft:diffDays(n.due),
        assignee:n.assignee||"—", assigneeEmail:emailOf(n.assignee),
        site:n.site||"", key:`ncr-due-${n._docId}`,
      })),
    // High severity open observations
    ...obs
      .filter(o=>o.severity==="High" && o.status==="Open")
      .map(o=>({
        id:o._docId, category:"Observation", severity:"High", color:C.orange,
        title:`High Severity Obs — ${o.id}`,
        detail:`${o.area||""} · ${(o.desc||"").slice(0,80)}`,
        due:"", daysLeft:null,
        assignee:o.observer||"—", assigneeEmail:emailOf(o.observer),
        site:o.site||"", key:`obs-${o._docId}`,
      })),
    // Equipment cert expiry
    ...equipment
      .filter(e=>e.certExpiryDate&&diffDays(e.certExpiryDate)!==null&&diffDays(e.certExpiryDate)<=expWin)
      .map(e=>{const d=diffDays(e.certExpiryDate);return{
        id:e._docId+"_cert", category:"Equip. Cert", severity:d<0?"Expired":"Expiring", color:d<0?C.red:C.orange,
        title:`Equip. Cert ${d<0?"Expired":"Expiring"} — ${e.equipNumber||e.equipType}`,
        detail:`Type: ${e.equipType} · Cert Expiry: ${e.certExpiryDate}${d>=0?` (${d}d left)`:" (EXPIRED)"}`,
        due:e.certExpiryDate, daysLeft:d,
        assignee:e.operatorName||"—", assigneeEmail:emailOf(e.operatorName),
        site:e.site||"", key:`eq-cert-${e._docId}`,
      };}),
    // SAG License expiry
    ...equipment
      .filter(e=>e.sagLicenseExpiry&&e.sagLicense==="YES"&&diffDays(e.sagLicenseExpiry)!==null&&diffDays(e.sagLicenseExpiry)<=expWin)
      .map(e=>{const d=diffDays(e.sagLicenseExpiry);return{
        id:e._docId+"_sag", category:"SAG License", severity:d<0?"Expired":"Expiring", color:d<0?C.red:C.orange,
        title:`SAG License ${d<0?"Expired":"Expiring"} — ${e.operatorName||"Unknown"}`,
        detail:`Equipment: ${e.equipNumber||e.equipType} · SAG Expiry: ${e.sagLicenseExpiry}${d>=0?` (${d}d left)`:" (EXPIRED)"}`,
        due:e.sagLicenseExpiry, daysLeft:d,
        assignee:e.operatorName||"—", assigneeEmail:emailOf(e.operatorName),
        site:e.site||"", key:`eq-sag-${e._docId}`,
      };}),
    // 3rd party cert expiry
    ...equipment
      .filter(e=>e.thirdPartyCertExpiry&&e.thirdPartyCertified==="YES"&&diffDays(e.thirdPartyCertExpiry)!==null&&diffDays(e.thirdPartyCertExpiry)<=expWin)
      .map(e=>{const d=diffDays(e.thirdPartyCertExpiry);return{
        id:e._docId+"_3p", category:"3rd Party Cert", severity:d<0?"Expired":"Expiring", color:d<0?C.red:C.orange,
        title:`3P Cert ${d<0?"Expired":"Expiring"} — ${e.equipNumber||e.equipType}`,
        detail:`By: ${e.thirdPartyBy||"—"} · Expiry: ${e.thirdPartyCertExpiry}${d>=0?` (${d}d left)`:" (EXPIRED)"}`,
        due:e.thirdPartyCertExpiry, daysLeft:d,
        assignee:e.operatorName||"—", assigneeEmail:emailOf(e.operatorName),
        site:e.site||"", key:`eq-3p-${e._docId}`,
      };}),
    // Manpower Iqama expiry
    ...manpower
      .filter(m=>m.iqamaExpiry&&diffDays(m.iqamaExpiry)!==null&&diffDays(m.iqamaExpiry)<=expWin)
      .map(m=>{const d=diffDays(m.iqamaExpiry);return{
        id:m._docId+"_iq", category:"Iqama Expiry", severity:d<0?"Expired":"Expiring", color:d<0?C.red:C.orange,
        title:`Iqama ${d<0?"Expired":"Expiring"} — ${m.name}`,
        detail:`Iqama: ${m.iqamaNumber||"—"} · Profession: ${m.iqamaProfession||"—"} · Expiry: ${m.iqamaExpiry}${d>=0?` (${d}d left)`:" (EXPIRED)"}`,
        due:m.iqamaExpiry, daysLeft:d,
        assignee:m.name||"—", assigneeEmail:null,
        site:m.site||"", key:`mp-${m._docId}`,
      };}),

    // ── Observation closeout overdue (open > 7 days with no action) ──────────
    ...obs
      .filter(o=>{
        if(o.status==="Closed") return false;
        if(!o.date) return false;
        const daysOpen = -diffDays(o.date); // negative diffDays = days in the past
        return daysOpen>7;
      })
      .map(o=>{
        const daysOpen = -diffDays(o.date);
        const isCritical = o.severity==="High"||o.severity==="Critical";
        return{
          id:o._docId+"_cls", category:"Obs Closeout", severity:daysOpen>30?"Overdue":isCritical?"Critical":"Pending", color:daysOpen>30?C.red:isCritical?C.orange:C.yellow,
          title:`Obs Not Closed — ${o.id}`,
          detail:`${o.severity} severity · ${o.area||""} · Open for ${daysOpen} days · ${(o.desc||"").slice(0,60)}`,
          due:o.date, daysLeft:-daysOpen,
          assignee:o.observer||"—", assigneeEmail:emailOf(o.observer),
          site:o.site||"", key:`obs-cls-${o._docId}`,
        };
      }),

    // ── Weekly report late (current week not yet uploaded/updated) ───────────
    ...(()=>{
      const alerts=[];
      const wd = weeklyData;
      if(!wd) return alerts;
      // Check if weekly report is stale — dateTo is more than 10 days ago
      const dateToStr = wd.dateTo;
      if(dateToStr){
        // Parse "Apr 02, 2026" style
        const parsed = new Date(dateToStr);
        if(!isNaN(parsed)){
          const daysSince = -diffDays(parsed.toISOString().split("T")[0]);
          if(daysSince>10){
            alerts.push({
              id:"weekly-late", category:"Weekly Report", severity:daysSince>21?"Overdue":"Late", color:daysSince>21?C.red:C.orange,
              title:`Weekly Report Not Updated — ${daysSince}d since last upload`,
              detail:`Last report: Week ${wd.weekNo||"?"} (${wd.dateFrom||"?"} – ${wd.dateTo||"?"}) · File: ${wd.fileName||"manual entry"}`,
              due:"", daysLeft:-daysSince,
              assignee:"HSE Team", assigneeEmail:null,
              site:"All Sites", key:"weekly-late",
            });
          }
        }
      }
      return alerts;
    })(),

    // ── Monthly report data late (KPI/PCI tables not updated this month) ─────
    ...(()=>{
      const alerts=[];
      if(!monthlyState) return alerts;
      const {kpiTable,kpiItems=[]} = monthlyState;
      if(!kpiTable||!kpiItems.length) return alerts;
  // eslint-disable-next-line no-unused-vars
      const currentMonth = new Date().toLocaleString("default",{month:"short"}); // e.g. "Apr"
      const months3 = ["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"];
      const mo = months3[new Date().getMonth()];
      // Check if any KPI item has data for current month
      const hasCurrentMonth = kpiItems.some(k=>kpiTable[k]&&kpiTable[k][mo]&&String(kpiTable[k][mo]).trim()!=="");
      if(!hasCurrentMonth){
        alerts.push({
          id:"monthly-late", category:"Monthly Report", severity:"Pending", color:C.yellow,
          title:`Monthly KPI/PCI Not Updated for ${mo}`,
          detail:`Monthly Monitor section has no data for ${mo} yet. Please update KPI and PCI tables.`,
          due:"", daysLeft:null,
          assignee:"HSE Team", assigneeEmail:null,
          site:"All Sites", key:"monthly-late",
        });
      }
      return alerts;
    })(),
  ];

  // Dedupe by key
  const seen=new Set(); const deduped=allAlerts.filter(a=>{if(seen.has(a.key))return false;seen.add(a.key);return true;});

  const filtered = deduped.filter(a=>{
    if(filterCat && a.category!==filterCat) return false;
    if(filterSev && a.severity!==filterSev) return false;
    return true;
  });

  const cats = [...new Set(deduped.map(a=>a.category))];
  const sevs = [...new Set(deduped.map(a=>a.severity))];
  const allSel = filtered.length>0 && filtered.every(a=>selectedAlerts.includes(a.key));
  // eslint-disable-next-line no-unused-vars
  const toggleAll = ()=>setSelected(allSel?[]:filtered.map(a=>a.key));
  // eslint-disable-next-line no-unused-vars
  const toggleOne = k=>setSelected(p=>p.includes(k)?p.filter(x=>x!==k):[...p,k]);

  // Summary counts
  const critCount    = deduped.filter(a=>a.severity==="Critical"||a.severity==="Expired").length;
  const warnCount    = deduped.filter(a=>a.severity==="Expiring"||a.severity==="Overdue"||a.severity==="High"||a.severity==="Due Soon").length;
  const recipCount   = activeRecips.length;

  // ── EmailJS init ──────────────────────────────────────────────────────────
  // The SDK is bundled with the app (see `import emailjs` at top of file), so
  // there is no runtime script download, no CDN dependency, and no CSP
  // script-src exception needed. We only need to init with the current public
  // key before each send (safe to call multiple times).
  const loadEmailJS = async () => {
    if(!savedCfg?.publicKey) throw new Error("EmailJS Public Key not configured.");
    emailjs.init({publicKey: savedCfg.publicKey});
  };

  // ── Build formatted email body ────────────────────────────────────────────
  // ── Build grouped weekly digest text ────────────────────────────────────
  const buildDigest = () => {
    // Group by category — names listed, no dates or descriptions
  // eslint-disable-next-line no-unused-vars
    const groups = {};
    deduped.forEach(a=>{
      if(!groups[a.category]) groups[a.category]={total:0,expired:0,expiring:0,critical:0,overdue:0,dueSoon:0,high:0,pending:0};
      groups[a.category].total++;
      if(a.severity==="Expired")       groups[a.category].expired++;
      else if(a.severity==="Expiring") groups[a.category].expiring++;
      else if(a.severity==="Critical") groups[a.category].critical++;
      else if(a.severity==="Overdue")  groups[a.category].overdue++;
      else if(a.severity==="Due Soon") groups[a.category].dueSoon++;
      else if(a.severity==="High")     groups[a.category].high++;
      else                             groups[a.category].pending++;

    });

    // One-line headline per category
    const headline = Object.entries(groups).map(([cat,g])=>{
      const parts=[];
      if(g.expired)  parts.push(`${g.expired} Expired`);
      if(g.expiring) parts.push(`${g.expiring} Expiring`);
      if(g.critical) parts.push(`${g.critical} Critical`);
      if(g.overdue)  parts.push(`${g.overdue} Overdue`);
      if(g.dueSoon)  parts.push(`${g.dueSoon} Due Soon`);
      if(g.high)     parts.push(`${g.high} High`);
      if(g.pending)  parts.push(`${g.pending} Pending`);
      return `${g.total} ${cat}: ${parts.join(", ")}`;
    }).join("\n");

    // ── Severity totals (single source of truth) ───────────────────────────
    // Counted once here and re-used in both the breakdown text and the per-
    // recipient EmailJS params — so the numbers on the "Critical/Overdue/
    // Expiring" tiles in the email can never drift from the body.
    const totalCrit     = deduped.filter(a=>a.severity==="Critical"||a.severity==="Expired").length;
    const totalWarn     = deduped.filter(a=>a.severity==="Expiring"||a.severity==="Overdue"||a.severity==="High"||a.severity==="Due Soon").length;
    const totalOther    = deduped.length - totalCrit - totalWarn;
    const totalOverdue  = deduped.filter(a=>a.severity==="Overdue").length;
    const totalExpiring = deduped.filter(a=>a.severity==="Expiring"||a.severity==="Due Soon").length;

    // ── Build per-category breakdown lines once ────────────────────────────
    const categoryLines = Object.entries(groups).map(([cat,g])=>{
      const parts=[];
      if(g.expired)  parts.push(`${g.expired} Expired`);
      if(g.expiring) parts.push(`${g.expiring} Expiring`);
      if(g.critical) parts.push(`${g.critical} Critical`);
      if(g.overdue)  parts.push(`${g.overdue} Overdue`);
      if(g.dueSoon)  parts.push(`${g.dueSoon} Due Soon`);
      if(g.high)     parts.push(`${g.high} High`);
      if(g.pending)  parts.push(`${g.pending} Pending`);
      return `  ${cat.padEnd(24)} ${String(g.total).padStart(4)}   (${parts.join(", ")})`;
    });

    // ── Per-recipient body builder ─────────────────────────────────────────
    // IMPORTANT: EmailJS does NOT recursively interpolate Handlebars inside an
    // already-substituted variable. If we drop `Dear {{to_name}},` into the
    // `alerts` payload, the email shows the literal text `{{to_name}}`. So we
    // interpolate the recipient's name in JavaScript BEFORE sending — and we
    // leave it to the EmailJS template's own `{{to_name}}` slot to handle
    // greetings outside the body.
    const buildBody = (toName) => [
      `Dear ${toName},`,
      ``,
      `Please find below this week's HSSE alert summary for your action.`,
      ``,
      `DAN Company - HSSE Weekly Alert Summary`,
      `Date: ${today.toDateString()}`,
      ``,
      `TOTAL ITEMS REQUIRING ATTENTION: ${deduped.length}`,
      `  Critical / Expired : ${totalCrit}`,
      `  Warning / Overdue  : ${totalWarn}`,
      `  Pending            : ${totalOther}`,
      ``,
      `BREAKDOWN BY CATEGORY:`,
      `─────────────────────────────────────────────────────`,
      ...categoryLines,
      `─────────────────────────────────────────────────────`,
      ``,
      `Please log in to the HSSE System to review and take action.`,
      `This is an automated weekly summary. Do not reply to this email.`,
      ``,
      `Regards,`,
      `DAN Company HSSE Management System`,
    ].join("\n");

    return {
      headline,
      buildBody,
      total: deduped.length,
      groups,
      totalCrit,
      totalWarn,
      totalOther,
      totalOverdue,
      totalExpiring,
    };
  };

  // ── Send weekly digest to all active recipients ───────────────────────────
  const sendDigest = async () => {
    if(!isReady){alert("Configure EmailJS settings first.");return;}
    if(!activeRecips.length){alert("Add at least one active recipient first.");return;}
    if(!deduped.length){alert("No active alerts to send.");return;}
    setSendingDigest(true); setDigestResult(null);
    try{
      await loadEmailJS();
      const digest = buildDigest();
      const {headline, buildBody, total, totalCrit, totalOverdue, totalExpiring} = digest;
      const recipients = activeRecips.map(r=>({email:r.email,name:r.name}));
      const sentDate = new Date().toISOString();
      const subject  = `HSSE Weekly Summary - ${total} items require attention [${today.toDateString()}]`;
      let sent=0, failed=0, lastError="";
      for(const to of recipients){
        const toName = to.name || to.email.split("@")[0];
        try{
          const params = {
            to_email:    to.email,
            to_name:     toName,
            subject,
            alerts:      buildBody(toName),   // name interpolated in JS — not via {{to_name}}
            alert_count: String(total),
            alert_date:  today.toDateString(),
            critical:    String(totalCrit),
            overdue:     String(totalOverdue),
            expiring:    String(totalExpiring),
            project:     "DAN Company - HSSE Management System",
            headline,
          };
          const resp = await emailjs.send(savedCfg.serviceId, savedCfg.templateId, params);
          console.log("EmailJS send response:", resp);
          sent++;
        }catch(e){
          failed++;
          lastError = e?.text||e?.message||JSON.stringify(e)||"Unknown error";
          console.error("EmailJS failed for", to.email, e);
        }
      }
      // Save last sent timestamp
      await setDoc(doc(db,"settings","emailAlerts"),{lastSent:sentDate},{merge:true});
      setLastSent(sentDate);
      setDigestResult({sent,failed,total:recipients.length,headline,lastError:failed>0?lastError:""});
    }catch(err){setDigestResult({error:err.message});}
    finally{setSendingDigest(false);}
  };



  // ── Send to individual responsible person ─────────────────────────────────
  const sendToResponsible = async (alert) => {
    if(!alert.assigneeEmail){
      window.alert(`No email found for "${alert.assignee}" in the system.\nAdd their email in User Management first.`);
      return;
    }
    if(!isReady){window.alert("Configure EmailJS settings first.");return;}
    setSendingId(alert.key);
    try{
      await loadEmailJS();
      const toName = alert.assignee || (alert.assigneeEmail||"").split("@")[0];
      // Body — built the same way buildDigest.buildBody is, so any template
      // that renders {{alerts}} as a <pre> block or white-space:pre-wrap gets
      // consistent formatting between weekly digest and single-item alerts.
      const daysText = alert.daysLeft==null
        ? ""
        : (alert.daysLeft<0 ? `OVERDUE (${Math.abs(alert.daysLeft)}d)` : `${alert.daysLeft}d`);
      const body = [
        `Dear ${toName},`,
        ``,
        `The following item requires your action:`,
        ``,
        `Title    : ${alert.title}`,
        alert.category ? `Category : ${alert.category}` : null,
        alert.severity ? `Severity : ${alert.severity}` : null,
        alert.due      ? `Due Date : ${alert.due}`      : null,
        daysText       ? `Remaining: ${daysText}`       : null,
        ``,
        alert.detail || "",
        ``,
        `Please log in to the HSSE System to review and take action.`,
        ``,
        `Regards,`,
        `DAN Company HSSE Management System`,
      ].filter(line => line !== null).join("\n");

      // Severity flags — same semantics as sendDigest so the template never
      // sees "expiring" meaning two different things from two different senders.
      const isCrit     = alert.severity==="Critical" || alert.severity==="Expired";
      const isOverdue  = alert.severity==="Overdue";
      const isExpiring = alert.severity==="Expiring" || alert.severity==="Due Soon";

      const respParams = {
        to_email:    alert.assigneeEmail,
        to_name:     toName,
        subject:     `Action Required: ${alert.title}`,
        alerts:      body,                 // greeting interpolated in JS — NOT {{to_name}}
        alert_count: "1",
        alert_date:  today.toDateString(),
        critical:    isCrit     ? "1" : "0",
        overdue:     isOverdue  ? "1" : "0",
        expiring:    isExpiring ? "1" : "0",
        project:     "DAN Company - HSSE Management System",
        headline:    alert.title,
      };
      const r = await emailjs.send(savedCfg.serviceId, savedCfg.templateId, respParams);
      console.log("EmailJS notify response:", r);
      setSendResult({sent:1,failed:0,total:1,personal:alert.assignee});
    }catch(err){setSendResult({error:err.message});}
    finally{setSendingId(null);}
  };

  // severity sort order
  const sevOrder = {Critical:0,Expired:1,Overdue:2,"Due Soon":3,High:4,Expiring:5};
  const sorted = [...filtered].sort((a,b)=>(sevOrder[a.severity]??9)-(sevOrder[b.severity]??9));

  return(
    <div style={{display:"flex",flexDirection:"column",gap:18}}>

      {/* Summary strip */}
      <PillGrid minWidth={130}>
        {[
          ["Total Alerts",    deduped.length,  C.blue],
          ["Critical/Expired",critCount,       C.red],
          ["Warning",         warnCount,       C.orange],
          ["Recipients",      recipCount,      C.teal],
        ].map(([l,v,c])=>(
          <StatPill key={l} label={l} value={v} color={c} C={C}/>
        ))}
      </PillGrid>

      {/* EmailJS config panel */}
      <div style={{background:C.card,border:`1px solid ${isReady?C.green+"55":C.orange+"55"}`,borderRadius:14,padding:18}}>
        <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",flexWrap:"wrap",gap:8}}>
          <div style={{display:"flex",alignItems:"center",gap:10}}>
            <div style={{background:isReady?C.green+"22":C.orange+"22",padding:8,borderRadius:8}}>
              <Mail size={18} style={{color:isReady?C.green:C.orange}}/>
            </div>
            <div>
              <div style={{color:C.text,fontWeight:700,fontSize:14}}>EmailJS Configuration</div>
              <div style={{color:C.muted,fontSize:11}}>
                {isReady?`✅ Ready · ${recipCount} active recipient${recipCount!==1?"s":""} · Expiry window: ${expWin} days`:"⚠️ Not configured — enter credentials below"}
              </div>
            </div>
          </div>
          <button onClick={()=>setEditCfg(!editCfg)}
            style={{background:C.blue+"22",border:`1px solid ${C.blue}44`,color:C.blue,borderRadius:8,padding:"6px 12px",fontSize:12,fontWeight:700,cursor:"pointer",display:"flex",alignItems:"center",gap:5}}>
            <Edit2 size={12}/>{editCfg?"Cancel":"Edit Settings"}
          </button>
        </div>



        {/* Setup form */}
        {(!isReady||editCfg)&&(
          <div style={{marginTop:14}}>
            <div style={{background:C.bg,borderRadius:10,padding:12,marginBottom:12,fontSize:12,color:C.muted,lineHeight:1.8}}>
              <strong style={{color:C.text}}>📧 EmailJS setup (free · 200 emails/month · no backend):</strong><br/>
              1. Sign up at <a href="https://www.emailjs.com" target="_blank" rel="noreferrer" style={{color:C.teal}}>emailjs.com</a><br/>
              2. <strong>Email Services</strong> → Add Service (Gmail/Outlook) → copy <strong>Service ID</strong><br/>
              3. <strong>Email Templates</strong> → Create template → use these variables:<br/>
              <code style={{background:C.card,padding:"4px 8px",borderRadius:6,display:"block",marginTop:4,fontSize:11}}>
                {"{{to_name}}"} {"{{subject}}"} {"{{alerts}}"} {"{{alert_count}}"} {"{{critical}}"} {"{{overdue}}"} {"{{expiring}}"} {"{{alert_date}}"} {"{{project}}"}
              </code><br/>
              4. <strong>Account</strong> → copy <strong>Public Key</strong>
            </div>
            <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:12}}>
              <Field label="Service ID" C={C}><Inp C={C} placeholder="service_xxxxxxx" value={ejsConfig.serviceId||""} onChange={e=>setEjsConfig(p=>({...p,serviceId:e.target.value}))}/></Field>
              <Field label="Template ID" C={C}><Inp C={C} placeholder="template_xxxxxxx" value={ejsConfig.templateId||""} onChange={e=>setEjsConfig(p=>({...p,templateId:e.target.value}))}/></Field>
              <Field label="Public Key" C={C}><Inp C={C} placeholder="Public key from Account tab" value={ejsConfig.publicKey||""} onChange={e=>setEjsConfig(p=>({...p,publicKey:e.target.value}))}/></Field>
              <Field label={`Expiry Warning Window (days)`} C={C}>
                <Sel C={C} value={String(ejsConfig.expiryDays||30)} onChange={e=>setEjsConfig(p=>({...p,expiryDays:Number(e.target.value)}))}>
                  {[7,14,30,60,90].map(d=><option key={d} value={d}>{d} days</option>)}
                </Sel>
              </Field>
            </div>

            <div style={{marginTop:10,padding:"8px 12px",background:C.blue+"11",border:`1px solid ${C.blue}22`,borderRadius:8,fontSize:11,color:C.blue}}>
              💡 <strong>Send to Responsible:</strong> Add user email addresses in <strong>User Management</strong> to enable the per-row "Send to Responsible" button. The system matches by name.
            </div>
            {cfgSaveError && (
              <div style={{marginTop:10,padding:"8px 12px",background:C.red+"15",border:`1px solid ${C.red}44`,borderRadius:8,fontSize:12,color:C.red,lineHeight:1.5}}>
                ⚠ {cfgSaveError}
              </div>
            )}
            <Btn onClick={saveCfg} color={C.teal} style={{marginTop:10}} disabled={cfgSaving}>
              <Save size={14}/>{cfgSaving ? "Saving..." : "Save Configuration"}
            </Btn>
          </div>
        )}
      </div>

      {/* ── RECIPIENT MANAGER ─────────────────────────────────────────────── */}
      <div style={{background:C.card,border:`1px solid ${C.border}`,borderRadius:14,overflow:"hidden"}}>
        <div style={{padding:"12px 18px",borderBottom:`1px solid ${C.border}`,display:"flex",justifyContent:"space-between",alignItems:"center",flexWrap:"wrap",gap:8}}>
          <span style={{color:C.text,fontWeight:700,fontSize:14}}>
            📋 Alert Recipients <span style={{background:C.teal+"22",color:C.teal,fontSize:11,padding:"2px 8px",borderRadius:99,marginLeft:6,fontWeight:700}}>{recipientList.length} total · {activeRecips.length} active</span>
          </span>
        </div>

        {/* Add new recipient row */}
        <div style={{padding:"12px 18px",borderBottom:`1px solid ${C.border}`,background:C.bg,display:"flex",gap:8,alignItems:"flex-end",flexWrap:"wrap"}}>
          <div style={{flex:2,minWidth:130}}>
            <div style={{fontSize:11,color:C.muted,marginBottom:4,fontWeight:600}}>Full Name</div>
            <Inp C={C} placeholder="e.g. Ahmed Al-Rashid" value={newRecip.name} onChange={e=>setNewRecip(p=>({...p,name:e.target.value}))}
              onKeyDown={ev=>{if(ev.key==="Enter")addRecipient();}}/>
          </div>
          <div style={{flex:3,minWidth:180}}>
            <div style={{fontSize:11,color:C.muted,marginBottom:4,fontWeight:600}}>Email Address</div>
            <Inp C={C} type="email" placeholder="e.g. ahmed@dan.sa" value={newRecip.email} onChange={e=>setNewRecip(p=>({...p,email:e.target.value}))}
              onKeyDown={ev=>{if(ev.key==="Enter")addRecipient();}}/>
          </div>
          <div style={{flex:2,minWidth:130}}>
            <div style={{fontSize:11,color:C.muted,marginBottom:4,fontWeight:600}}>Role / Title</div>
            <Inp C={C} placeholder="e.g. HSE Manager" value={newRecip.role} onChange={e=>setNewRecip(p=>({...p,role:e.target.value}))}
              onKeyDown={ev=>{if(ev.key==="Enter")addRecipient();}}/>
          </div>
          <Btn onClick={addRecipient} color={C.teal} disabled={!newRecip.name||!newRecip.email}
            style={{padding:"8px 16px",flexShrink:0}}>
            <Plus size={14}/>Add
          </Btn>
        </div>

        {/* Recipient list */}
        {recipientList.length===0?(
          <div style={{padding:24,textAlign:"center",color:C.muted,fontSize:13}}>
            No recipients yet — add the first one above to start sending email alerts.
          </div>
        ):(
          <table style={{width:"100%",borderCollapse:"collapse"}}>
            <thead><tr>
              {["Name","Email","Role / Title","Status","Actions"].map(h=><Th key={h} C={C}>{h}</Th>)}
            </tr></thead>
            <tbody>
              {recipientList.map(r=>(
                <tr key={r.id}
                  style={{background:r.active===false?C.muted+"11":"transparent",opacity:r.active===false?0.65:1}}
                  onMouseEnter={ev=>ev.currentTarget.style.background=r.active===false?C.muted+"11":C.border+"33"}
                  onMouseLeave={ev=>ev.currentTarget.style.background=r.active===false?C.muted+"11":"transparent"}>

                  {editRecipId===r.id?(
                    // ── Edit mode ───────────────────────────────────────────
                    <>
                      <Td C={C}><Inp C={C} value={editRecipData.name||""} onChange={e=>setEditRecipData(p=>({...p,name:e.target.value}))}/></Td>
                      <Td C={C}><Inp C={C} type="email" value={editRecipData.email||""} onChange={e=>setEditRecipData(p=>({...p,email:e.target.value}))}/></Td>
                      <Td C={C}><Inp C={C} value={editRecipData.role||""} onChange={e=>setEditRecipData(p=>({...p,role:e.target.value}))}/></Td>
                      <Td C={C}><Badge label={r.active===false?"Inactive":"Active"} color={r.active===false?C.muted:C.green}/></Td>
                      <Td C={C}>
                        <div style={{display:"flex",gap:6}}>
                          <Btn onClick={saveEditRecip} color={C.green} style={{padding:"4px 10px",fontSize:11}}><Save size={11}/>Save</Btn>
                          <button onClick={()=>setEditRecipId(null)} style={{background:C.border,border:"none",color:C.text,borderRadius:6,padding:"4px 10px",fontSize:11,cursor:"pointer"}}>Cancel</button>
                        </div>
                      </Td>
                    </>
                  ):(
                    // ── View mode ───────────────────────────────────────────
                    <>
                      <Td C={C} style={{color:C.text,fontWeight:600}}>{r.name}</Td>
                      <Td C={C} style={{color:C.teal,fontFamily:"monospace",fontSize:12}}>{r.email}</Td>
                      <Td C={C} style={{color:C.muted}}>{r.role||"—"}</Td>
                      <Td C={C}>
                        <button onClick={()=>toggleRecipient(r.id)}
                          style={{background:r.active===false?C.muted+"22":C.green+"22",border:`1px solid ${r.active===false?C.muted+"44":C.green+"44"}`,color:r.active===false?C.muted:C.green,borderRadius:99,padding:"3px 12px",fontSize:11,fontWeight:700,cursor:"pointer",whiteSpace:"nowrap"}}>
                          {r.active===false?"● Inactive":"● Active"}
                        </button>
                      </Td>
                      <Td C={C}>
                        <div style={{display:"flex",gap:6}}>
                          <button onClick={()=>startEditRecip(r)}
                            style={{background:C.blue+"22",border:`1px solid ${C.blue}44`,color:C.blue,borderRadius:6,padding:"4px 9px",fontSize:11,fontWeight:700,cursor:"pointer",display:"flex",alignItems:"center",gap:4}}>
                            <Edit2 size={11}/>Edit
                          </button>
                          <button onClick={()=>removeRecipient(r.id)}
                            style={{background:"none",border:"none",cursor:"pointer",color:C.muted,padding:"4px 6px",display:"flex",alignItems:"center"}}>
                            <Trash2 size={13}/>
                          </button>
                        </div>
                      </Td>
                    </>
                  )}
                </tr>
              ))}
            </tbody>
          </table>
        )}

        <div style={{padding:"10px 18px",borderTop:`1px solid ${C.border}`,fontSize:11,color:C.muted,background:C.bg}}>
          💡 Toggle <strong>Active/Inactive</strong> to temporarily pause alerts to a recipient without removing them. Only active recipients receive bulk emails.
        </div>
      </div>

      {/* ── WEEKLY DIGEST PANEL ─────────────────────────────────────────────── */}
      <div style={{background:C.card,border:`1px solid ${deduped.length?C.orange+"55":C.green+"55"}`,borderRadius:14,overflow:"hidden"}}>

        {/* Header */}
        <div style={{padding:"14px 18px",borderBottom:`1px solid ${C.border}`,display:"flex",justifyContent:"space-between",alignItems:"center",flexWrap:"wrap",gap:10}}>
          <div>
            <div style={{color:C.text,fontWeight:700,fontSize:15}}>📋 Weekly Digest Summary</div>
            <div style={{color:C.muted,fontSize:11,marginTop:2}}>
              {lastSent
                ? `Last sent: ${new Date(lastSent).toLocaleString()}`
                : "Not sent yet this week"}
            </div>
          </div>
          <div style={{display:"flex",gap:8,alignItems:"center",flexWrap:"wrap"}}>
            <button onClick={()=>setPreviewOpen(p=>!p)}
              style={{background:C.blue+"22",border:`1px solid ${C.blue}44`,color:C.blue,borderRadius:8,padding:"7px 14px",fontSize:12,fontWeight:700,cursor:"pointer",display:"flex",alignItems:"center",gap:5}}>
              {previewOpen?"▲ Hide Preview":"👁 Preview Email"}
            </button>
            <Btn onClick={sendDigest} color={C.teal} disabled={sendingDigest||!isReady||!deduped.length}>
              {sendingDigest
                ? <><span style={{width:10,height:10,borderRadius:"50%",border:"2px solid #fff",borderTopColor:"transparent",display:"inline-block",marginRight:6,animation:"spin .7s linear infinite"}}/>Sending...</>
                : <><Mail size={14}/>Send Weekly Digest ({activeRecips.length} recipients)</>
              }
            </Btn>
          </div>
        </div>

        {/* Digest result banner */}
        {digestResult&&(
          <div style={{padding:"10px 18px",background:digestResult.error?C.red+"11":C.green+"11",borderBottom:`1px solid ${digestResult.error?C.red:C.green}33`,display:"flex",justifyContent:"space-between",alignItems:"center"}}>
            {digestResult.error
              ? <div>
                  <div style={{color:C.red,fontSize:12,fontWeight:700}}>❌ Send failed: {digestResult.error}</div>
                  <div style={{color:C.muted,fontSize:11,marginTop:3}}>Check your Service ID, Template ID and Public Key in EmailJS settings.</div>
                </div>
              : digestResult.failed>0&&digestResult.sent===0
              ? <div>
                  <div style={{color:C.red,fontSize:12,fontWeight:700}}>❌ All {digestResult.total} sends failed</div>
                  {digestResult.lastError&&<div style={{color:C.muted,fontSize:11,marginTop:3}}>Error: {digestResult.lastError}</div>}
                  <div style={{color:C.muted,fontSize:11,marginTop:2}}>Check: Service ID · Template ID · Public Key · EmailJS template has all required variables</div>
                </div>
              : <div>
                  <div style={{color:digestResult.failed>0?C.orange:C.green,fontSize:12,fontWeight:700}}>
                    {digestResult.failed>0?"⚠️":"✅"} Sent to {digestResult.sent}/{digestResult.total} recipient{digestResult.total!==1?"s":""}
                    {digestResult.failed>0?` · ${digestResult.failed} failed`:""}
                  </div>
                  {digestResult.lastError&&<div style={{color:C.orange,fontSize:11,marginTop:3}}>Last error: {digestResult.lastError}</div>}
                  {digestResult.headline&&<div style={{color:C.muted,fontSize:11,marginTop:3}}>{digestResult.headline}</div>}
                </div>
            }
            <button onClick={()=>setDigestResult(null)} style={{background:"none",border:"none",color:C.muted,cursor:"pointer",fontSize:16}}>×</button>
          </div>
        )}

        {/* Digest category breakdown cards */}
        {deduped.length===0?(
          <div style={{padding:32,textAlign:"center",color:C.muted,fontSize:14}}>
            🎉 No active alerts — everything is on track! Nothing to send this week.
          </div>
        ):(()=>{
  // eslint-disable-next-line no-unused-vars
          const groups={};
          deduped.forEach(a=>{
            if(!groups[a.category]) groups[a.category]={color:a.color,total:0,expired:0,expiring:0,critical:0,overdue:0,dueSoon:0};
            groups[a.category].total++;
            if(a.severity==="Expired")   groups[a.category].expired++;
            if(a.severity==="Expiring")  groups[a.category].expiring++;
            if(a.severity==="Critical")  groups[a.category].critical++;
            if(a.severity==="Overdue")   groups[a.category].overdue++;
            if(a.severity==="Due Soon")  groups[a.category].dueSoon++;
          });
          return(
            <div style={{padding:"14px 18px",display:"grid",gridTemplateColumns:"repeat(auto-fill,minmax(220px,1fr))",gap:10}}>
              {Object.entries(groups).map(([cat,g])=>(
                <div key={cat} style={{background:g.color+"0f",border:`1px solid ${g.color}33`,borderRadius:10,padding:"12px 14px"}}>
                  <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:8}}>
                    <span style={{color:C.text,fontWeight:700,fontSize:13}}>{cat}</span>
                    <span style={{background:g.color+"33",color:g.color,fontWeight:900,fontSize:16,padding:"2px 10px",borderRadius:99}}>{g.total}</span>
                  </div>
                  <div style={{display:"flex",flexWrap:"wrap",gap:4}}>
                    {g.expired>0   && <Badge label={`${g.expired} Expired`}   color={C.red}/>}
                    {g.expiring>0  && <Badge label={`${g.expiring} Expiring`} color={C.orange}/>}
                    {g.critical>0  && <Badge label={`${g.critical} Critical`} color={C.red}/>}
                    {g.overdue>0   && <Badge label={`${g.overdue} Overdue`}   color={C.orange}/>}
                    {g.dueSoon>0   && <Badge label={`${g.dueSoon} Due Soon`}  color={C.yellow}/>}
                  </div>
                </div>
              ))}
            </div>
          );
        })()}

        {/* Email preview */}
        {previewOpen&&deduped.length>0&&(()=>{
          const {breakdown} = buildDigest();
          return(
            <div style={{margin:"0 18px 18px",background:C.bg,border:`1px solid ${C.border}`,borderRadius:10,overflow:"hidden"}}>
              <div style={{padding:"8px 14px",borderBottom:`1px solid ${C.border}`,display:"flex",justifyContent:"space-between",alignItems:"center"}}>
                <span style={{color:C.text,fontWeight:700,fontSize:12}}>📧 Email Preview</span>
                <span style={{color:C.muted,fontSize:11}}>Subject: HSSE Weekly Summary - {deduped.length} items require attention [sent to each recipient by name]</span>
              </div>
              <pre style={{padding:"14px 16px",color:C.sub,fontSize:12,lineHeight:1.8,whiteSpace:"pre-wrap",margin:0,fontFamily:"monospace",maxHeight:400,overflowY:"auto"}}>{breakdown}</pre>
            </div>
          );
        })()}

      </div>

      {/* ── DETAIL TABLE ─────────────────────────────────────────────────────── */}
      <div style={{background:C.card,border:`1px solid ${C.border}`,borderRadius:14,overflow:"hidden"}}>
        <div style={{padding:"12px 16px",borderBottom:`1px solid ${C.border}`,display:"flex",justifyContent:"space-between",alignItems:"center",flexWrap:"wrap",gap:8}}>
          <span style={{color:C.text,fontWeight:700,fontSize:14}}>🔍 Detail View ({filtered.length}{filterCat||filterSev?` of ${deduped.length}`:""} alerts)</span>
          <div style={{display:"flex",gap:6,flexWrap:"wrap",alignItems:"center"}}>
            <select value={filterCat} onChange={e=>setFilterCat(e.target.value)}
              style={{background:C.bg,border:`1px solid ${filterCat?C.teal:C.border}`,borderRadius:8,padding:"5px 10px",color:filterCat?C.teal:C.muted,fontSize:12,outline:"none",fontWeight:filterCat?700:400}}>
              <option value="">All Categories</option>
              {cats.map(c=><option key={c}>{c}</option>)}
            </select>
            <select value={filterSev} onChange={e=>setFilterSev(e.target.value)}
              style={{background:C.bg,border:`1px solid ${filterSev?C.red:C.border}`,borderRadius:8,padding:"5px 10px",color:filterSev?C.red:C.muted,fontSize:12,outline:"none",fontWeight:filterSev?700:400}}>
              <option value="">All Severities</option>
              {sevs.map(s=><option key={s}>{s}</option>)}
            </select>
            {(filterCat||filterSev)&&<button onClick={()=>{setFilterCat("");setFilterSev("");}} style={{background:"none",border:"none",color:C.muted,cursor:"pointer",fontSize:12}}>✕ Clear</button>}
          </div>
        </div>

        {/* Send result for individual notify */}
        {sendResult&&(
          <div style={{padding:"10px 16px",background:sendResult.error?C.red+"11":C.green+"11",borderBottom:`1px solid ${sendResult.error?C.red:C.green}33`,display:"flex",justifyContent:"space-between",alignItems:"center"}}>
            {sendResult.error
              ? <span style={{color:C.red,fontSize:12}}>❌ {sendResult.error}</span>
              : <span style={{color:C.green,fontSize:12,fontWeight:600}}>✅ Email sent to {sendResult.personal||"recipient"}</span>
            }
            <button onClick={()=>setSendResult(null)} style={{background:"none",border:"none",color:C.muted,cursor:"pointer",fontSize:16}}>×</button>
          </div>
        )}

        <div style={{overflowX:"auto"}}>
          <table style={{width:"100%",borderCollapse:"collapse",minWidth:860}}>
            <thead><tr>
              {["Category","Severity","Detail","Due / Expiry","Days Left","Responsible","Notify"].map(h=><Th key={h} C={C}>{h}</Th>)}
            </tr></thead>
            <tbody>
              {sorted.length===0?(
                <tr><td colSpan={7} style={{padding:32,textAlign:"center",color:C.muted,fontSize:13}}>
                  🎉 No alerts in this filter
                </td></tr>
              ):sorted.map(a=>{
                const daysColor = a.daysLeft===null?C.muted:a.daysLeft<0?C.red:a.daysLeft<=7?C.red:a.daysLeft<=30?C.orange:C.green;
                const daysLabel = a.daysLeft===null?"—":a.daysLeft<0?`${Math.abs(a.daysLeft)}d overdue`:`${a.daysLeft}d left`;
                return(
                  <tr key={a.key}
                    onMouseEnter={ev=>ev.currentTarget.style.background=C.border+"33"}
                    onMouseLeave={ev=>ev.currentTarget.style.background="transparent"}>
                    <Td C={C}><Badge label={a.category} color={a.color}/></Td>
                    <Td C={C}><Badge label={a.severity} color={a.color}/></Td>
                    <Td C={C} style={{color:C.sub,fontSize:11,maxWidth:260}}>{a.detail}</Td>
                    <Td C={C} style={{fontFamily:"monospace",fontSize:11,color:daysColor,fontWeight:a.daysLeft!==null&&a.daysLeft<=30?700:400}}>{a.due||"—"}</Td>
                    <Td C={C}><span style={{color:daysColor,fontWeight:700,fontSize:12}}>{daysLabel}</span></Td>
                    <Td C={C}>
                      <div>
                        <div style={{fontSize:12,color:C.text,fontWeight:600}}>{a.assignee}</div>
                        {a.assigneeEmail&&<div style={{fontSize:10,color:C.muted}}>{a.assigneeEmail}</div>}
                        {!a.assigneeEmail&&a.assignee!=="—"&&<div style={{fontSize:10,color:C.muted,fontStyle:"italic"}}>no email on file</div>}
                      </div>
                    </Td>
                    <Td C={C}>
                      <button onClick={()=>sendToResponsible(a)}
                        disabled={sendingId===a.key||!isReady||!a.assigneeEmail}
                        title={!a.assigneeEmail?"No email for "+a.assignee:!isReady?"Configure EmailJS first":"Send to "+a.assignee}
                        style={{background:a.assigneeEmail&&isReady?C.teal+"22":"transparent",border:`1px solid ${a.assigneeEmail&&isReady?C.teal+"55":C.border}`,
                          color:a.assigneeEmail&&isReady?C.teal:C.muted,borderRadius:7,padding:"4px 10px",fontSize:11,fontWeight:700,
                          cursor:a.assigneeEmail&&isReady?"pointer":"not-allowed",display:"flex",alignItems:"center",gap:4,opacity:sendingId===a.key?0.6:1}}>
                        {sendingId===a.key
                          ?<span style={{width:8,height:8,borderRadius:"50%",border:"2px solid currentColor",borderTopColor:"transparent",display:"inline-block",animation:"spin .7s linear infinite"}}/>
                          :<Mail size={11}/>}
                        {sendingId===a.key?"Sending...":"Notify"}
                      </button>
                    </Td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>

      {!isReady&&(
        <div style={{background:C.blue+"11",border:`1px solid ${C.blue}33`,borderRadius:10,padding:"12px 16px",fontSize:12,color:C.blue,lineHeight:1.7}}>
          📧 <strong>EmailJS</strong> sends emails directly from the browser — no server required. Free tier includes <strong>200 emails/month</strong>.<br/>
          Add user email addresses in <strong>User Management</strong> to unlock the per-row <strong>"Notify Responsible"</strong> button.
        </div>
      )}
    </div>
  );
};
// ── ROOT APP wrapped in ErrorBoundary ────────────────────────────────────────
const AppInner = () => {
  const [darkMode,setDarkMode]             = useState(true);
  const [installPrompt,setInstallPrompt]   = useState(null);
  const [isOnline,setIsOnline]             = useState(navigator.onLine);
  const [showInstall,setShowInstall]       = useState(false);

  // PWA install prompt
  useEffect(()=>{
    window.showInstallButton = (prompt) => { setInstallPrompt(prompt); setShowInstall(true); };
    const handleOnline  = () => setIsOnline(true);
    const handleOffline = () => setIsOnline(false);
    window.addEventListener("online",  handleOnline);
    window.addEventListener("offline", handleOffline);
    return()=>{
      window.removeEventListener("online",  handleOnline);
      window.removeEventListener("offline", handleOffline);
      delete window.showInstallButton;
    };
  },[]);

  const installPWA = async () => {
    if(!installPrompt) return;
    installPrompt.prompt();
    const result = await installPrompt.userChoice;
    if(result.outcome==="accepted") setShowInstall(false);
    setInstallPrompt(null);
  };

  // Session timeout — auto sign-out after 8 hours of inactivity
  const inactivityTimer = useRef(null);
  const SESSION_TIMEOUT_MS = 8 * 60 * 60 * 1000; // 8 hours
  const resetTimer = useCallback(()=>{
    clearTimeout(inactivityTimer.current);
    inactivityTimer.current = setTimeout(async()=>{
      console.warn("[HSSE] Session timed out due to inactivity.");
      await signOut(auth);
    }, SESSION_TIMEOUT_MS);
  },[]);
  useEffect(()=>{
    const events=["mousedown","keydown","touchstart","scroll"];
    events.forEach(e=>window.addEventListener(e,resetTimer,{passive:true}));
    resetTimer();
    return()=>{
      events.forEach(e=>window.removeEventListener(e,resetTimer));
      clearTimeout(inactivityTimer.current);
    };
  },[resetTimer]);
  const C                                  = darkMode?DARK:LIGHT;
  const [authUser,setAuthUser]             = useState(null);
  const [userProfile,setUserProfile]       = useState(null);
  const [accessDenied,setAccessDenied]     = useState(false);
  const [deniedEmail,setDeniedEmail]       = useState("");
  const [showChangePw,setShowChangePw]     = useState(false);
  const [authLoading,setAuthLoading]       = useState(true);
  // Default active section based on user's site assignment
  const getDefaultSection = (profile) => {
    if(!profile) return "overview";
    if(profile.role==="admin"||profile.site==="All Sites") return "overview";
    if(profile.site==="Site 1") return "site1";
    if(profile.site==="Site 2") return "site2";
    if(profile.site==="Site 3") return "site3";
    return "overview";
  };
  // ── Hash-based routing ────────────────────────────────────────────────────
  // Maps URL hash (#/palm1, #/palm2, #/site3, #/home, #/resources, #/users,
  // #/notifications, #/dropdowns) to internal section IDs, and vice-versa.
  // This gives us bookmarkable, shareable URLs per page without adding a
  // router dependency.
  const HASH_TO_ID = {
    "home":"overview","overview":"overview",
    "palm1":"site1","site1":"site1",
    "palm2":"site2","site2":"site2",
    "site3":"site3",
    "resources":"resources","users":"users",
    "notifications":"notifications","dropdowns":"dropdowns",
  };
  const ID_TO_HASH = {
    "overview":"home","site1":"palm1","site2":"palm2","site3":"site3",
    "resources":"resources","users":"users",
    "notifications":"notifications","dropdowns":"dropdowns",
  };
  const sectionFromHash = () => {
    const h = (window.location.hash||"").replace(/^#\/?/,"").toLowerCase();
    return HASH_TO_ID[h] || null;
  };
  const [active,setActive] = useState(() => sectionFromHash() || "overview");
  const [sideOpen,setSideOpen]             = useState(true);
  const [dataLoading,setDataLoading]       = useState(true);
  const [settingsLoading,setSettingsLoading] = useState(true);
  const [isMobile,setIsMobile]             = useState(window.innerWidth<768);
  const [obs,setObs]                       = useState([]);
  const [ncr,setNcr]                       = useState([]);
  const [risks,setRisks]                   = useState([]);
  const [appEquipment,setAppEquipment]     = useState([]);
  const [incidents,setIncidents]           = useState([]);  // incident register
  const [appManpower,setAppManpower]       = useState([]);
  const [appLastSent,setAppLastSent]       = useState(null);   // last digest sent date
  const [firestoreUsers,setFirestoreUsers] = useState([]);
  const [notifOpen,setNotifOpen]           = useState(false);
  const [pptGenerating,setPptGenerating]   = useState(false);

  // ── ALL PERSISTED DASHBOARD STATE ────────────────────────────────────────
  const [zones,setZones]             = useState(DEFAULT_ZONES);
  const [obsSeverity,setObsSeverity]     = useState(DEFAULT_OBS_SEVERITY);
  const [ncrCats,setNcrCats]             = useState(DEFAULT_NCR_CATS);
  const [ncrSeverity,setNcrSeverity]     = useState(DEFAULT_NCR_SEVERITY);
  const [ncrStatus,setNcrStatus]         = useState(DEFAULT_NCR_STATUS);
  const [riskCats,setRiskCats]           = useState(DEFAULT_RISK_CATS);
  const [riskStatus,setRiskStatus]       = useState(DEFAULT_RISK_STATUS);
  const [equipStatus,setEquipStatus]     = useState(DEFAULT_EQUIP_STATUS);
  const [mpStatus,setMpStatus]           = useState(DEFAULT_MP_STATUS);
  const [ltiResetDate,setLtiResetDate]   = useState(null);
  const [obsTypes,setObsTypes]       = useState(DEFAULT_OBS_TYPES);
  const [actionsList,setActionsList] = useState(DEFAULT_ACTIONS);
  const [manualStats,setManualStats] = useState(INIT_MANUAL_STATS);
  const [kpis,setKpis]               = useState(DEFAULT_KPI_DATA);
  // eslint-disable-next-line no-unused-vars
  const [radarData,setRadarData]     = useState(DEFAULT_RADAR_DATA);
  const [welfareItems,setWelfareItems] = useState(DEFAULT_WELFARE_ITEMS);
  const [weeklyData,setWeeklyData]   = useState(WEEKLY_DATA);
  const [monthlyState,setMonthlyState] = useState({
    trend: DEFAULT_MONTHLY_TREND,
    summary: {welfare:"87%",training:"94%"},
    kpiItems: INIT_KPI_ITEMS,
    kpiTable: buildDefaultKpiTable(INIT_KPI_ITEMS),
    pciItems: INIT_PCI_ITEMS,
    pciTable: buildDefaultKpiTable(INIT_PCI_ITEMS),
  });

  const training=[{id:"TR-001",name:"J. Rahman",course:"NEBOSH IGC",status:"Valid"},{id:"TR-002",name:"M. Torres",course:"Forklift",status:"Expired"}];
  const ptw=[{id:"PTW-001",type:"Hot Work",area:"Zone A",status:"Active"},{id:"PTW-002",type:"Confined Space",area:"Tank Farm",status:"Active"}];

  // ── AUTH LISTENER (Neon) ─────────────────────────────────────────────────────
  // neonAuth.onAuthStateChanged fires immediately:
  // - With user object if a valid JWT token exists in localStorage
  // - With null if no token or token expired
  // The user object already contains all profile fields from Neon users table
  useEffect(()=>{
    const unsub = auth.onAuthStateChanged(async neonUser => {
      if(neonUser){
        setAccessDenied(false);
        try{
          // neonUser is the full profile from /auth/me
          // Map to the shape the rest of the app expects
          const profile = {
            uid:                neonUser.id || neonUser.uid,
            email:              neonUser.email || "",
            name:               neonUser.name  || neonUser.email?.split("@")[0] || "User",
            role:               neonUser.role  || "viewer",
            site:               neonUser.site  || "Site 1",
            avatar:             neonUser.avatar || (neonUser.name||"??").split(" ").map(w=>w[0]).join("").slice(0,2).toUpperCase(),
            permissions:        neonUser.permissions || DEFAULT_PERMISSIONS[neonUser.role||"viewer"],
            // Scoped grants (Turn A backend, Turn B frontend). Safely default to []
            // so this works even if the API response didn't include the field.
            grants:             Array.isArray(neonUser.grants) ? neonUser.grants : [],
            mustChangePassword: neonUser.mustChangePassword || neonUser.must_change_password || false,
          };
          setUserProfile(profile);
          setAuthUser({ uid: profile.uid, email: profile.email });
          setActive(getDefaultSection(profile));
          if(profile.mustChangePassword) setShowChangePw(true);
        }catch(e){
          console.error("[HSSE] Auth profile error:",e.message);
          setAuthUser(null);
          setUserProfile(null);
        }
      } else {
        setAuthUser(null);
        setUserProfile(null);
        setAccessDenied(false);
      }
      setAuthLoading(false);
    });
    return()=>unsub();
  },[]);

  // ── WATCH SETTINGS FROM FIRESTORE (real-time) ────────────────────────────
  // onSnapshot keeps Overview + all sections live — any save by any user
  // or browser tab is reflected instantly without a page refresh.
  useEffect(()=>{
    if(!authUser) return;
    const unsub=onSnapshot(
      doc(db,"settings","dashboardData"),
      (snap)=>{
        if(snap.exists()){
          const d=snap.data?.()??snap.data??{};
          if(d.zones)          setZones(d.zones);
          if(d.obsTypes)       setObsTypes(d.obsTypes);
          if(d.actionsList)    setActionsList(d.actionsList);
          if(d.obsSeverity)    setObsSeverity(d.obsSeverity);
          if(d.ncrCats)        setNcrCats(d.ncrCats);
          if(d.ncrSeverity)    setNcrSeverity(d.ncrSeverity);
          if(d.ncrStatus)      setNcrStatus(d.ncrStatus);
          if(d.riskCats)       setRiskCats(d.riskCats);
          if(d.riskStatus)     setRiskStatus(d.riskStatus);
          if(d.equipStatus)    setEquipStatus(d.equipStatus);
          if(d.mpStatus)       setMpStatus(d.mpStatus);
          if(d.ltiResetDate)   setLtiResetDate(d.ltiResetDate);
          if(d.manualStats)    setManualStats(d.manualStats);
          if(d.lastSent)       setAppLastSent(d.lastSent);
          if(d.kpis)           setKpis(d.kpis);
          if(d.radarData)      setRadarData(d.radarData);
          if(d.welfareItems)   setWelfareItems(d.welfareItems);
          if(d.weeklyData)     setWeeklyData(d.weeklyData);
          if(d.monthlyState){
            setMonthlyState(prev=>({
              ...prev,
              ...d.monthlyState,
              kpiTable: d.monthlyState.kpiTable||buildDefaultKpiTable(d.monthlyState.kpiItems||INIT_KPI_ITEMS),
              pciTable: d.monthlyState.pciTable||buildDefaultKpiTable(d.monthlyState.pciItems||INIT_PCI_ITEMS),
            }));
          }
        }
        setSettingsLoading(false);
      },
      (err)=>{console.error("Settings listener error:",err); setSettingsLoading(false);}
    );
    return ()=>unsub();
  },[authUser]);

  // ── REALTIME COLLECTIONS ─────────────────────────────────────────────────
  useEffect(()=>{
    if(!authUser) return;
    const cols=[["observations",setObs],["ncr",setNcr],["risks",setRisks],["equipment",setAppEquipment],["manpower",setAppManpower],["incidents",setIncidents]];
    const loadedCols = new Set();
    const markLoaded = (col) => {
      loadedCols.add(col);
      if(loadedCols.size>=cols.length) setDataLoading(false);
    };
    const onErr=(col)=>(e)=>{
      console.error(`[HSSE] Firestore listener(${col}) error:`,e.code,e.message);
      markLoaded(col); // mark as done even on error so UI doesn't hang
    };
    const unsubs=cols.map(([name,setter])=>onSnapshot(
      collection(db,name),
      snap=>{
        try{setter(snap.docs.map(d=>{const flat=d.data?.()||d;const raw=typeof flat.raw==="string"?JSON.parse(flat.raw||"{}"):flat.raw||{};return{...raw,...flat,_docId:d.id||flat.id};}));}
        catch(e){console.error(`[HSSE] setter(${name}) failed:`,e);}
        markLoaded(name);
      },
      onErr(name)
    ));
    const unsubUsers=onSnapshot(
      collection(db,"users"),
      snap=>setFirestoreUsers(snap.docs.map(d=>({...d.data?.()||d,uid:d.id}))),
      e=>console.error("[HSSE] users listener:",e.code)
    );
    return()=>{unsubs.forEach(u=>u());unsubUsers();};
  },[authUser]);

  useEffect(()=>{
    const h=()=>setIsMobile(window.innerWidth<768);
    window.addEventListener("resize",h);return()=>window.removeEventListener("resize",h);
  },[]);

  // ── Role-based default landing ──────────────────────────────────────────────
  // Once userProfile is available, if there's no hash in the URL send the user
  // to their default page (admin/All Sites → home; site-specific users → their
  // site page). We only do this when the hash is empty so we don't override a
  // deep link the user bookmarked.
  useEffect(()=>{
    if(!userProfile) return;
    const hashHas = !!(window.location.hash||"").replace(/^#\/?/,"");
    if(hashHas) return;
    const def = getDefaultSection(userProfile);
    setActive(def);
    const slug = ID_TO_HASH[def];
    if(slug) window.location.hash = "#/"+slug;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  },[userProfile]);

  // ── Keep URL hash in sync when user clicks a nav item ──────────────────────
  useEffect(()=>{
    const slug = ID_TO_HASH[active];
    if(!slug) return;
    const current = (window.location.hash||"").replace(/^#\/?/,"").toLowerCase();
    if(current !== slug) window.location.hash = "#/"+slug;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  },[active]);

  // ── React to browser back/forward (hash change) ─────────────────────────────
  useEffect(()=>{
    const onHash = () => {
      const id = sectionFromHash();
      if(id) setActive(id);
    };
    window.addEventListener("hashchange", onHash);
    return () => window.removeEventListener("hashchange", onHash);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  },[]);

  // eslint-disable-next-line no-unused-vars
  const handleAddIncident = async (data) => {
    try{ await fbAdd("incidents", data); }
    catch(e){ console.error("[HSSE] handleAddIncident:",e); throw e; }
  };
  // eslint-disable-next-line no-unused-vars
  const handleDeleteIncident = async (docId) => {
    if(!docId) return;
    if(!window.confirm("Delete this incident record? This cannot be undone.")) return;
    try{ await fbDelId("incidents", docId); }
    catch(e){ console.error("[HSSE] handleDeleteIncident:",e); alert("Delete failed: "+e.message); }
  };

  const handleSignOut=async()=>{
    try{
      clearTimeout(inactivityTimer.current);
      await signOut(auth);
    }catch(e){
      console.error("[HSSE] Sign out error:",e);
      // Force clear local state even if Firebase signOut fails
      setAuthUser(null);
      setUserProfile(null);
    }
  };

  const handleGeneratePPT = async () => {
    setPptGenerating(true);
    try {
      await generatePPT({ obs, ncr, kpis, manualStats, welfareItems, weeklyData, userProfile, computedDaysLTI });
    } catch(err) {
      console.error("PPT generation failed:", err);
      alert("❌ Could not generate presentation: " + err.message);
    } finally {
      setPptGenerating(false);
    }
  };

  const LoadScreen = ({msg,sub}) => (
    <div style={{minHeight:"100vh",background:"#0f172a",display:"flex",alignItems:"center",justifyContent:"center",flexDirection:"column",gap:16,fontFamily:"Inter,sans-serif"}}>
      <DanLogo size={90}/>
      <div style={{color:"#14b8a6",fontWeight:700,fontSize:16}}>{msg}</div>
      <div style={{width:200,height:4,borderRadius:99,background:"#334155",overflow:"hidden"}}><div style={{width:"60%",height:4,borderRadius:99,background:"linear-gradient(90deg,#14b8a6,#6366f1)"}}/></div>
      {sub&&<div style={{color:"#64748b",fontSize:12}}>{sub}</div>}
    </div>
  );

  if(authLoading) return <LoadScreen msg="Loading…"/>;
  // Access denied — signed in with Microsoft but not pre-approved
  if(accessDenied) return(
    <div style={{minHeight:"100vh",background:"#0f172a",display:"flex",alignItems:"center",justifyContent:"center",fontFamily:"Inter,sans-serif",padding:16}}>
      <div style={{background:"#1e293b",border:"1px solid #ef444444",borderRadius:20,padding:40,width:"100%",maxWidth:440,textAlign:"center",boxShadow:"0 20px 60px rgba(0,0,0,0.5)"}}>
        <div style={{fontSize:52,marginBottom:16}}>🚫</div>
        <h2 style={{color:"#ef4444",fontWeight:900,fontSize:20,margin:"0 0 12px"}}>Access Denied</h2>
        <p style={{color:"#94a3b8",fontSize:13,lineHeight:1.7,marginBottom:8}}>
          <strong style={{color:"#e2e8f0"}}>{deniedEmail}</strong> is not authorised to access this system.
        </p>
        <p style={{color:"#64748b",fontSize:12,lineHeight:1.7,marginBottom:24}}>
          Please contact your system administrator to be added as an approved user.
        </p>
        <button onClick={()=>{setAccessDenied(false);setDeniedEmail("");}}
          style={{background:"#334155",color:"#e2e8f0",border:"none",borderRadius:10,padding:"10px 24px",fontWeight:700,fontSize:13,cursor:"pointer"}}>
          ← Try a different account
        </button>
        <div style={{marginTop:20,padding:"10px 14px",background:"#0f172a",borderRadius:8,fontSize:11,color:"#64748b"}}>
          🔒 DAN Company HSSE System — Restricted Access
        </div>
      </div>
    </div>
  );

  if(!authUser||!userProfile) return <Login C={C}/>;
  if(dataLoading||settingsLoading) return <LoadScreen msg="Loading HSSE Data…" sub="Connecting to Firebase…"/>;

  const role=ROLE_META[userProfile.role]||ROLE_META.viewer;
  const userPerms=userProfile.permissions||DEFAULT_PERMISSIONS[userProfile.role];

  // ── Auto-compute Days Without LTI from reset date ────────────────────────
  // If ltiResetDate is set, compute days since that date automatically
  const computedDaysLTI = (() => {
    if(ltiResetDate){
      const reset = new Date(ltiResetDate);
      if(isNaN(reset.getTime())) return manualStats?.daysLTI||0;
      const days = Math.floor((new Date() - reset) / (1000*60*60*24));
      return Math.max(0, days); // never show negative days
    }
    return manualStats?.daysLTI||0;
  })();
  const visibleNav=getSiteNavItems(userProfile.site, userProfile.role, userPerms, userProfile.grants);
  const sideWidth=isMobile?(sideOpen?240:0):(sideOpen?248:62);
  // Weekly digest reminder — true if never sent or 7+ days since last send
  const digestDaysSince = appLastSent
    ? Math.floor((new Date() - new Date(appLastSent)) / (1000*60*60*24))
    : null;
  const digestDue = digestDaysSince===null || digestDaysSince>=7;
  const digestDueMsg = digestDaysSince===null
    ? "Weekly email digest has never been sent"
    : `Weekly digest overdue — last sent ${digestDaysSince} day${digestDaysSince!==1?"s":""} ago`;

  const alerts=[
    ...ncr.filter(n=>n.status==="Overdue").map(n=>({msg:`NCR ${n.id} overdue`,color:C.red})),
    ...obs.filter(o=>o.severity==="High"&&o.status==="Open").map(o=>({msg:`High obs: ${o.area}`,color:C.orange})),
    ...training.filter(t=>t.status==="Expired").map(t=>({msg:`${t.name} — training expired`,color:C.red})),
    ...(digestDue&&userProfile.role==="admin"?[{msg:digestDueMsg,color:C.yellow,isDigest:true}]:[]),
  ];

  const renderSection = () => {
    switch(active) {
      // ── All-sites master overview (admin / All Sites users) ──────────────
      case "overview":     return <Overview obs={obs} ncr={ncr} incidents={incidents} training={training} ptw={ptw} manualStats={manualStats} setManualStats={setManualStats} userRole={userProfile.role} kpis={kpis} computedDaysLTI={computedDaysLTI} manpower={appManpower} equipment={appEquipment} setActive={setActive} C={C}/>;
      // ── Site dashboards — full HSSE hub per site ───────────────────────────
      case "site1": return (
        <SiteDashboard
          siteId="Site 1"
          userProfile={userProfile}
          zones={zones} obsTypes={obsTypes} actionsList={actionsList}
          obsSeverity={obsSeverity} ncrCats={ncrCats} ncrSeverity={ncrSeverity}
          ncrStatus={ncrStatus} riskCats={riskCats} riskStatus={riskStatus}
          equipStatus={equipStatus} mpStatus={mpStatus} risks={risks}
          ltiResetDate={ltiResetDate}
          incidents={(incidents||[]).filter(i=>!i.site||i.site==="Site 1")}
          globalManualStats={manualStats}
          C={C}
        />
      );
      case "site2": return (
        <SiteDashboard
          siteId="Site 2"
          userProfile={userProfile}
          zones={zones} obsTypes={obsTypes} actionsList={actionsList}
          obsSeverity={obsSeverity} ncrCats={ncrCats} ncrSeverity={ncrSeverity}
          ncrStatus={ncrStatus} riskCats={riskCats} riskStatus={riskStatus}
          equipStatus={equipStatus} mpStatus={mpStatus} risks={risks}
          ltiResetDate={ltiResetDate}
          incidents={incidents.filter(i=>!i.site||i.site==="Site 2") }
          globalManualStats={manualStats}
          C={C}
        />
      );
      case "site3": return (
        <SiteDashboard
          siteId="Site 3"
          userProfile={userProfile}
          zones={zones} obsTypes={obsTypes} actionsList={actionsList}
          obsSeverity={obsSeverity} ncrCats={ncrCats} ncrSeverity={ncrSeverity}
          ncrStatus={ncrStatus} riskCats={riskCats} riskStatus={riskStatus}
          equipStatus={equipStatus} mpStatus={mpStatus} risks={risks}
          ltiResetDate={ltiResetDate}
          incidents={incidents.filter(i=>!i.site||i.site==="Site 3") }
          globalManualStats={manualStats}
          C={C}
        />
      );
      // ── Shared sections ────────────────────────────────────────────────────
      case "resources":    return <Resources user={userProfile} equipStatus={equipStatus} mpStatus={mpStatus} C={C}/>;
      case "users":        return <UserMgmt firestoreUsers={firestoreUsers} setFirestoreUsers={setFirestoreUsers} userRole={userProfile.role} C={C}/>;
      case "notifications": return <EmailAlerts obs={obs} ncr={ncr} equipment={appEquipment} manpower={appManpower} firestoreUsers={firestoreUsers} weeklyData={weeklyData} monthlyState={monthlyState} C={C}/>;
      case "dropdowns":    return <DropdownSettings zones={zones} setZones={setZones} obsTypes={obsTypes} setObsTypes={setObsTypes} actionsList={actionsList} setActionsList={setActionsList} obsSeverity={obsSeverity} setObsSeverity={setObsSeverity} ncrCats={ncrCats} setNcrCats={setNcrCats} ncrSeverity={ncrSeverity} setNcrSeverity={setNcrSeverity} ncrStatus={ncrStatus} setNcrStatus={setNcrStatus} riskCats={riskCats} setRiskCats={setRiskCats} riskStatus={riskStatus} setRiskStatus={setRiskStatus} equipStatus={equipStatus} setEquipStatus={setEquipStatus} mpStatus={mpStatus} setMpStatus={setMpStatus} ltiResetDate={ltiResetDate} setLtiResetDate={setLtiResetDate} C={C}/>;
      default:             return null;
    }
  };

  return(
    <div style={{background:C.bg,minHeight:"100vh",display:"flex",fontFamily:"Inter,sans-serif",color:C.text,position:"relative"}}>
      {showChangePw&&<ChangePasswordModal onClose={()=>setShowChangePw(false)} mustChange={userProfile.mustChangePassword} C={C}/>}
      {isMobile&&sideOpen&&<div onClick={()=>setSideOpen(false)} style={{position:"fixed",inset:0,background:"rgba(0,0,0,0.5)",zIndex:199}}/>}
      <aside style={{background:C.card,borderRight:`1px solid ${C.border}`,width:sideWidth,transition:"width .25s",flexShrink:0,display:"flex",flexDirection:"column",position:isMobile?"fixed":"sticky",top:0,left:0,height:"100vh",overflowY:"auto",overflowX:"hidden",zIndex:isMobile?200:10,boxShadow:isMobile&&sideOpen?"4px 0 20px rgba(0,0,0,0.4)":"none"}}>
        <div style={{display:"flex",alignItems:"center",gap:10,padding:"12px",borderBottom:`1px solid ${C.border}`,flexShrink:0}}>
          <div style={{flexShrink:0}}><DanLogo size={sideOpen?44:34}/></div>
          {sideOpen&&<div style={{overflow:"hidden"}}><div style={{color:C.text,fontWeight:900,fontSize:12,whiteSpace:"nowrap",lineHeight:1.3}}>DAN Company</div><div style={{color:"#14b8a6",fontSize:9,whiteSpace:"nowrap"}}>HSSE Command Center</div></div>}
          <button onClick={()=>setSideOpen(!sideOpen)} style={{marginLeft:"auto",background:"none",border:"none",cursor:"pointer",color:C.muted,flexShrink:0}}><Menu size={15}/></button>
        </div>
        <nav style={{flex:1,padding:"8px 6px",display:"flex",flexDirection:"column",gap:1}}>
          {visibleNav.map(({id,label,icon:Icon,color,adminOnly})=>(
            <button key={id} onClick={()=>{setActive(id);if(isMobile)setSideOpen(false);}}
              style={{background:active===id?color+"22":"transparent",color:active===id?color:C.muted,borderLeft:active===id?`3px solid ${color}`:"3px solid transparent",borderTop:"none",borderRight:"none",borderBottom:"none",borderRadius:"0 8px 8px 0",padding:"9px 10px",display:"flex",alignItems:"center",gap:9,fontSize:12,fontWeight:active===id?700:400,cursor:"pointer",textAlign:"left",transition:"all .15s",whiteSpace:"nowrap",width:"100%"}}>
              <div style={{position:"relative",flexShrink:0}}>
                <Icon size={16}/>
                {id==="notifications"&&digestDue&&userProfile.role==="admin"&&!sideOpen&&(
                  <span style={{position:"absolute",top:-2,right:-2,width:6,height:6,borderRadius:"50%",background:C.yellow,border:`1px solid ${C.card}`}}/>
                )}
              </div>
              {sideOpen&&<span style={{overflow:"hidden",textOverflow:"ellipsis",display:"flex",alignItems:"center",gap:5}}>
                {label}
                {adminOnly&&<span style={{fontSize:9,background:C.red+"33",color:C.red,marginLeft:4,padding:"1px 4px",borderRadius:99}}>ADMIN</span>}
                {id==="notifications"&&digestDue&&userProfile.role==="admin"&&<span style={{width:7,height:7,borderRadius:"50%",background:C.yellow,flexShrink:0,display:"inline-block"}}/>}
              </span>}
            </button>
          ))}
        </nav>
        <div style={{padding:10,borderTop:`1px solid ${C.border}`,flexShrink:0}}>
          <div style={{display:"flex",alignItems:"center",gap:8}}>
            <div style={{background:role.color+"33",width:30,height:30,borderRadius:"50%",display:"flex",alignItems:"center",justifyContent:"center",fontSize:10,fontWeight:700,color:role.color,flexShrink:0}}>{userProfile.avatar||"??"}</div>
            {sideOpen&&<div style={{overflow:"hidden",flex:1}}>
              <div style={{fontSize:11,fontWeight:600,color:C.text,whiteSpace:"nowrap",overflow:"hidden",textOverflow:"ellipsis"}}>{userProfile.name}</div>
              <div style={{fontSize:10,color:C.muted,whiteSpace:"nowrap",overflow:"hidden",textOverflow:"ellipsis"}}>{authUser.email}</div>
            </div>}
          </div>

        </div>
        {sideOpen&&<button onClick={()=>setShowChangePw(true)} style={{margin:"0 10px 10px",width:"calc(100% - 20px)",background:C.bg,border:`1px solid ${C.border}`,borderRadius:6,padding:"5px 8px",color:C.muted,fontSize:11,cursor:"pointer",display:"flex",alignItems:"center",gap:5}}><Key size={11}/>Change Password</button>}
      </aside>
      <div style={{flex:1,display:"flex",flexDirection:"column",minWidth:0}}>
        <header style={{background:C.card,borderBottom:`1px solid ${C.border}`,padding:"10px 16px",display:"flex",alignItems:"center",gap:8,position:"sticky",top:0,zIndex:100,flexShrink:0,flexWrap:"wrap"}}>
          {isMobile&&<button onClick={()=>setSideOpen(true)} style={{background:"none",border:"none",cursor:"pointer",color:C.muted,padding:4,display:"flex"}}><Menu size={18}/></button>}
          <div style={{minWidth:0}}>
            <h1 style={{color:C.text,fontWeight:900,fontSize:15,margin:0,whiteSpace:"nowrap",overflow:"hidden",textOverflow:"ellipsis"}}>{NAV.find(n=>n.id===active)?.label}</h1>
            <p style={{color:C.muted,fontSize:10,margin:0}}>{new Date().toDateString()} · {userProfile.site}</p>
          </div>
          <div style={{background:role.color+"22",border:`1px solid ${role.color}44`,borderRadius:99,padding:"3px 8px",display:"flex",alignItems:"center",gap:4,flexShrink:0}}>
            <Lock size={9} style={{color:role.color}}/><span style={{color:role.color,fontSize:10,fontWeight:700}}>{role.label}</span>
          </div>
          <div style={{marginLeft:"auto",display:"flex",alignItems:"center",gap:6}}>
            {!isMobile&&<div style={{background:C.bg,border:`1px solid ${C.border}`,borderRadius:8,display:"flex",alignItems:"center",gap:6,padding:"5px 10px"}}>
              <Search size={12} style={{color:C.muted}}/>
              <input
                placeholder="Search..."
                style={{background:"transparent",border:"none",color:C.text,fontSize:12,outline:"none",width:90}}
                onChange={e=>{
                  // Global search: navigate to site1 obs section with filter pre-filled
                  const v=e.target.value.trim();
                  if(v.length>=2) setActive(userProfile?.site==="Site 2"?"site2":userProfile?.site==="Site 3"?"site3":"site1");
                }}
              />
            </div>}
            <button onClick={()=>setDarkMode(!darkMode)} style={{background:C.bg,border:`1px solid ${C.border}`,borderRadius:8,padding:"6px 8px",cursor:"pointer",color:C.sub,display:"flex"}}>
              {darkMode?<Sun size={14}/>:<Moon size={14}/>}
            </button>
            <div style={{position:"relative"}} onBlur={e=>{ if(!e.currentTarget.contains(e.relatedTarget)) setNotifOpen(false); }}>
              <button onClick={()=>setNotifOpen(!notifOpen)} aria-label="Notifications" style={{background:C.bg,border:`1px solid ${C.border}`,borderRadius:8,padding:"6px 8px",cursor:"pointer",color:C.sub,display:"flex"}}><Bell size={14}/></button>
              {alerts.length>0&&<div style={{position:"absolute",top:-4,right:-4,background:C.red,color:"#fff",width:15,height:15,borderRadius:"50%",fontSize:9,display:"flex",alignItems:"center",justifyContent:"center",fontWeight:700}}>{alerts.length}</div>}
              {notifOpen&&(
                <div style={{position:"absolute",right:0,top:34,background:C.card,border:`1px solid ${C.border}`,borderRadius:12,padding:12,width:280,boxShadow:"0 8px 32px rgba(0,0,0,0.3)",zIndex:200}}>
                  <div style={{fontWeight:700,color:C.text,fontSize:12,marginBottom:8}}>🔔 Alerts ({alerts.length})</div>

                  {/* Weekly digest reminder — shown prominently at the top */}
                  {digestDue&&userProfile.role==="admin"&&(
                    <div style={{background:C.yellow+"22",border:`1px solid ${C.yellow}44`,borderRadius:8,padding:"8px 10px",marginBottom:8}}>
                      <div style={{display:"flex",alignItems:"center",gap:6,marginBottom:4}}>
                        <Mail size={12} style={{color:C.yellow,flexShrink:0}}/>
                        <span style={{fontSize:11,color:C.yellow,fontWeight:700}}>Weekly Digest Due</span>
                      </div>
                      <div style={{fontSize:11,color:C.sub,marginBottom:6}}>
                        {digestDaysSince===null
                          ? "Never sent — remind recipients of active alerts"
                          : `Last sent ${digestDaysSince} day${digestDaysSince!==1?"s":""} ago`}
                      </div>
                      <button
                        onClick={()=>{setActive("notifications");setNotifOpen(false);}}
                        style={{background:C.yellow,color:"#000",border:"none",borderRadius:6,padding:"4px 10px",fontSize:11,fontWeight:700,cursor:"pointer",width:"100%"}}>
                        Go to Email Alerts →
                      </button>
                    </div>
                  )}

                  {alerts.filter(a=>!a.isDigest).slice(0,5).map((a,i)=>(
                    <div key={i} style={{display:"flex",gap:7,alignItems:"center",padding:"5px 0",borderBottom:`1px solid ${C.border}44`}}>
                      <div style={{width:6,height:6,borderRadius:"50%",background:a.color,flexShrink:0}}/>
                      <span style={{fontSize:11,color:C.sub}}>{a.msg}</span>
                    </div>
                  ))}
                  {alerts.filter(a=>!a.isDigest).length===0&&!digestDue&&(
                    <div style={{color:C.muted,fontSize:12}}>No active alerts 🎉</div>
                  )}
                </div>
              )}
            </div>
            {/* PPT Generate Button */}
            <button onClick={handleGeneratePPT} disabled={pptGenerating}
              style={{background:pptGenerating?"#33415555":"linear-gradient(135deg,#0D9488,#6366f1)",color:"#fff",border:"none",borderRadius:8,padding:"6px 10px",cursor:pptGenerating?"not-allowed":"pointer",display:"flex",alignItems:"center",gap:5,fontSize:11,fontWeight:700,opacity:pptGenerating?0.6:1,whiteSpace:"nowrap",flexShrink:0}}>
              {pptGenerating
                ? <><span style={{width:10,height:10,borderRadius:"50%",border:"2px solid #fff",borderTopColor:"transparent",display:"inline-block",animation:"spin 0.8s linear infinite"}}/>{!isMobile&&" Generating..."}</>
                : <>{!isMobile&&"📊 "}{!isMobile?"Export PPT":"📊"}</>
              }
            </button>
            {!isOnline&&(
              <div style={{background:"#ef444422",border:"1px solid #ef444444",borderRadius:8,padding:"4px 10px",fontSize:11,color:"#ef4444",fontWeight:700,display:"flex",alignItems:"center",gap:4}}>
                <div style={{width:6,height:6,borderRadius:"50%",background:"#ef4444"}}/>
                Offline
              </div>
            )}
            {showInstall&&(
              <button onClick={installPWA} style={{background:C.teal,color:"#fff",border:"none",borderRadius:8,padding:"5px 10px",fontSize:11,fontWeight:700,cursor:"pointer",display:"flex",alignItems:"center",gap:4}}>
                📱 Install App
              </button>
            )}
            <button onClick={handleSignOut} aria-label="Sign out" title="Sign out" style={{background:C.red+"22",border:`1px solid ${C.red}44`,borderRadius:8,padding:"6px 8px",cursor:"pointer",color:C.red,display:"flex",alignItems:"center",gap:4,fontSize:11,fontWeight:600}}>
              <LogOut size={12}/>{!isMobile&&"Logout"}
            </button>
          </div>
        </header>
        <main style={{flex:1,padding:isMobile?12:20,overflowY:"auto"}}>
          {renderSection()}
        </main>
      </div>
    </div>
  );
};

export default function App(){
  return <ErrorBoundary><AppInner/></ErrorBoundary>;
}