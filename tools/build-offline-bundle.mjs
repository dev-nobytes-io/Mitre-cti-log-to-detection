// Generate a comprehensive offline ATT&CK bundle covering every Enterprise
// data source + component my persona files reference, plus representative
// techniques per tactic and the most-cited threat groups. Structured to be
// drop-in compatible with the live MITRE CTI feed but small enough (<300 KB)
// to ship inside the static site.
//
// Run: node tools/build-offline-bundle.mjs > samples/stix-offline-bundle.json
import { writeFileSync } from "node:fs";

const objects = [];
let counter = 0;
const fid = (kind) => `${kind}--gen-${(++counter).toString(36).padStart(6, "0")}`;
const xid = (k) => `${k.replace(/[^a-z0-9]+/g,"-").toLowerCase()}`;

// ---------- tactics ----------
const TACTICS = [
  ["reconnaissance",     "Reconnaissance",     "TA0043"],
  ["resource-development","Resource Development","TA0042"],
  ["initial-access",     "Initial Access",     "TA0001"],
  ["execution",          "Execution",          "TA0002"],
  ["persistence",        "Persistence",        "TA0003"],
  ["privilege-escalation","Privilege Escalation","TA0004"],
  ["defense-evasion",    "Defense Evasion",    "TA0005"],
  ["credential-access",  "Credential Access",  "TA0006"],
  ["discovery",          "Discovery",          "TA0007"],
  ["lateral-movement",   "Lateral Movement",   "TA0008"],
  ["collection",         "Collection",         "TA0009"],
  ["command-and-control","Command and Control","TA0011"],
  ["exfiltration",       "Exfiltration",       "TA0010"],
  ["impact",             "Impact",             "TA0040"],
];
for (const [shortname, name, eid] of TACTICS) {
  objects.push({
    type: "x-mitre-tactic",
    id: `x-mitre-tactic--${xid("tac-"+shortname)}`,
    name, x_mitre_shortname: shortname,
    external_references: [{ source_name: "mitre-attack", external_id: eid }],
  });
}

// ---------- data sources + components (canonical ATT&CK names) ----------
const DATA_SOURCES = [
  ["Active Directory",  "DS0026", ["Active Directory Object Access","Active Directory Object Creation","Active Directory Object Modification","Active Directory Object Deletion","Active Directory Credential Request"], ["Windows"]],
  ["Application Log",   "DS0015", ["Application Log Content"], ["IaaS","SaaS","Containers","Office 365","Google Workspace","Linux","macOS","Windows"]],
  ["Certificate",       "DS0037", ["Certificate Registration"], ["PRE"]],
  ["Cloud Service",     "DS0025", ["Cloud Service Enumeration","Cloud Service Metadata","Cloud Service Modification","Cloud Service Disable"], ["IaaS","SaaS","Office 365","Google Workspace","Azure AD"]],
  ["Cloud Storage",     "DS0010", ["Cloud Storage Access","Cloud Storage Creation","Cloud Storage Deletion","Cloud Storage Enumeration","Cloud Storage Metadata","Cloud Storage Modification"], ["IaaS"]],
  ["Cluster",           "DS0034", ["Cluster Metadata"], ["Containers"]],
  ["Command",           "DS0017", ["Command Execution"], ["Windows","Linux","macOS","Network","Containers","ESXi"]],
  ["Container",         "DS0032", ["Container Creation","Container Enumeration","Container Metadata","Container Start"], ["Containers"]],
  ["Domain Name",       "DS0038", ["Active DNS","Passive DNS","Domain Registration"], ["PRE"]],
  ["Drive",             "DS0016", ["Drive Access","Drive Creation","Drive Modification"], ["Windows","Linux","macOS"]],
  ["Driver",            "DS0027", ["Driver Load","Driver Metadata"], ["Windows","Linux","macOS"]],
  ["File",              "DS0022", ["File Access","File Creation","File Deletion","File Metadata","File Modification"], ["Windows","Linux","macOS"]],
  ["Firewall",          "DS0018", ["Firewall Disable","Firewall Enumeration","Firewall Metadata","Firewall Rule Modification"], ["IaaS","Windows","Linux","macOS","Network"]],
  ["Firmware",          "DS0001", ["Firmware Modification"], ["Windows","Linux","macOS","Network"]],
  ["Group",             "DS0036", ["Group Enumeration","Group Metadata","Group Modification"], ["IaaS","SaaS","Office 365","Google Workspace","Azure AD","Windows","Linux","macOS"]],
  ["Image",             "DS0007", ["Image Creation","Image Deletion","Image Metadata","Image Modification"], ["IaaS","Containers"]],
  ["Instance",          "DS0030", ["Instance Creation","Instance Deletion","Instance Enumeration","Instance Metadata","Instance Modification","Instance Start","Instance Stop"], ["IaaS"]],
  ["Internet Scan",     "DS0035", ["Response Content","Response Metadata"], ["PRE"]],
  ["Kernel",            "DS0008", ["Kernel Module Load"], ["Linux","macOS"]],
  ["Logon Session",     "DS0028", ["Logon Session Creation","Logon Session Metadata"], ["IaaS","SaaS","Office 365","Google Workspace","Azure AD","Windows","Linux","macOS","Network"]],
  ["Malware Repository","DS0004", ["Malware Content","Malware Metadata"], ["PRE"]],
  ["Module",            "DS0011", ["Module Load"], ["Windows","Linux","macOS"]],
  ["Named Pipe",        "DS0023", ["Named Pipe Metadata"], ["Windows"]],
  ["Network Share",     "DS0033", ["Network Share Access"], ["Windows","Linux","macOS"]],
  ["Network Traffic",   "DS0029", ["Network Connection Creation","Network Traffic Content","Network Traffic Flow"], ["IaaS","Windows","Linux","macOS","Network"]],
  ["Persona",           "DS0021", ["Social Media"], ["PRE"]],
  ["Pod",               "DS0014", ["Pod Creation","Pod Enumeration","Pod Metadata","Pod Modification"], ["Containers"]],
  ["Process",           "DS0009", ["OS API Execution","Process Access","Process Creation","Process Metadata","Process Modification","Process Termination"], ["Windows","Linux","macOS"]],
  ["Scheduled Job",     "DS0003", ["Scheduled Job Creation","Scheduled Job Metadata","Scheduled Job Modification"], ["Windows","Linux","macOS","Containers"]],
  ["Script",            "DS0012", ["Script Execution"], ["Windows","Linux","macOS"]],
  ["Sensor Health",     "DS0013", ["Host Status"], ["Windows","Linux","macOS","Network"]],
  ["Service",           "DS0019", ["Service Creation","Service Metadata","Service Modification"], ["Windows","Linux","macOS"]],
  ["Snapshot",          "DS0020", ["Snapshot Creation","Snapshot Deletion","Snapshot Enumeration","Snapshot Metadata","Snapshot Modification"], ["IaaS"]],
  ["User Account",      "DS0002", ["User Account Authentication","User Account Creation","User Account Deletion","User Account Metadata","User Account Modification"], ["IaaS","SaaS","Office 365","Google Workspace","Azure AD","Windows","Linux","macOS","Containers"]],
  ["Volume",            "DS0005", ["Volume Creation","Volume Deletion","Volume Enumeration","Volume Metadata","Volume Modification"], ["IaaS"]],
  ["Web Credential",    "DS0006", ["Web Credential Creation","Web Credential Usage"], ["IaaS","SaaS","Office 365","Google Workspace","Azure AD","Windows","Linux","macOS"]],
  ["Windows Registry",  "DS0024", ["Windows Registry Key Access","Windows Registry Key Creation","Windows Registry Key Deletion","Windows Registry Key Modification"], ["Windows"]],
  ["WMI",               "DS0005", ["WMI Creation"], ["Windows"]],
];

const dsIds = {};
const compIds = {};
for (const [name, attackId, components, platforms] of DATA_SOURCES) {
  const id = `x-mitre-data-source--${xid("ds-"+name)}`;
  dsIds[name] = id;
  objects.push({
    type: "x-mitre-data-source",
    id, name, x_mitre_platforms: platforms,
    external_references: [{ source_name: "mitre-attack", external_id: attackId }],
  });
  for (const c of components) {
    const cid = `x-mitre-data-component--${xid("dc-"+name+"-"+c)}`;
    compIds[c] = compIds[c] || cid; // first-wins; some component names are shared (rare)
    if (!compIds[c+"@"+name]) compIds[c+"@"+name] = cid;
    objects.push({
      type: "x-mitre-data-component", id, // overwritten below
    });
    objects.pop();
    objects.push({ type:"x-mitre-data-component", id:cid, name:c, x_mitre_data_source_ref:id });
  }
}

// ---------- techniques (representative across all tactics) ----------
const TECHNIQUES = [
  // [attackId, name, tactic shortnames, platforms, detecting components]
  ["T1059","Command and Scripting Interpreter",["execution"],["Windows","Linux","macOS","Network"],["Process Creation","Command Execution","Script Execution","Module Load"]],
  ["T1053","Scheduled Task/Job",                ["execution","persistence","privilege-escalation"],["Windows","Linux","macOS"],["Scheduled Job Creation","Scheduled Job Modification","File Creation","Process Creation","Command Execution"]],
  ["T1106","Native API",                        ["execution"],["Windows","Linux","macOS"],["OS API Execution","Module Load","Process Creation"]],
  ["T1547","Boot or Logon Autostart Execution", ["persistence","privilege-escalation"],["Windows","Linux","macOS"],["Windows Registry Key Creation","Windows Registry Key Modification","File Creation","File Modification","Module Load","Driver Load"]],
  ["T1543","Create or Modify System Process",   ["persistence","privilege-escalation"],["Windows","Linux","macOS"],["Service Creation","Service Modification","File Creation","File Modification","Process Creation","Command Execution"]],
  ["T1136","Create Account",                    ["persistence"],["Windows","Linux","macOS","IaaS","SaaS"],["User Account Creation","Process Creation","Command Execution"]],
  ["T1078","Valid Accounts",                    ["defense-evasion","persistence","privilege-escalation","initial-access"],["Windows","Linux","macOS","SaaS","IaaS","Office 365","Google Workspace","Azure AD","Containers"],["Logon Session Creation","Logon Session Metadata","User Account Authentication"]],
  ["T1098","Account Manipulation",              ["persistence","privilege-escalation"],["Windows","Linux","macOS","IaaS","SaaS","Azure AD"],["User Account Modification","Active Directory Object Modification","Cloud Service Modification","Process Creation","Command Execution"]],
  ["T1027","Obfuscated Files or Information",   ["defense-evasion"],["Windows","Linux","macOS"],["File Creation","File Metadata","Process Creation","Command Execution"]],
  ["T1070","Indicator Removal",                 ["defense-evasion"],["Windows","Linux","macOS","Network"],["File Deletion","File Modification","Windows Registry Key Deletion","Process Creation","Command Execution"]],
  ["T1218","System Binary Proxy Execution",     ["defense-evasion"],["Windows"],["Process Creation","Command Execution","Module Load"]],
  ["T1003","OS Credential Dumping",             ["credential-access"],["Windows","Linux","macOS"],["Process Creation","Process Access","Command Execution","File Access","File Creation","OS API Execution"]],
  ["T1110","Brute Force",                       ["credential-access"],["Windows","Linux","macOS","Network","Office 365","SaaS","IaaS","Google Workspace","Azure AD","Containers"],["User Account Authentication","Logon Session Creation","Application Log Content"]],
  ["T1555","Credentials from Password Stores",  ["credential-access"],["Windows","Linux","macOS"],["File Access","Process Creation","Process Access","Command Execution","Web Credential Usage"]],
  ["T1018","Remote System Discovery",           ["discovery"],["Windows","Linux","macOS","IaaS"],["Process Creation","Command Execution","Network Connection Creation"]],
  ["T1046","Network Service Discovery",         ["discovery"],["Windows","Linux","macOS","Network","IaaS","Containers"],["Network Connection Creation","Network Traffic Flow","Process Creation","Command Execution"]],
  ["T1057","Process Discovery",                 ["discovery"],["Windows","Linux","macOS"],["Process Creation","Command Execution","OS API Execution"]],
  ["T1083","File and Directory Discovery",      ["discovery"],["Windows","Linux","macOS","Network"],["Process Creation","Command Execution","File Access"]],
  ["T1526","Cloud Service Discovery",           ["discovery"],["IaaS","SaaS","Office 365","Google Workspace","Azure AD"],["Cloud Service Enumeration"]],
  ["T1021","Remote Services",                   ["lateral-movement"],["Windows","Linux","macOS"],["Network Connection Creation","Logon Session Creation","Process Creation","Module Load"]],
  ["T1080","Taint Shared Content",              ["lateral-movement"],["Windows","Linux","macOS"],["File Creation","File Modification","Network Share Access"]],
  ["T1005","Data from Local System",            ["collection"],["Windows","Linux","macOS"],["File Access","Process Creation","Command Execution"]],
  ["T1071","Application Layer Protocol",        ["command-and-control"],["Windows","Linux","macOS","Network"],["Network Traffic Content","Network Traffic Flow","Network Connection Creation"]],
  ["T1572","Protocol Tunneling",                ["command-and-control"],["Windows","Linux","macOS"],["Network Connection Creation","Network Traffic Content","Network Traffic Flow"]],
  ["T1041","Exfiltration Over C2 Channel",      ["exfiltration"],["Windows","Linux","macOS"],["Network Traffic Content","Network Traffic Flow","Network Connection Creation"]],
  ["T1486","Data Encrypted for Impact",         ["impact"],["Windows","Linux","macOS","IaaS"],["File Modification","File Creation","Process Creation","Command Execution","Cloud Storage Modification"]],
  ["T1490","Inhibit System Recovery",           ["impact"],["Windows","Linux","macOS"],["Process Creation","Command Execution","Service Modification","Windows Registry Key Modification","Cloud Storage Deletion","Snapshot Deletion"]],
  ["T1485","Data Destruction",                  ["impact"],["Windows","Linux","macOS","IaaS"],["File Deletion","File Modification","Volume Deletion","Snapshot Deletion","Process Creation"]],
  ["T1496","Resource Hijacking",                ["impact"],["Windows","Linux","macOS","Containers","IaaS"],["Process Creation","Network Connection Creation","Network Traffic Flow","Sensor Health"]],
  ["T1190","Exploit Public-Facing Application", ["initial-access"],["Windows","Linux","macOS","IaaS","Containers"],["Application Log Content","Network Traffic Content"]],
  ["T1566","Phishing",                          ["initial-access"],["Windows","Linux","macOS","SaaS","Office 365","Google Workspace"],["Application Log Content","File Creation","Network Traffic Content","Network Traffic Flow"]],
  ["T1133","External Remote Services",          ["initial-access","persistence"],["Windows","Linux","macOS"],["Logon Session Creation","Logon Session Metadata","Application Log Content","Network Traffic Flow"]],
  ["T1068","Exploitation for Privilege Escalation",["privilege-escalation"],["Windows","Linux","macOS"],["Driver Load","Process Creation","Application Log Content"]],
  ["T1112","Modify Registry",                   ["defense-evasion"],["Windows"],["Windows Registry Key Creation","Windows Registry Key Modification","Windows Registry Key Deletion","Process Creation","Command Execution"]],
  ["T1053.005","Scheduled Task",                ["execution","persistence","privilege-escalation"],["Windows"],["Scheduled Job Creation","Scheduled Job Modification","File Creation","Process Creation"]],
  ["T1505","Server Software Component",         ["persistence"],["Windows","Linux","macOS"],["File Creation","File Modification","Process Creation","Module Load","Application Log Content"]],
  ["T1562","Impair Defenses",                   ["defense-evasion"],["Windows","Linux","macOS","Containers","IaaS"],["Service Modification","Firewall Disable","Firewall Rule Modification","Cloud Service Disable","Process Creation","Command Execution","Sensor Health"]],
  ["T1087","Account Discovery",                 ["discovery"],["Windows","Linux","macOS","IaaS","SaaS","Office 365","Google Workspace","Azure AD"],["Process Creation","Command Execution","Group Enumeration","User Account Metadata"]],
];

const techIds = {};
let relCount = 0;
for (const [aid, name, tactics, platforms, comps] of TECHNIQUES) {
  const id = `attack-pattern--${xid("ap-"+aid)}`;
  techIds[aid] = id;
  const isSub = aid.includes(".");
  objects.push({
    type: "attack-pattern", id, name,
    external_references: [{ source_name: "mitre-attack", external_id: aid }],
    kill_chain_phases: tactics.map(t => ({ kill_chain_name: "mitre-attack", phase_name: t })),
    x_mitre_platforms: platforms,
    x_mitre_is_subtechnique: isSub,
  });
  for (const c of comps) {
    const cid = compIds[c];
    if (!cid) continue;
    objects.push({
      type:"relationship",
      id:`relationship--${xid("rd-"+(++relCount))}`,
      relationship_type:"detects",
      source_ref:cid, target_ref:id,
    });
  }
}

// ---------- intrusion sets / groups ----------
const GROUPS = [
  ["G0016","APT29",["Cozy Bear","Nobelium"],                ["T1059","T1078","T1098","T1110","T1003","T1018","T1057","T1083","T1526","T1021","T1027","T1547","T1041","T1071","T1136","T1133","T1190","T1566"]],
  ["G0007","APT28",["Fancy Bear","Sofacy"],                 ["T1059","T1078","T1003","T1110","T1547","T1018","T1083","T1027","T1041","T1071","T1133","T1190","T1566","T1112"]],
  ["G0034","Sandworm Team",[],                              ["T1059","T1547","T1018","T1003","T1485","T1486","T1490","T1027","T1543","T1133"]],
  ["G0096","APT41",[],                                      ["T1059","T1078","T1003","T1027","T1021","T1110","T1543","T1547","T1505","T1041","T1071","T1190"]],
  ["G0050","APT32",["OceanLotus"],                          ["T1059","T1078","T1547","T1027","T1018","T1057","T1071","T1041","T1133","T1566"]],
  ["G0035","Dragonfly",["Energetic Bear"],                  ["T1059","T1078","T1003","T1133","T1190","T1505","T1027","T1547","T1136"]],
  ["G0064","APT33",[],                                      ["T1059","T1110","T1003","T1027","T1547","T1041","T1190","T1566"]],
  ["G0094","Kimsuky",[],                                    ["T1059","T1547","T1078","T1057","T1041","T1071","T1027","T1190","T1566","T1133"]],
  ["G0032","Lazarus Group",["BeagleBoyz"],                  ["T1059","T1003","T1078","T1547","T1027","T1486","T1041","T1190","T1566","T1572"]],
  ["G0046","FIN7",[],                                       ["T1059","T1003","T1027","T1018","T1078","T1547","T1543","T1566","T1133","T1057","T1485"]],
  ["G0061","FIN8",[],                                       ["T1059","T1003","T1027","T1078","T1505","T1543","T1566","T1190"]],
  ["G0037","FIN6",[],                                       ["T1059","T1003","T1027","T1547","T1485","T1190","T1566"]],
  ["G0008","Carbanak",[],                                   ["T1059","T1003","T1027","T1547","T1543","T1078","T1566"]],
  ["G0102","Wizard Spider",["TrickBot Group"],              ["T1059","T1003","T1027","T1547","T1543","T1486","T1490","T1057","T1018","T1083","T1566"]],
  ["G0114","Chimera",[],                                    ["T1059","T1003","T1018","T1027","T1078","T1547"]],
  ["G0119","INDRIK SPIDER",["Evil Corp"],                   ["T1059","T1003","T1027","T1486","T1547","T1543","T1566"]],
  ["G1003","Ember Bear",[],                                 ["T1059","T1027","T1003","T1485","T1190","T1566"]],
  ["G1006","Earth Lusca",[],                                ["T1059","T1003","T1027","T1547","T1543","T1190","T1566"]],
  ["G1015","Scattered Spider",[],                           ["T1059","T1078","T1098","T1110","T1133","T1566","T1190","T1486","T1490"]],
  ["G0097","Bluenoroff",[],                                 ["T1059","T1027","T1003","T1547","T1041","T1566"]],
];

let useCount = 0;
for (const [gid, name, aliases, techs] of GROUPS) {
  const id = `intrusion-set--${xid("is-"+gid)}`;
  objects.push({
    type: "intrusion-set", id, name,
    aliases: [name, ...aliases],
    external_references: [{ source_name: "mitre-attack", external_id: gid }],
  });
  for (const t of techs) {
    const tid = techIds[t];
    if (!tid) continue;
    objects.push({
      type:"relationship",
      id:`relationship--${xid("ru-"+(++useCount))}`,
      relationship_type:"uses",
      source_ref:id, target_ref:tid,
    });
  }
}

const bundle = {
  type: "bundle",
  id: "bundle--offline-comprehensive-001",
  spec_version: "2.1",
  objects,
};

writeFileSync(process.argv[2] || "/dev/stdout", JSON.stringify(bundle));
console.error(`generated ${objects.length} STIX objects (${DATA_SOURCES.length} data sources, ${TECHNIQUES.length} techniques, ${GROUPS.length} groups)`);
