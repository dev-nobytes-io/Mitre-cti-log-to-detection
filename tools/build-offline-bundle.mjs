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

// Log sources ((name, channel) tuples) per data component. These get
// embedded as x_mitre_log_sources[] on the corresponding data component
// object — the same shape MITRE ATT&CK v18+ ships in attack-stix-data.
// Components not in this map fall back to a generic placeholder so the
// chain Log Source -> Component -> Analytic -> Strategy still resolves.
const LOG_SOURCES_BY_COMPONENT = {
  "Process Creation":               [["sysmon","1"],["windows-security","4688"],["auditd","execve"]],
  "Process Termination":            [["sysmon","5"],["windows-security","4689"]],
  "Process Access":                 [["sysmon","10"]],
  "Process Metadata":               [["sysmon","1"]],
  "Process Modification":           [["sysmon","8"]],
  "OS API Execution":               [["sysmon","1"]],
  "Command Execution":              [["powershell","4104"],["windows-security","4688"],["sysmon","1"]],
  "Script Execution":               [["powershell","4104"],["powershell","4103"]],
  "Module Load":                    [["sysmon","7"]],
  "File Creation":                  [["sysmon","11"],["auditd","CREATE"]],
  "File Modification":              [["sysmon","11"],["auditd","WRITE"]],
  "File Deletion":                  [["sysmon","23"],["auditd","DELETE"]],
  "File Access":                    [["auditd","ACCESS"]],
  "File Metadata":                  [["sysmon","11"]],
  "Network Connection Creation":    [["sysmon","3"],["zeek","conn"],["netflow","v9"]],
  "Network Traffic Flow":           [["zeek","conn"],["netflow","v9"]],
  "Network Traffic Content":        [["zeek","http"],["zeek","ssl"],["suricata","alert"]],
  "Logon Session Creation":         [["windows-security","4624"],["windows-security","4625"],["auditd","USER_LOGIN"]],
  "Logon Session Metadata":         [["windows-security","4624"]],
  "User Account Authentication":    [["windows-security","4624"],["okta","system"],["azure-signinlogs","SignInLogs"]],
  "User Account Creation":          [["windows-security","4720"],["azure-auditlogs","Add user"]],
  "User Account Modification":      [["windows-security","4738"],["azure-auditlogs","Update user"]],
  "User Account Deletion":          [["windows-security","4726"]],
  "User Account Metadata":          [["windows-security","4624"]],
  "Windows Registry Key Creation":     [["sysmon","12"]],
  "Windows Registry Key Modification": [["sysmon","13"]],
  "Windows Registry Key Deletion":     [["sysmon","12"]],
  "Windows Registry Key Access":       [["sysmon","12"]],
  "Service Creation":               [["windows-system","7045"]],
  "Service Metadata":               [["windows-security","4697"]],
  "Service Modification":           [["windows-security","4697"]],
  "Driver Load":                    [["sysmon","6"]],
  "Driver Metadata":                [["sysmon","6"]],
  "Scheduled Job Creation":         [["windows-security","4698"]],
  "Scheduled Job Modification":     [["windows-security","4702"]],
  "Scheduled Job Metadata":         [["windows-security","4698"]],
  "Application Log Content":        [["application-log","generic"],["okta","system"],["m365","unifiedauditlog"]],
  "Cloud Service Enumeration":      [["aws-cloudtrail","management"],["azure-activity","activity"]],
  "Cloud Service Metadata":         [["aws-cloudtrail","management"]],
  "Cloud Service Modification":     [["aws-cloudtrail","management"]],
  "Cloud Service Disable":          [["aws-cloudtrail","management"]],
  "Cloud Storage Access":           [["aws-cloudtrail","data"]],
  "Cloud Storage Modification":     [["aws-cloudtrail","data"]],
  "Cloud Storage Deletion":         [["aws-cloudtrail","data"]],
  "Cloud Storage Creation":         [["aws-cloudtrail","data"]],
  "Cloud Storage Enumeration":      [["aws-cloudtrail","management"]],
  "Cloud Storage Metadata":         [["aws-cloudtrail","management"]],
  "Snapshot Creation":              [["aws-cloudtrail","management"]],
  "Snapshot Deletion":              [["aws-cloudtrail","management"]],
  "Snapshot Enumeration":           [["aws-cloudtrail","management"]],
  "Snapshot Metadata":              [["aws-cloudtrail","management"]],
  "Snapshot Modification":          [["aws-cloudtrail","management"]],
  "Active Directory Object Modification": [["windows-security","5136"]],
  "Active Directory Object Creation":     [["windows-security","5137"]],
  "Active Directory Object Deletion":     [["windows-security","5141"]],
  "Active Directory Object Access":       [["windows-security","4662"]],
  "Active Directory Credential Request":  [["windows-security","4769"]],
  "Group Enumeration":              [["windows-security","4799"]],
  "Group Metadata":                 [["windows-security","4799"]],
  "Group Modification":             [["windows-security","4732"]],
  "Network Share Access":           [["windows-security","5140"]],
  "Firewall Rule Modification":     [["windows-security","4946"]],
  "Firewall Disable":               [["windows-security","4954"]],
  "Firewall Metadata":              [["windows-security","4954"]],
  "Firewall Enumeration":           [["windows-security","4954"]],
  "Web Credential Usage":           [["aws-cloudtrail","management"]],
  "Web Credential Creation":        [["okta","system"]],
  "Sensor Health":                  [["sensor-health","ping"]],
  "Host Status":                    [["sensor-health","ping"]],
  "Kernel Module Load":             [["auditd","KERN_MODULE"]],
  "Container Creation":             [["k8s-audit","pods"],["docker","events"]],
  "Container Start":                [["k8s-audit","pods"],["docker","events"]],
  "Container Enumeration":          [["k8s-audit","pods"]],
  "Container Metadata":             [["k8s-audit","pods"]],
  "Pod Creation":                   [["k8s-audit","pods"]],
  "Pod Modification":               [["k8s-audit","pods"]],
  "Pod Enumeration":                [["k8s-audit","pods"]],
  "Pod Metadata":                   [["k8s-audit","pods"]],
  "Cluster Metadata":               [["k8s-audit","cluster"]],
  "Image Creation":                 [["aws-cloudtrail","management"]],
  "Image Deletion":                 [["aws-cloudtrail","management"]],
  "Image Metadata":                 [["aws-cloudtrail","management"]],
  "Image Modification":             [["aws-cloudtrail","management"]],
  "Instance Creation":              [["aws-cloudtrail","management"]],
  "Instance Deletion":              [["aws-cloudtrail","management"]],
  "Instance Modification":          [["aws-cloudtrail","management"]],
  "Instance Enumeration":           [["aws-cloudtrail","management"]],
  "Instance Metadata":              [["aws-cloudtrail","management"]],
  "Instance Start":                 [["aws-cloudtrail","management"]],
  "Instance Stop":                  [["aws-cloudtrail","management"]],
  "Volume Creation":                [["aws-cloudtrail","management"]],
  "Volume Deletion":                [["aws-cloudtrail","management"]],
  "Volume Modification":            [["aws-cloudtrail","management"]],
  "Volume Enumeration":             [["aws-cloudtrail","management"]],
  "Volume Metadata":                [["aws-cloudtrail","management"]],
  "Drive Access":                   [["sysmon","9"]],
  "Drive Creation":                 [["sysmon","9"]],
  "Drive Modification":             [["sysmon","9"]],
  "Named Pipe Metadata":            [["sysmon","17"]],
  "Firmware Modification":          [["sensor-health","firmware"]],
  "Certificate Registration":       [["public-data","cert-stream"]],
  "Active DNS":                     [["public-data","dns"]],
  "Passive DNS":                    [["public-data","dns"]],
  "Domain Registration":            [["public-data","whois"]],
  "Response Content":               [["public-data","scan"]],
  "Response Metadata":              [["public-data","scan"]],
  "Malware Content":                [["public-data","sandbox"]],
  "Malware Metadata":               [["public-data","sandbox"]],
  "Social Media":                   [["public-data","social"]],
  "WMI Creation":                   [["sysmon","19"]],
};

const dsIds = {};
const compIds = {};
const compMeta = {}; // cid -> { name, sourceName, logSources: [{name, channel}] }
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
    const tuples = LOG_SOURCES_BY_COMPONENT[c] || [["generic", c.toLowerCase().replace(/\s+/g,"-")]];
    const logSources = tuples.map(([n, ch]) => ({ name: n, channel: ch }));
    compMeta[cid] = { name: c, sourceName: name, logSources };
    objects.push({
      type: "x-mitre-data-component",
      id: cid,
      name: c,
      x_mitre_data_source_ref: id,
      x_mitre_log_sources: logSources,
    });
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

// ---------- analytics + detection strategies ----------
// Each detection strategy groups one or more analytics; each analytic
// references log sources via x_mitre_log_source_references[] (each entry
// pins a (data-component, name, channel) triple). Strategies are linked
// to techniques via STIX `detects` relationships (source = strategy).
//
// Format mirrors github.com/mitre-attack/attack-stix-data v18.1+:
//   x-mitre-detection-strategy { x_mitre_analytic_refs: [analyticId, ...] }
//   x-mitre-analytic            { x_mitre_log_source_references: [{x_mitre_data_component_ref, name, channel}, ...] }
//
// Tuples below are [strategyId, name, [analytics]], where each analytic
// is [name, description, platforms, [componentName -> uses all its log sources]].
const STRATEGIES = [
  ["DET0001", "Suspicious Process Creation Chains",
    [
      ["Encoded PowerShell via Sysmon", "Sysmon EID 1 with -EncodedCommand or base64 payloads",
        ["Windows"], ["Process Creation","Command Execution"], ["T1059"]],
      ["Process spawn anomalies on Linux", "auditd execve traces of unusual parent/child pairs",
        ["Linux"], ["Process Creation","Command Execution"], ["T1059"]],
    ],
  ],
  ["DET0002", "Lateral Movement via Remote Logon",
    [
      ["Windows interactive logon from non-RDP host", "4624 type 10 plus uncommon source IPs",
        ["Windows"], ["Logon Session Creation","User Account Authentication","Network Connection Creation"], ["T1021","T1078"]],
    ],
  ],
  ["DET0003", "Defense Impairment",
    [
      ["Windows Defender disabled via service", "4697 + service modification events",
        ["Windows"], ["Service Modification","Process Creation","Command Execution"], ["T1562"]],
      ["Firewall rule disabled", "4946 / 4954 firewall events",
        ["Windows"], ["Firewall Disable","Firewall Rule Modification"], ["T1562"]],
    ],
  ],
  ["DET0004", "Credential Access via OS Tools",
    [
      ["lsass access by non-system process", "Sysmon EID 10 ProcessAccess of lsass.exe",
        ["Windows"], ["Process Access","Process Creation","OS API Execution"], ["T1003"]],
      ["Brute-force authentication patterns", "Repeated 4625 / Okta failures from one source",
        ["Windows"], ["User Account Authentication","Logon Session Creation","Application Log Content"], ["T1110"]],
    ],
  ],
  ["DET0005", "Cloud Service Manipulation",
    [
      ["IAM policy or trust modification", "CloudTrail PutUserPolicy / PutRolePolicy / UpdateAssumeRolePolicy",
        ["IaaS"], ["Cloud Service Modification","Cloud Service Enumeration"], ["T1098","T1526"]],
      ["Snapshot or storage wipe", "CloudTrail DeleteSnapshot / DeleteBucket bursts",
        ["IaaS"], ["Cloud Storage Deletion","Snapshot Deletion","Cloud Storage Modification"], ["T1485","T1490"]],
    ],
  ],
  ["DET0006", "C2 Beaconing",
    [
      ["Periodic outbound beacons", "Zeek conn.log periodicity + low byte count",
        ["Network"], ["Network Connection Creation","Network Traffic Flow","Network Traffic Content"], ["T1071","T1572","T1041"]],
    ],
  ],
];

let analyticCount = 0;
let strategyCount = 0;
const detectsRelsCount = { n: 0 };
for (const [strategyExtId, stratName, analytics] of STRATEGIES) {
  const stratId = `x-mitre-detection-strategy--${xid("ds-"+strategyExtId)}`;
  const analyticIds = [];
  // techniques this strategy collectively detects (union over analytics)
  const stratTechIds = new Set();
  for (const [aname, adesc, aPlatforms, componentNames, attackTechIds] of analytics) {
    const aid = `x-mitre-analytic--${xid("an-"+(++analyticCount))}`;
    const refs = [];
    for (const cn of componentNames) {
      const cid = compIds[cn];
      if (!cid) continue;
      const meta = compMeta[cid];
      if (!meta) continue;
      for (const ls of meta.logSources) {
        refs.push({ x_mitre_data_component_ref: cid, name: ls.name, channel: ls.channel });
      }
    }
    objects.push({
      type: "x-mitre-analytic",
      id: aid,
      name: aname,
      description: adesc,
      x_mitre_platforms: aPlatforms,
      x_mitre_log_source_references: refs,
    });
    analyticIds.push(aid);
    for (const t of attackTechIds) {
      const tid = techIds[t];
      if (tid) stratTechIds.add(tid);
    }
  }
  objects.push({
    type: "x-mitre-detection-strategy",
    id: stratId,
    name: stratName,
    description: `Detection strategy ${strategyExtId}: ${stratName}`,
    external_references: [{ source_name: "mitre-attack", external_id: strategyExtId }],
    x_mitre_analytic_refs: analyticIds,
  });
  strategyCount += 1;
  // detects rels: strategy -> technique (the v18+ pattern)
  for (const tid of stratTechIds) {
    objects.push({
      type: "relationship",
      id: `relationship--${xid("rds-"+(++detectsRelsCount.n))}`,
      relationship_type: "detects",
      source_ref: stratId,
      target_ref: tid,
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
console.error(`generated ${objects.length} STIX objects (${DATA_SOURCES.length} data sources, ${TECHNIQUES.length} techniques, ${GROUPS.length} groups, ${analyticCount} analytics, ${strategyCount} detection strategies)`);
