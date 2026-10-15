const names: Record<number, string> = {
  1: "A · IPv4",
  28: "AAAA · IPv6",
  5: "CNAME · alias",
  65: "HTTPS · service",
  15: "MX · mail",
  16: "TXT · text",
  33: "SRV · service",
  12: "PTR · reverse",
  2: "NS · nameserver",
  6: "SOA · authority",
  43: "DS · delegation",
  64: "SVCB · service",
  255: "ANY",
};
export function dnsTypeName(kind: number): string {
  return names[kind] ?? `Type ${kind}`;
}
export function typeScopeText(scope: { include: number[]; exclude: number[] }): string {
  const include = scope.include.length ? scope.include.map(dnsTypeName).join(", ") : "All types";
  return scope.exclude.length
    ? `${include}; except ${scope.exclude.map(dnsTypeName).join(", ")}`
    : include;
}

export function clientScopeText(scope: { include: string[]; exclude: string[] }): string {
  const include = scope.include.length ? scope.include.join(", ") : "All clients";
  return scope.exclude.length ? `${include}; except ${scope.exclude.join(", ")}` : include;
}

export const clientFilteringTags = [
  "device_audio",
  "device_camera",
  "device_gameconsole",
  "device_laptop",
  "device_nas",
  "device_pc",
  "device_phone",
  "device_printer",
  "device_securityalarm",
  "device_tablet",
  "device_tv",
  "device_other",
  "os_android",
  "os_ios",
  "os_linux",
  "os_macos",
  "os_windows",
  "os_other",
  "user_admin",
  "user_regular",
  "user_child",
] as const;
