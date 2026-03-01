# ============================================================
# BoltEdge SecToolkit — Sample Tool Page (IP Geolocation)
# Run from your Next.js project root
# Creates: app/tools/ip/geolocation/page.tsx
# ============================================================

Write-Host "=== Creating IP Geolocation Tool Page ===" -ForegroundColor Cyan

New-Item -ItemType Directory -Force -Path "app/tools/ip/geolocation" | Out-Null

$file = "app/tools/ip/geolocation/page.tsx"
Write-Host "  Writing $file..." -ForegroundColor Yellow

$content = @"
`"use client`";

import { useTool } from `"@/hooks/useTool`";
import ToolLayout from `"@/components/tools/ToolLayout`";
import { getToolById } from `"@/lib/toolRegistry`";

export default function IPGeolocationPage() {
  const tool = getToolById(`"ip-geolocation`");

  if (!tool) return null;

  const { execute, result, error, loading, executionTime } = useTool({
    endpoint: tool.endpoint,
  });

  return (
    <ToolLayout
      title={tool.name}
      description={tool.description}
      placeholder={tool.placeholder}
      inputLabel=`"IP Address`"
      loading={loading}
      error={error}
      result={result}
      executionTime={executionTime}
      onExecute={execute}
      resultRenderer={(data) => <GeolocationResult data={data} />}
    />
  );
}

/** Custom result renderer for geolocation data */
function GeolocationResult({ data }: { data: any }) {
  if (!data) return null;

  const location = data.location || {};
  const network = data.network || {};

  return (
    <div className=`"grid grid-cols-1 md:grid-cols-2 gap-6`">
      {/* Location Card */}
      <div className=`"space-y-3`">
        <h3 className=`"text-sm font-medium text-zinc-400 uppercase tracking-wider`">
          Location
        </h3>
        <div className=`"space-y-2`">
          <Row label=`"Country`" value={location.country} sub={location.country_code} />
          <Row label=`"Region`" value={location.region} />
          <Row label=`"City`" value={location.city} />
          <Row label=`"Postal Code`" value={location.postal_code} />
          <Row label=`"Timezone`" value={location.timezone} />
          <Row label=`"Continent`" value={location.continent} />
          {location.latitude && (
            <Row
              label=`"Coordinates`"
              value={location.latitude + `", `" + location.longitude}
            />
          )}
          <Row label=`"EU Member`" value={location.is_eu ? `"Yes`" : `"No`"} />
        </div>
      </div>

      {/* Network Card */}
      <div className=`"space-y-3`">
        <h3 className=`"text-sm font-medium text-zinc-400 uppercase tracking-wider`">
          Network
        </h3>
        <div className=`"space-y-2`">
          <Row label=`"ASN`" value={network.asn} />
          <Row label=`"Organisation`" value={network.organisation} />
          <Row label=`"Network`" value={network.network} />
        </div>
      </div>
    </div>
  );
}

/** Reusable key-value row */
function Row({
  label,
  value,
  sub,
}: {
  label: string;
  value: any;
  sub?: string;
}) {
  if (value === null || value === undefined) return null;
  return (
    <div className=`"flex justify-between items-center py-1.5 border-b border-zinc-800/50`">
      <span className=`"text-sm text-zinc-500`">{label}</span>
      <span className=`"text-sm text-zinc-200 font-mono`">
        {String(value)}
        {sub && (
          <span className=`"text-zinc-500 ml-1.5`">({sub})</span>
        )}
      </span>
    </div>
  );
}
"@
[System.IO.File]::WriteAllText($file, $content, [System.Text.UTF8Encoding]::new($false))

Write-Host ""
Write-Host "  Done!" -ForegroundColor Green
Write-Host ""
Write-Host "  Visit: http://localhost:3002/tools/ip/geolocation" -ForegroundColor Cyan
Write-Host ""
Write-Host "  This page uses:" -ForegroundColor White
Write-Host "    getToolById('ip-geolocation')  -> gets endpoint + metadata" -ForegroundColor Gray
Write-Host "    useTool({ endpoint })          -> manages loading/result/error" -ForegroundColor Gray
Write-Host "    ToolLayout                     -> shared input/button/results UI" -ForegroundColor Gray
Write-Host "    GeolocationResult              -> custom result renderer" -ForegroundColor Gray
Write-Host ""
Write-Host "  Pattern for all 101 tools:" -ForegroundColor Cyan
Write-Host "    app/tools/{category}/{tool}/page.tsx" -ForegroundColor Gray