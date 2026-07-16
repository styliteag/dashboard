// Two-letter GeoIP country badge shown next to IPs everywhere. The hover
// title carries everything else the local GeoLite2 DB knows (city, region ·
// country name · continent · EU) — supplied by the backend as `name`.
export default function CountryTag({
  code,
  name,
}: {
  code?: string | null;
  name?: string | null;
}) {
  if (!code) return null;
  return (
    <span
      className="ml-1 rounded bg-slate-800 px-1 py-0.5 text-[10px] text-slate-300"
      title={name ?? undefined}
    >
      {code}
    </span>
  );
}
