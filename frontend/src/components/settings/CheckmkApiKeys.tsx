import ApiKeys from "./ApiKeys";

export default function CheckmkApiKeys() {
  return (
    <ApiKeys
      defaultName="checkmk"
      purpose="checkmk"
      intro={
        <>
          Read-only service-account keys (Bearer <code className="text-slate-300">orbit_…</code>,
          rejected on non-GET). Keys created here are <strong>re-viewable</strong>: the token is
          kept encrypted so you can copy it again later. Revoking drops that copy.
        </>
      }
      createdLabel="Copy it into Checkmk:"
      usageExample={(key) => `ORBIT_URL=https://<dashboard>\nORBIT_API_KEY=${key}`}
    />
  );
}
