import ApiKeys from "./ApiKeys";

export default function PrometheusApiKeys() {
  return (
    <ApiKeys
      defaultName="prometheus"
      purpose="prometheus"
      intro={
        <>
          Read-only keys for scraping <code>/api/export/prometheus</code>. Use as{" "}
          <code>Authorization: Bearer orbit_…</code> (or <code>bearer_token</code> in Prometheus
          config). Keys are <strong>re-viewable</strong> and rejected on non-GET requests.
        </>
      }
      createdLabel="Use this key for Prometheus:"
      usageExample={(key) => `# prometheus.yml scrape config example
scrape_configs:
  - job_name: orbit
    metrics_path: /api/export/prometheus
    scheme: https
    bearer_token: '${key}'
    static_configs:
      - targets: ['dashboard.example.com']

# Or with explicit header:
# authorization:
#   credentials: '${key}'`}
      help={
        <>
          The Prometheus export always returns <strong>all</strong> evaluated checks for visible
          instances (no Checkmk-style selection rules or aggregation). Filter and alert in PromQL.
          Push instances are served from cache; direct instances are polled live on scrape.
        </>
      }
    />
  );
}
