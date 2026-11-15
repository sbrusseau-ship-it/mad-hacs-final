export type ScanField = "email" | "username" | "name" | "ssn" | "phone" | "address" | "ip";

export interface ToolResult {
  backend?: "browser" | "sherlock";
  input_value: string;
  input_type: string;
  tool_name: string;
  category: string;
  url_searched: string;
  status: string;
  match_count: number;
  match_details: string[];
  source_url?: string | null;
  final_url?: string | null;
  error?: string | null;
}

export interface SearchResult {
  grade?: {
    percent_matches: number;
    total_sites: number;
    sites_with_hits: number;
    total_matches: number;
  } | null;
  summary: {
    total_queries: number;
    total_tools_searched: number;
    total_tools_planned?: number;
    tools_with_matches: number;
    total_matches: number;
    results_by_status: Record<string, number>;
  };
  results: ToolResult[];
  matches: [string, string][];
}

export interface SearchJob {
  progress?: { completed_sources: number; total_sources: number } | null;
  id: string;
  status: "queued" | "running" | "completed" | "failed";
  message?: string;
  error?: string | null;
  result?: SearchResult | null;
}

async function request(path: string, signal: AbortSignal, body?: unknown): Promise<SearchJob> {
  const response = await fetch(path, {
    method: body ? "POST" : "GET",
    headers: body ? { "Content-Type": "application/json" } : undefined,
    body: body ? JSON.stringify(body) : undefined,
    signal,
  });
  const data = await response.json().catch(() => null);
  if (!response.ok) {
    const fields = data?.fields && typeof data.fields === "object"
      ? Object.values(data.fields).join(" ") : "";
    throw new Error(typeof data?.error === "string"
      ? `${data.error}${fields ? ` ${fields}` : ""}`
      : `Search request failed (HTTP ${response.status}).`);
  }
  if (typeof data?.id !== "string" || !["queued", "running", "completed", "failed"].includes(data.status)) {
    throw new Error("The server returned an invalid search response.");
  }
  return data;
}

export const startSearch = (identifiers: Partial<Record<ScanField, string>>, signal: AbortSignal) =>
  request("/api/search", signal, { identifiers });

export const getSearch = (id: string, signal: AbortSignal) =>
  request(`/api/search/${encodeURIComponent(id)}`, signal);

function streamSearch(id: string, signal: AbortSignal, onUpdate: (job: SearchJob) => void): Promise<SearchJob> {
  return new Promise((resolve, reject) => {
    if (signal.aborted) { reject(new DOMException("Aborted", "AbortError")); return; }
    const events = new EventSource(`/api/search/${encodeURIComponent(id)}/events`);
    const close = () => { events.close(); signal.removeEventListener("abort", abort); };
    const abort = () => { close(); reject(new DOMException("Aborted", "AbortError")); };
    signal.addEventListener("abort", abort, { once: true });
    events.onmessage = (event) => {
      try {
        const job: SearchJob = JSON.parse(event.data);
        if (job.id !== id || !["queued", "running", "completed", "failed"].includes(job.status)) {
          throw new Error("Invalid live search response.");
        }
        onUpdate(job);
        if (job.status === "completed" || job.status === "failed") { close(); resolve(job); }
      } catch (error) { close(); reject(error); }
    };
    events.onerror = () => { close(); reject(new Error("Live updates disconnected.")); };
  });
}

// A proxy/network that cannot stream can still deliver partial results by polling.
export async function followSearch(id: string, signal: AbortSignal, onUpdate: (job: SearchJob) => void): Promise<SearchJob> {
  try { return await streamSearch(id, signal, onUpdate); }
  catch (error) { if (signal.aborted) throw error; }
  while (true) {
    const job = await getSearch(id, signal);
    onUpdate(job);
    if (job.status === "completed" || job.status === "failed") return job;
    await new Promise<void>((resolve, reject) => {
      const abort = () => { clearTimeout(timer); reject(new DOMException("Aborted", "AbortError")); };
      const timer = window.setTimeout(() => { signal.removeEventListener("abort", abort); resolve(); }, 1000);
      signal.addEventListener("abort", abort, { once: true });
    });
  }
}
