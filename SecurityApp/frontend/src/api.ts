export type ScanField = "email" | "username" | "name" | "ssn" | "phone" | "address" | "ip";

export interface ToolResult {
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
  summary: {
    total_queries: number;
    total_tools_searched: number;
    tools_with_matches: number;
    total_matches: number;
    results_by_status: Record<string, number>;
  };
  results: ToolResult[];
  matches: [string, string][];
}

export interface SearchJob {
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
