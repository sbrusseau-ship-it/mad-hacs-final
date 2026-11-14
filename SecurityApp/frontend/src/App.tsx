import { type FormEvent, useState } from "react";

type ScanField = "email" | "username" | "password";

const scanFields: { id: ScanField; label: string; placeholder: string; type: string }[] = [
  { id: "email", label: "Email address", placeholder: "name@example.com", type: "email" },
  { id: "username", label: "Username", placeholder: "your_handle", type: "text" },
  { id: "password", label: "Password", placeholder: "Enter a password to check", type: "password" },
];

function ShieldIcon({ size = 18 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" aria-hidden="true">
      <path
        d="M12 3 5.5 5.7v5.6c0 4.2 2.7 7.9 6.5 9.7 3.8-1.8 6.5-5.5 6.5-9.7V5.7L12 3Z"
        stroke="currentColor"
        strokeWidth="1.7"
      />
      <path
        d="m9.2 12 1.8 1.8 3.9-4.2"
        stroke="currentColor"
        strokeWidth="1.7"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

function EyeIcon({ hidden }: { hidden: boolean }) {
  return (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" aria-hidden="true">
      <path
        d="M3 12s3.3-5 9-5 9 5 9 5-3.3 5-9 5-9-5-9-5Z"
        stroke="currentColor"
        strokeWidth="1.6"
      />
      <circle cx="12" cy="12" r="2.2" stroke="currentColor" strokeWidth="1.6" />
      {hidden && (
        <path d="m4 4 16 16" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" />
      )}
    </svg>
  );
}

export default function App() {
  const [enabled, setEnabled] = useState<Record<ScanField, boolean>>({
    email: true,
    username: true,
    password: false,
  });
  const [values, setValues] = useState<Record<ScanField, string>>({
    email: "",
    username: "",
    password: "",
  });
  const [showPassword, setShowPassword] = useState(false);
  const [isScanning, setIsScanning] = useState(false);
  const [scanMessage, setScanMessage] = useState("");

  const toggleField = (field: ScanField) => {
    setEnabled((current) => ({ ...current, [field]: !current[field] }));
    setScanMessage("");
  };

  const handleSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!isReady || isScanning) return;

    setScanMessage("");
    setIsScanning(true);
    try {
      const response = await fetch("/api/search", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          fields: activeFields.filter(({ id }) => values[id].trim()).map(({ id }) => id),
        }),
      });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);

      const data = await response.json();
      if (typeof data?.message !== "string" || !data.message.trim()) {
        throw new Error("Invalid demo response");
      }
      setScanMessage(data.message);
    } catch {
      setScanMessage("The demo request failed. Check that Flask is running and try again.");
    } finally {
      setIsScanning(false);
    }
  };

  const activeFields = scanFields.filter(({ id }) => enabled[id]);
  const isReady = activeFields.length > 0 && activeFields.some(({ id }) => values[id].trim());

  return (
    <main className="min-h-screen overflow-hidden bg-[#080a09] text-[#f2f5f0]">
      <div className="noise fixed inset-0 pointer-events-none" />

      <header className="relative z-10 border-b border-white/[0.14]">
        <div className="mx-auto flex h-[72px] max-w-[1440px] items-center justify-between px-5 sm:px-8 lg:px-12">
          <a href="#" className="group flex items-center gap-3" aria-label="Nulltrace home">
            <span className="grid h-9 w-9 place-items-center rounded-md border border-[#4da3ff]/30 bg-[#4da3ff]/[0.07] text-[#4da3ff] transition-colors group-hover:bg-[#4da3ff]/[0.12]">
              <ShieldIcon size={19} />
            </span>
            <span className="font-mono text-base font-semibold tracking-[0.1em]">
              Cat<span className="text-[#4da3ff]">Phish</span>
            </span>
          </a>

          <div className="flex items-center gap-3">
            <span className="hidden items-center gap-2 font-mono text-xs tracking-[0.1em] text-white/65 sm:flex">
              <span className="h-1.5 w-1.5 rounded-full bg-[#4da3ff] shadow-[0_0_8px_#4da3ff]" />
              SYSTEM OPERATIONAL
            </span>
            <button className="rounded-md border border-white/20 bg-white/[0.05] px-3 py-2 font-mono text-xs tracking-[0.06em] text-white/75 transition hover:border-white/35 hover:text-white">
              DOCS
            </button>
          </div>
        </div>
      </header>

      <section className="relative z-10 mx-auto max-w-[1440px] px-5 pb-12 pt-14 sm:px-8 lg:px-12 lg:pb-20 lg:pt-20">
        <div className="grid items-start gap-12 lg:grid-cols-[minmax(0,0.9fr)_minmax(520px,1.1fr)] lg:gap-20">
          <div className="max-w-xl pt-2">
            <div className="mb-6 flex items-center gap-3 font-mono text-xs tracking-[0.16em] text-[#4da3ff]">
              <span className="text-white/45">01</span>
              <span className="h-px w-8 bg-[#4da3ff]/50" />
              EXPOSURE CHECK
            </div>
            <h1 className="block border-none border-transparent text-[clamp(3rem,6vw,6.1rem)] font-medium leading-[0.94] tracking-[-0.055em] text-white shadow-[0_4px_4px_rgba(0,0,0,0.25),inset_0_4px_4px_rgba(0,0,0,0.25)] [--figma-make-local-effect-type:INNER_SHADOW]">
              Find what the
              <br />
              <span>internet knows.</span>
            </h1>
            <p className="mt-7 max-w-lg border-none border-transparent bg-[#4c4c4c] text-base leading-7 text-white/[0.86] sm:text-lg sm:leading-8">
              Search known breach records for exposed credentials. Get a clear signal, without the
              noise.
            </p>

            <div className="mt-10 grid max-w-lg grid-cols-3 border-y border-white/[0.14] py-5">
              <div>
                <div className="font-mono text-lg text-white">14.8B</div>
                <div className="mt-1 text-sm text-white/55">Records indexed</div>
              </div>
              <div className="border-l border-white/[0.14] pl-5 sm:pl-7">
                <div className="font-mono text-lg text-white">972</div>
                <div className="mt-1 text-sm text-white/55">Known breaches</div>
              </div>
              <div className="border-l border-white/[0.14] pl-5 sm:pl-7">
                <div className="font-mono text-lg text-[#4da3ff]">0</div>
                <div className="mt-1 text-sm text-white/55">Data retained</div>
              </div>
            </div>

            <div className="mt-8 flex gap-3 rounded-md border border-[#4da3ff]/15 bg-[#4da3ff]/[0.035] p-4">
              <span className="mt-0.5 shrink-0 text-[#4da3ff]">
                <ShieldIcon size={17} />
              </span>
              <p className="text-sm leading-6 text-white/65">
                Privacy first. Search values should be hashed client-side before reaching a
                production API. Never enter a password you currently use.
              </p>
            </div>
          </div>

          <div className="relative">
            <div className="absolute -inset-8 -z-10 bg-[radial-gradient(circle_at_center,rgba(77,163,255,0.06),transparent_64%)]" />
            <div className="overflow-hidden rounded-lg border border-white/[0.18] bg-[#0d100e]/95 shadow-2xl shadow-black/50">
              <div className="flex items-center justify-between border-b border-white/[0.14] px-5 py-4">
                <div className="flex items-center gap-2">
                  <span className="h-2 w-2 rounded-full bg-[#ff5d55]/70" />
                  <span className="h-2 w-2 rounded-full bg-[#ffbd2e]/70" />
                  <span className="h-2 w-2 rounded-full bg-[#4da3ff]/70" />
                </div>
                <span className="font-mono text-[11px] tracking-[0.12em] text-white/50">
                  SECURE QUERY // V0.1
                </span>
              </div>

              <form onSubmit={handleSubmit} className="p-5 sm:p-7">
                <div className="mb-7">
                  <p className="font-mono text-xs uppercase tracking-[0.12em] text-white/60">
                    Select identifiers
                  </p>
                  <div className="mt-3 flex flex-wrap gap-2">
                    {scanFields.map((field) => (
                      <button
                        key={field.id}
                        type="button"
                        disabled={isScanning}
                        onClick={() => toggleField(field.id)}
                        className={`rounded border px-3 py-2 font-mono text-xs tracking-[0.06em] transition ${
                          enabled[field.id]
                            ? "border-[#4da3ff]/40 bg-[#4da3ff]/10 text-[#4da3ff]"
                            : "border-white/20 bg-white/[0.03] text-white/60 hover:border-white/35 hover:text-white/80"
                        }`}
                      >
                        <span className="mr-1.5">{enabled[field.id] ? "×" : "+"}</span>
                        {field.label.toUpperCase()}
                      </button>
                    ))}
                  </div>
                </div>

                <div className="space-y-5">
                  {activeFields.map((field, index) => (
                    <label key={field.id} className="block">
                      <span className="mb-2 flex items-center justify-between">
                        <span className="font-mono text-sm text-white/80">
                          <span className="mr-2 text-[#4da3ff]/75">0{index + 1}</span>
                          {field.label}
                        </span>
                        <span className="font-mono text-[10px] uppercase tracking-wider text-white/45">
                          Optional
                        </span>
                      </span>
                      <span className="relative block">
                        <span className="pointer-events-none absolute left-4 top-1/2 -translate-y-1/2 font-mono text-sm text-[#4da3ff]/55">
                          &gt;_
                        </span>
                        <input
                          type={field.id === "password" && showPassword ? "text" : field.type}
                          value={values[field.id]}
                          disabled={isScanning}
                          onChange={(event) => {
                            setValues((current) => ({
                              ...current,
                              [field.id]: event.target.value,
                            }));
                            setScanMessage("");
                          }}
                          placeholder={field.placeholder}
                          autoComplete={field.id === "password" ? "new-password" : field.id}
                          className="h-13 w-full rounded-md border border-white/20 bg-black/25 pl-13 pr-12 font-mono text-sm text-white outline-none transition placeholder:text-white/40 focus:border-[#4da3ff]/75 focus:bg-[#4da3ff]/[0.04] focus:shadow-[0_0_0_3px_rgba(77,163,255,0.08)]"
                        />
                        {field.id === "password" && (
                          <button
                            type="button"
                            aria-label={showPassword ? "Hide password" : "Show password"}
                            onClick={() => setShowPassword((current) => !current)}
                            className="absolute right-3 top-1/2 -translate-y-1/2 p-2 text-white/55 transition hover:text-white"
                          >
                            <EyeIcon hidden={!showPassword} />
                          </button>
                        )}
                      </span>
                    </label>
                  ))}
                </div>

                {activeFields.length === 0 && (
                  <div className="grid h-28 place-items-center rounded-md border border-dashed border-white/25 text-center">
                    <p className="font-mono text-sm text-white/55">
                      Select at least one identifier to begin.
                    </p>
                  </div>
                )}

                <button
                  type="submit"
                  disabled={!isReady || isScanning}
                  className="mt-7 flex h-13 w-full items-center justify-center gap-3 rounded-md border border-[#4da3ff] bg-[#4da3ff]/30 px-4 font-mono text-sm font-bold tracking-[0.08em] text-[#4da3ff]/50 transition hover:bg-[#4da3ff]/40 disabled:cursor-not-allowed disabled:bg-[#4da3ff]/30 disabled:text-[#4da3ff]/50"
                >
                  {isScanning ? (
                    <>
                      <span className="h-3.5 w-3.5 animate-spin rounded-full border-2 border-black/25 border-t-black" />
                      SENDING DEMO REQUEST
                    </>
                  ) : (
                    <>
                      RUN EXPOSURE CHECK <span aria-hidden="true">→</span>
                    </>
                  )}
                </button>

                {scanMessage && (
                  <div className="mt-5 border-l-2 border-[#4da3ff] bg-[#4da3ff]/[0.06] px-4 py-3">
                    <p role="status" className="text-sm leading-6 text-white/65">
                      {scanMessage}
                    </p>
                  </div>
                )}

                <div className="mt-5 flex items-center justify-center gap-2 font-mono text-[10px] tracking-[0.08em] text-white/45">
                  <ShieldIcon size={12} />
                  ENCRYPTED IN TRANSIT · NO SEARCH HISTORY
                </div>
              </form>
            </div>
            <div className="mt-3 flex justify-between px-1 font-mono text-[10px] tracking-[0.08em] text-white/40">
              <span>REQUEST_ID: LOCAL_PREVIEW</span>
              <span>LATENCY: --MS</span>
            </div>
          </div>
        </div>
      </section>
    </main>
  );
}
