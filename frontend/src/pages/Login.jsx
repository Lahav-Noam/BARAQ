import { useEffect, useState } from "react";
import { api, authStore } from "../api.js";
import { useAuth } from "../context/AuthContext.jsx";

export default function Login() {
  const { login } = useAuth();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [challenge, setChallenge] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [sso, setSso] = useState(null);
  const [mode, setMode] = useState("login"); // login | register
  const [notice, setNotice] = useState("");

  const [regForm, setRegForm] = useState({
    username: "",
    full_name: "",
    org: "",
    password: "",
    confirm: "",
  });

  useEffect(() => {
    api
      .get("/api/auth/oidc/status")
      .then(setSso)
      .catch(() => setSso(null));
  }, []);

  const submit = async (e) => {
    e.preventDefault();
    setBusy(true);
    setError("");
    setNotice("");
    try {
      if (challenge) {
        const res = await api.mfaVerify(challenge, code.trim());
        authStore.set(res.token);
        login(res);
        return;
      }
      if (mode === "register") {
        if (regForm.password !== regForm.confirm) {
          setError("Passwords do not match");
          return;
        }
        const res = await api.register({
          username: regForm.username.trim(),
          full_name: regForm.full_name.trim(),
          org: regForm.org.trim(),
          password: regForm.password,
        });
        setNotice(res.message || "Account created - awaiting administrator verification.");
        setMode("login");
        setUsername(regForm.username.trim());
        setPassword("");
        setRegForm({ username: "", full_name: "", org: "", password: "", confirm: "" });
        return;
      }
      const res = await api.login(username.trim(), password);
      if (res.mfa_required) {
        setChallenge(res.challenge);
        return;
      }
      authStore.set(res.token);
      login(res);
    } catch (err) {
      setError(err.message.replace(/^\d+: /, ""));
    } finally {
      setBusy(false);
    }
  };

  const switchMode = (next) => {
    setMode(next);
    setError("");
    setNotice("");
    setChallenge("");
    setCode("");
  };

  const cancelMfa = () => {
    setChallenge("");
    setCode("");
    setError("");
  };

  const inputCls =
    "w-full rounded-lg border border-slate-700 bg-slate-950 px-3.5 py-2.5 text-sm text-slate-100 outline-none transition-colors placeholder:text-slate-600 focus:border-teal-500";

  return (
    <div className="flex min-h-screen items-center justify-center bg-[#080e14] px-4">
      <div
        className="pointer-events-none fixed inset-0"
        style={{
          background:
            "radial-gradient(600px 400px at 20% 10%, rgba(20,184,166,0.07), transparent 60%), radial-gradient(600px 400px at 80% 90%, rgba(234,179,8,0.06), transparent 60%)",
        }}
      />
      <div className="relative w-full max-w-sm">
        <div className="mb-8 flex flex-col items-center gap-3">
          <svg className="h-16 w-16" viewBox="0 0 64 64">
            <defs>
              <linearGradient id="lgShield" x1="0%" y1="0%" x2="100%" y2="100%">
                <stop offset="0%" stopColor="#14b8a6" />
                <stop offset="100%" stopColor="#eab308" />
              </linearGradient>
              <filter id="lgGlow" x="-40%" y="-40%" width="180%" height="180%">
                <feGaussianBlur stdDeviation="2.4" result="blur" />
                <feMerge>
                  <feMergeNode in="blur" />
                  <feMergeNode in="SourceGraphic" />
                </feMerge>
              </filter>
            </defs>
            <path
              d="M32 3 L57 13.5 L57 30 Q57 47 32 61 Q7 47 7 30 L7 13.5 Z"
              fill="url(#lgShield)"
              opacity="0.16"
            />
            <path
              d="M32 3 L57 13.5 L57 30 Q57 47 32 61 Q7 47 7 30 L7 13.5 Z"
              fill="none"
              stroke="url(#lgShield)"
              strokeWidth="2"
              opacity="0.9"
            />
            <path
              d="M36.5 12 L22 34.5 L30.5 34.5 L26.5 52 L44 27.5 L34.5 27.5 Z"
              fill="#14b8a6"
              filter="url(#lgGlow)"
            />
          </svg>
          <div className="text-center">
            <h1 className="text-2xl font-bold tracking-wide text-white">BARAQ</h1>
            <p className="mt-1 text-xs font-semibold uppercase tracking-[0.25em] text-teal-400">
              {mode === "register" ? "Account Registration" : "Operator Access"}
            </p>
          </div>
        </div>

        <form
          onSubmit={submit}
          className="glass-line space-y-4 rounded-2xl bg-[#0f1a24]/85 p-6 shadow-[0_0_60px_-15px_rgba(20,184,166,0.3)] backdrop-blur-xl"
        >
          {challenge ? (
            <div>
              <label className="mb-1.5 block text-xs font-medium text-slate-400" htmlFor="code">
                Verification code
              </label>
              <input
                id="code"
                inputMode="numeric"
                autoComplete="one-time-code"
                value={code}
                onChange={(e) => setCode(e.target.value.replace(/[^0-9]/g, "").slice(0, 6))}
                autoFocus
                required
                placeholder="6-digit authenticator code"
                className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3.5 py-2.5 text-center font-mono text-lg tracking-[0.5em] text-slate-100 outline-none transition-colors placeholder:text-sm placeholder:tracking-normal placeholder:text-slate-600 focus:border-teal-500"
              />
              <p className="mt-2 text-center text-[11px] text-slate-500">
                Password verified for{" "}
                <span className="font-mono text-teal-400">{username}</span> — enter
                the code from your authenticator app.
              </p>
            </div>
          ) : mode === "register" ? (
            <>
              <div>
                <label className="mb-1.5 block text-xs font-medium text-slate-400" htmlFor="reg-username">
                  Username
                </label>
                <input
                  id="reg-username"
                  value={regForm.username}
                  onChange={(e) => setRegForm({ ...regForm, username: e.target.value })}
                  autoComplete="username"
                  autoFocus
                  required
                  minLength={3}
                  pattern="[a-zA-Z0-9_.-]+"
                  className={inputCls}
                  placeholder="e.g. j.doe"
                />
              </div>
              <div>
                <label className="mb-1.5 block text-xs font-medium text-slate-400" htmlFor="reg-name">
                  Full name <span className="text-slate-600">(optional)</span>
                </label>
                <input
                  id="reg-name"
                  value={regForm.full_name}
                  onChange={(e) => setRegForm({ ...regForm, full_name: e.target.value })}
                  autoComplete="name"
                  className={inputCls}
                  placeholder="Jane Doe"
                />
              </div>
              <div>
                <label className="mb-1.5 block text-xs font-medium text-slate-400" htmlFor="reg-org">
                  Organization <span className="text-slate-600">(optional)</span>
                </label>
                <input
                  id="reg-org"
                  value={regForm.org}
                  onChange={(e) => setRegForm({ ...regForm, org: e.target.value })}
                  className={inputCls}
                  placeholder="e.g. fintech-prod"
                />
              </div>
              <div>
                <label className="mb-1.5 block text-xs font-medium text-slate-400" htmlFor="reg-password">
                  Password <span className="text-slate-600">(min 8 characters)</span>
                </label>
                <input
                  id="reg-password"
                  type="password"
                  value={regForm.password}
                  onChange={(e) => setRegForm({ ...regForm, password: e.target.value })}
                  autoComplete="new-password"
                  required
                  minLength={8}
                  className={inputCls}
                  placeholder="••••••••"
                />
              </div>
              <div>
                <label className="mb-1.5 block text-xs font-medium text-slate-400" htmlFor="reg-confirm">
                  Confirm password
                </label>
                <input
                  id="reg-confirm"
                  type="password"
                  value={regForm.confirm}
                  onChange={(e) => setRegForm({ ...regForm, confirm: e.target.value })}
                  autoComplete="new-password"
                  required
                  minLength={8}
                  className={inputCls}
                  placeholder="••••••••"
                />
              </div>
              <p className="rounded-lg border border-amber-500/25 bg-amber-500/10 px-3 py-2 text-[11px] leading-relaxed text-amber-300">
                New accounts are created as analysts and stay locked until an
                administrator verifies them. You will be able to sign in once your
                account is approved.
              </p>
            </>
          ) : (
            <>
              <div>
                <label className="mb-1.5 block text-xs font-medium text-slate-400" htmlFor="username">
                  Username
                </label>
                <input
                  id="username"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  autoComplete="username"
                  autoFocus
                  required
                  className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3.5 py-2.5 text-sm text-slate-100 outline-none transition-colors placeholder:text-slate-600 focus:border-teal-500"
                  placeholder="e.g. admin"
                />
              </div>
              <div>
                <label className="mb-1.5 block text-xs font-medium text-slate-400" htmlFor="password">
                  Password
                </label>
                <input
                  id="password"
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  autoComplete="current-password"
                  required
                  className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3.5 py-2.5 text-sm text-slate-100 outline-none transition-colors placeholder:text-slate-600 focus:border-teal-500"
                  placeholder="••••••••"
                />
              </div>
            </>
          )}

          {error && (
            <p className="rounded-lg border px-4 py-2.5 text-sm" style={{ background: "var(--error-bg, #fef2f2)", borderColor: "var(--error-border, #fecaca)", color: "var(--error-text, #991b1b)" }}>
              {error}
            </p>
          )}

          {notice && (
            <p className="rounded-lg border px-4 py-2.5 text-sm" style={{ background: "var(--success-bg, #ecfdf5)", borderColor: "var(--success-border, #a7f3d0)", color: "var(--success-text, #065f46)" }}>
              {notice}
            </p>
          )}

          <button
            type="submit"
            disabled={busy}
            className="w-full rounded-lg bg-gradient-to-r from-teal-600 to-teal-500 px-4 py-2.5 text-sm font-semibold text-white transition-all hover:from-teal-500 hover:to-teal-400 disabled:opacity-50"
          >
            {busy
              ? challenge
                ? "Verifying…"
                : mode === "register"
                  ? "Creating account…"
                  : "Signing in…"
              : challenge
                ? "Verify Code"
                : mode === "register"
                  ? "Create Account"
                  : "Sign In"}
          </button>

          {challenge && (
            <button
              type="button"
              onClick={cancelMfa}
              disabled={busy}
              className="w-full rounded-lg border border-slate-700 px-4 py-2 text-xs font-medium text-slate-400 transition-colors hover:border-slate-500 hover:text-slate-200 disabled:opacity-50"
            >
              ← Back to sign in
            </button>
          )}

          {!challenge && mode === "login" && (sso?.oidc || sso?.ldap) && (
            <>
              <div className="flex items-center gap-3">
                <span className="h-px flex-1 bg-slate-800" />
                <span className="text-[10px] font-semibold uppercase tracking-widest text-slate-600">
                  Single sign-on
                </span>
                <span className="h-px flex-1 bg-slate-800" />
              </div>
              {sso?.oidc && (
                <a
                  href="/api/auth/oidc/login"
                  className="block w-full rounded-lg border border-slate-600 bg-slate-800 px-4 py-2.5 text-center text-sm font-semibold text-slate-200 transition-colors hover:border-slate-400 hover:bg-slate-700"
                >
                  Continue with SSO
                </a>
              )}
              {sso?.ldap && !sso?.oidc && (
                <p className="text-center text-[11px] text-slate-500">
                  Directory accounts sign in below with their corporate credentials.
                </p>
              )}
            </>
          )}

          {!challenge && mode !== "register" && (
            <button
              type="button"
              onClick={() => switchMode("register")}
              className="w-full rounded-lg border border-slate-700 px-4 py-2 text-xs font-medium text-slate-400 transition-colors hover:border-teal-500/50 hover:text-teal-300"
            >
              New here? Create an account
            </button>
          )}
          {!challenge && mode === "register" && (
            <button
              type="button"
              onClick={() => switchMode("login")}
              className="w-full rounded-lg border border-slate-700 px-4 py-2 text-xs font-medium text-slate-400 transition-colors hover:border-slate-500 hover:text-slate-200"
            >
              ← Back to sign in
            </button>
          )}

          {mode === "login" && (
            <p className="text-center text-[11px] text-slate-600">
              First run? The bootstrap password is in{" "}
              <span className="font-mono text-slate-500">first_run_credentials.txt</span>
            </p>
          )}
        </form>
      </div>
    </div>
  );
}
