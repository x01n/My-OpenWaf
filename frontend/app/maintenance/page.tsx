export default function MaintenancePage() {
  return (
    <main className="min-h-svh bg-[radial-gradient(circle_at_top_left,#ecfeff,#f8fafc_38%,#eef2ff)] px-6 py-10 text-slate-950 dark:bg-[radial-gradient(circle_at_top_left,#164e63,#020617_54%,#030712)] dark:text-slate-50">
      <section className="mx-auto flex min-h-[calc(100svh-5rem)] max-w-3xl items-center justify-center">
        <div className="w-full overflow-hidden rounded-[2rem] border border-slate-200/80 bg-white/90 shadow-2xl shadow-slate-900/10 backdrop-blur dark:border-slate-700/70 dark:bg-slate-950/82 dark:shadow-black/40">
          <div className="h-1.5 bg-gradient-to-r from-cyan-500 via-blue-500 to-violet-500" />
          <div className="space-y-8 p-8 sm:p-10">
            <div className="flex flex-col gap-5 sm:flex-row sm:items-center">
              <div className="flex h-16 w-16 shrink-0 items-center justify-center rounded-2xl bg-cyan-50 text-3xl text-cyan-700 ring-1 ring-cyan-100 dark:bg-cyan-950/40 dark:text-cyan-200 dark:ring-cyan-900/60">
                i
              </div>
              <div className="space-y-2">
                <p className="text-xs font-bold tracking-[0.24em] text-slate-500 uppercase dark:text-slate-400">
                  Maintenance
                </p>
                <h1 className="text-3xl font-black tracking-tight sm:text-4xl">
                  服务维护中
                </h1>
                <p className="max-w-2xl text-sm leading-7 text-slate-600 dark:text-slate-300">
                  当前站点正在维护或临时下线。My-OpenWaf
                  已接管维护页展示，请稍后再试。
                </p>
              </div>
            </div>

            <div className="rounded-2xl border border-slate-200 bg-slate-50/80 p-4 text-sm dark:border-slate-800 dark:bg-slate-900/70">
              <div className="flex flex-col gap-1 sm:flex-row sm:items-center sm:justify-between">
                <span className="font-medium text-slate-500 dark:text-slate-400">
                  Request ID
                </span>
                <code className="rounded-lg bg-white px-3 py-1 font-mono break-all text-slate-950 ring-1 ring-slate-200 dark:bg-slate-950 dark:text-slate-100 dark:ring-slate-800">
                  __WAF_REQUEST_ID__
                </code>
              </div>
            </div>

            <div className="flex flex-col gap-3 text-xs text-slate-500 sm:flex-row sm:items-center sm:justify-between dark:text-slate-400">
              <span>Protected by My-OpenWaf</span>
              <span className="rounded-full border border-slate-200 bg-white px-3 py-1 dark:border-slate-800 dark:bg-slate-950">
                Next.js static maintenance page
              </span>
            </div>
          </div>
        </div>
      </section>
    </main>
  )
}
