export function deferEffect(callback: () => void | Promise<void>) {
  const timer = window.setTimeout(() => {
    void callback()
  }, 0)

  return () => window.clearTimeout(timer)
}
