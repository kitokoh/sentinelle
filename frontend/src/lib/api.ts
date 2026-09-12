import axios from 'axios'

export const TOKEN_KEY = 'sentinelle_token'

/**
 * Instance axios centralisée.
 * - baseURL '/api' : en dev, le proxy Vite redirige vers http://localhost:8000 ;
 *   en prod (Docker), nginx fait de même vers le service `api`.
 * - le jeton JWT est lu depuis localStorage et joint à chaque requête ;
 * - sur 401, la session est nettoyée et l'utilisateur renvoyé vers /login.
 */
export const api = axios.create({
  baseURL: import.meta.env.VITE_API_BASE_URL ?? '/api',
})

api.interceptors.request.use((config) => {
  const token = localStorage.getItem(TOKEN_KEY)
  if (token) {
    config.headers.Authorization = `Bearer ${token}`
  }
  return config
})

api.interceptors.response.use(
  (response) => response,
  (error: unknown) => {
    if (axios.isAxiosError(error) && error.response?.status === 401) {
      localStorage.removeItem(TOKEN_KEY)
      if (window.location.pathname !== '/login') {
        window.location.assign('/login')
      }
    }
    return Promise.reject(error)
  },
)

/** Extrait un message lisible depuis une erreur API (FastAPI `detail` string ou tableau de violations). */
export function getApiErrorMessage(err: unknown): string {
  if (axios.isAxiosError(err)) {
    const detail = (err.response?.data as { detail?: unknown } | undefined)?.detail
    if (typeof detail === 'string') return detail
    if (Array.isArray(detail)) {
      return detail
        .map((d) =>
          typeof d === 'object' && d !== null && 'msg' in d
            ? String((d as { msg: unknown }).msg)
            : String(d),
        )
        .join(' · ')
    }
    if (err.code === 'ERR_NETWORK') return 'API injoignable — vérifiez que le backend est démarré.'
    if (err.message) return err.message
  }
  return 'Une erreur inattendue est survenue.'
}
