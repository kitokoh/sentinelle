import {
  createContext,
  useCallback,
  useContext,
  useMemo,
  useState,
  type ReactNode,
} from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { api, TOKEN_KEY } from '../lib/api'
import type { LoginResponse, User } from '../lib/types'

interface AuthContextValue {
  /** Utilisateur courant (null tant que /auth/me n'a pas répondu). */
  user: User | null
  /** Jeton JWT présent en session. */
  token: string | null
  /** Vrai pendant la vérification initiale de session. */
  isLoading: boolean
  login: (email: string, password: string) => Promise<void>
  register: (email: string, password: string) => Promise<void>
  logout: () => void
}

const AuthContext = createContext<AuthContextValue | null>(null)

export function AuthProvider({ children }: { children: ReactNode }) {
  const queryClient = useQueryClient()
  const [token, setToken] = useState<string | null>(() => localStorage.getItem(TOKEN_KEY))

  const meQuery = useQuery({
    queryKey: ['auth', 'me'],
    queryFn: async (): Promise<User> => {
      const { data } = await api.get<User>('/auth/me')
      return data
    },
    enabled: token !== null,
    retry: false,
    staleTime: 60_000,
  })

  const login = useCallback(
    async (email: string, password: string) => {
      const { data } = await api.post<LoginResponse>('/auth/login', { email, password })
      localStorage.setItem(TOKEN_KEY, data.access_token)
      setToken(data.access_token)
      await queryClient.invalidateQueries({ queryKey: ['auth', 'me'] })
    },
    [queryClient],
  )

  const register = useCallback(
    async (email: string, password: string) => {
      await api.post('/auth/register', { email, password })
      // Inscription réussie : connexion immédiate pour récupérer le jeton.
      await login(email, password)
    },
    [login],
  )

  const logout = useCallback(() => {
    localStorage.removeItem(TOKEN_KEY)
    setToken(null)
    queryClient.clear()
  }, [queryClient])

  const value = useMemo<AuthContextValue>(
    () => ({
      user: token ? meQuery.data ?? null : null,
      token,
      isLoading: token !== null && meQuery.isPending,
      login,
      register,
      logout,
    }),
    [token, meQuery.data, meQuery.isPending, login, register, logout],
  )

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext)
  if (!ctx) throw new Error('useAuth doit être utilisé dans un <AuthProvider>')
  return ctx
}
