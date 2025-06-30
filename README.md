# Tutorial de Autenticação com Next.js 15, TypeScript, TailwindCSS e shadcn

Neste tutorial, vamos criar um sistema de autenticação usando Next.js 15 com as seguintes características:
- Página inicial como tela de login
- Rota autenticada com mensagem de boas-vindas
- Redirecionamento de rotas não autenticadas para login
- Integração com a API dummyjson.com para autenticação

## Pré-requisitos

- Node.js instalado (versão 18+)
- Yarn ou npm

## Passo 1: Criar o projeto Next.js

```bash
npx create-next-app@latest next-auth-tutorial --typescript --tailwind --eslint
cd next-auth-tutorial
```

## Passo 2: Instalar dependências adicionais

```bash
npm install @radix-ui/react-dropdown-menu @radix-ui/react-slot class-variance-authority clsx tailwind-merge lucide-react axios js-cookie
npx shadcn-ui@latest init
```

Durante a inicialização do shadcn, aceite os valores padrão.

## Passo 3: Configurar a estrutura de pastas

Crie a seguinte estrutura de pastas:

```
src/
  app/
    (auth)/
      login/
        page.tsx
    (protected)/
      welcome/
        page.tsx
    layout.tsx
    page.tsx
  components/
    auth/
      login-form.tsx
  lib/
    api.ts
    auth.ts
  middleware.ts
```

## Passo 4: Configurar o middleware de autenticação

Crie/edite `src/middleware.ts`:

```typescript
import { NextResponse } from 'next/server'
import type { NextRequest } from 'next/server'
import { verifyAuth } from './lib/auth'

export async function middleware(request: NextRequest) {
  const token = request.cookies.get('token')?.value
  const verifiedToken = token && (await verifyAuth(token).catch((err) => {
    console.error(err)
  }))

  // Se tentar acessar rota protegida sem token válido
  if (request.nextUrl.pathname.startsWith('/protected') && !verifiedToken) {
    return NextResponse.redirect(new URL('/auth/login', request.url))
  }

  // Se tentar acessar login com token válido
  if (request.nextUrl.pathname.startsWith('/auth/login') && verifiedToken) {
    return NextResponse.redirect(new URL('/protected/welcome', request.url))
  }

  return NextResponse.next()
}

export const config = {
  matcher: ['/protected/:path*', '/auth/login'],
}
```

## Passo 5: Criar utilitários de autenticação

Crie `src/lib/auth.ts`:

```typescript
import Cookies from 'js-cookie'
import { api } from './api'

interface AuthResponse {
  id: number
  username: string
  email: string
  firstName: string
  lastName: string
  gender: string
  image: string
  token: string
}

export const login = async (username: string, password: string): Promise<AuthResponse> => {
  try {
    const response = await api.post('/auth/login', {
      username,
      password,
    })
    
    if (response.data.token) {
      Cookies.set('token', response.data.token, { expires: 7 }) // Expira em 7 dias
    }
    
    return response.data
  } catch (error) {
    throw error
  }
}

export const logout = () => {
  Cookies.remove('token')
}

export const verifyAuth = async (token: string): Promise<boolean> => {
  try {
    const response = await api.get('/auth/me', {
      headers: {
        'Authorization': `Bearer ${token}`,
      },
    })
    return !!response.data
  } catch (error) {
    return false
  }
}

export const getCurrentUser = async (): Promise<AuthResponse | null> => {
  const token = Cookies.get('token')
  if (!token) return null

  try {
    const response = await api.get('/auth/me', {
      headers: {
        'Authorization': `Bearer ${token}`,
      },
    })
    return response.data
  } catch (error) {
    return null
  }
}
```

## Passo 6: Configurar a API client

Crie `src/lib/api.ts`:

```typescript
import axios from 'axios'

export const api = axios.create({
  baseURL: 'https://dummyjson.com',
  timeout: 5000,
})

api.interceptors.response.use(
  (response) => response,
  (error) => {
    return Promise.reject(error)
  }
)
```

## Passo 7: Criar o formulário de login

Crie `src/components/auth/login-form.tsx`:

```typescript
'use client'

import { useState } from 'react'
import { useRouter } from 'next/navigation'
import { Label } from '@/components/ui/label'
import { Input } from '@/components/ui/input'
import { Button } from '@/components/ui/button'
import { login } from '@/lib/auth'

export function LoginForm() {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [isLoading, setIsLoading] = useState(false)
  const router = useRouter()

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setIsLoading(true)
    setError('')

    try {
      await login(username, password)
      router.push('/protected/welcome')
    } catch (err) {
      setError('Credenciais inválidas. Tente novamente.')
      console.error(err)
    } finally {
      setIsLoading(false)
    }
  }

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      <div className="space-y-2">
        <Label htmlFor="username">Usuário</Label>
        <Input
          id="username"
          type="text"
          placeholder="kminchelle" // Usuário de teste da dummyjson
          value={username}
          onChange={(e) => setUsername(e.target.value)}
          required
        />
      </div>
      <div className="space-y-2">
        <Label htmlFor="password">Senha</Label>
        <Input
          id="password"
          type="password"
          placeholder="0lelplR" // Senha de teste da dummyjson
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          required
        />
      </div>
      {error && <p className="text-red-500 text-sm">{error}</p>}
      <Button type="submit" className="w-full" disabled={isLoading}>
        {isLoading ? 'Entrando...' : 'Entrar'}
      </Button>
    </form>
  )
}
```

## Passo 8: Criar a página de login

Crie `src/app/(auth)/login/page.tsx`:

```typescript
import { LoginForm } from '@/components/auth/login-form'

export default function LoginPage() {
  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-50">
      <div className="w-full max-w-md p-8 space-y-8 bg-white rounded-lg shadow-md">
        <div className="text-center">
          <h1 className="text-3xl font-bold">Next.js Auth</h1>
          <p className="mt-2 text-gray-600">Faça login para continuar</p>
        </div>
        <LoginForm />
      </div>
    </div>
  )
}
```

## Passo 9: Criar a página protegida

Crie `src/app/(protected)/welcome/page.tsx`:

```typescript
import { getCurrentUser } from '@/lib/auth'
import { Button } from '@/components/ui/button'
import { redirect } from 'next/navigation'

export default async function WelcomePage() {
  const user = await getCurrentUser()

  if (!user) {
    redirect('/auth/login')
  }

  const handleLogout = async () => {
    'use server'
    const { logout } = await import('@/lib/auth')
    logout()
    redirect('/auth/login')
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-50">
      <div className="w-full max-w-md p-8 space-y-8 bg-white rounded-lg shadow-md">
        <div className="text-center">
          <h1 className="text-3xl font-bold">Bem-vindo!</h1>
          <p className="mt-2 text-gray-600">
            Você está logado como {user.firstName} {user.lastName}
          </p>
        </div>
        <form action={handleLogout}>
          <Button type="submit" className="w-full">
            Sair
          </Button>
        </form>
      </div>
    </div>
  )
}
```

## Passo 10: Configurar o layout principal

Edite `src/app/layout.tsx`:

```typescript
import type { Metadata } from 'next'
import { Inter } from 'next/font/google'
import './globals.css'

const inter = Inter({ subsets: ['latin'] })

export const metadata: Metadata = {
  title: 'Next.js Auth',
  description: 'Tutorial de autenticação com Next.js 15',
}

export default function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <html lang="en">
      <body className={inter.className}>{children}</body>
    </html>
  )
}
```

## Passo 11: Configurar a página inicial

Edite `src/app/page.tsx`:

```typescript
import { redirect } from 'next/navigation'

export default function Home() {
  redirect('/auth/login')
}
```

## Passo 12: Configurar o TypeScript

Adicione ao `tsconfig.json` na seção `compilerOptions`:

```json
{
  "compilerOptions": {
    "paths": {
      "@/*": ["./src/*"]
    }
  }
}
```

## Explicação do controle de rotas no Next.js 15

No Next.js 15, temos várias abordagens para controle de rotas autenticadas:

1. **Middleware**: O arquivo `middleware.ts` intercepta todas as requisições antes de chegarem às páginas. Nele, verificamos:
   - Se o usuário tem um token válido ao acessar rotas protegidas
   - Se um usuário autenticado tenta acessar a página de login
   - Redirecionamentos apropriados em cada caso

2. **Grupos de rotas**: Usamos `(auth)` e `(protected)` para agrupar rotas sem afetar a URL:
   - `(auth)/login` → `/auth/login`
   - `(protected)/welcome` → `/protected/welcome`

3. **Server Components**: Nas páginas protegidas (como welcome), fazemos uma verificação adicional no servidor:
   - Se não houver usuário, redirecionamos para login
   - Isso fornece uma camada extra de segurança

4. **Cookies**: Armazenamos o token JWT em cookies HTTP-only para segurança:
   - O middleware consegue acessar os cookies da requisição
   - O cliente não tem acesso direto ao token

5. **API externa**: Integramos com dummyjson.com que fornece:
   - Endpoint `/auth/login` para autenticação
   - Endpoint `/auth/me` para verificar o token

## Testando a aplicação

1. Inicie o servidor:
```bash
npm run dev
```

2. Acesse `http://localhost:3000` - você deve ser redirecionado para `/auth/login`

3. Use as credenciais de teste:
   - Usuário: `kminchelle`
   - Senha: `0lelplR`

4. Após o login, você será redirecionado para `/protected/welcome`

5. Tente acessar qualquer rota em `/protected/*` sem estar autenticado - você será redirecionado para login

6. Ao clicar em "Sair", você será deslogado e redirecionado para a página de login

## Conclusão

Este tutorial demonstra como implementar um sistema de autenticação completo com Next.js 15, utilizando:

- Middleware para controle de acesso
- API externa para autenticação
- Cookies para armazenamento seguro de tokens
- Grupos de rotas para organização
- Server Components para verificação adicional
- UI moderna com shadcn e TailwindCSS

Você pode expandir este sistema adicionando:
- Registro de novos usuários
- Recuperação de senha
- Rotas protegidas baseadas em roles/permissões
- Refresh tokens
