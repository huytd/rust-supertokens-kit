import { createContext, useEffect, useState } from "react"

export type User = {
    id: string
    name: string
    email: string
    picture: string
}

export const UserContext = createContext<{
    user: User | null
    loading: boolean
    error: boolean
} | null>(null)

export const useUser = () => {
    const [loading, setLoading] = useState(false)
    const [user, setUser] = useState<User | null>(null)
    const [error, setError] = useState(false)

    useEffect(() => {
        setError(false)
        setLoading(true)
        fetch("/auth/me")
            .then((res) => {
                if (res.status === 401) {
                    setUser(null)
                    setError(true)
                } else {
                    res.json().then((user) => setUser(user))
                    setError(false)
                }
            })
            .finally(() => setLoading(false))
    }, [])

    return { loading, user, error }
}
