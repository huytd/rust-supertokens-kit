import { AppShell, Box, Group, Header } from "@mantine/core"
import { UserContext, useUser } from "./lib/user"
import UserMenu from "./components/UserMenu"

function App() {
    const profile = useUser()
    return (
        <UserContext.Provider value={profile}>
            <AppShell
                header={
                    <Header height={60} p="md">
                        <Group position="apart">
                            <Box>App</Box>
                            <UserMenu />
                        </Group>
                    </Header>
                }
            >
                Hello
            </AppShell>
        </UserContext.Provider>
    )
}

export default App
