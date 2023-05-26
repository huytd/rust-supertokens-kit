import {
    Avatar,
    Group,
    Menu,
    UnstyledButton,
    Text,
    rem,
    Button,
} from "@mantine/core"
import {
    IconChevronDown,
    IconLogout,
    IconSettings,
    IconUser,
} from "@tabler/icons-react"
import { useContext } from "react"
import { UserContext } from "../lib/user"
import { Link } from "react-router-dom"

export default function UserMenu() {
    const profile = useContext(UserContext)
    if (!profile?.loading) {
        return !profile?.error ? (
            <Menu width={150}>
                <Menu.Target>
                    <UnstyledButton>
                        <Group spacing={"xs"}>
                            <Avatar
                                src={profile?.user?.picture}
                                radius="xl"
                                size={26}
                                imageProps={{
                                    referrerPolicy: "no-referrer",
                                }}
                            />
                            <Text size="sm" weight={500}>
                                {profile?.user?.name}
                            </Text>
                            <IconChevronDown size={rem(12)} stroke={1.5} />
                        </Group>
                    </UnstyledButton>
                </Menu.Target>
                <Menu.Dropdown>
                    <Menu.Item icon={<IconUser size={rem(14)} stroke={1.5} />}>
                        Profile
                    </Menu.Item>
                    <Menu.Item
                        icon={<IconSettings size={rem(14)} stroke={1.5} />}
                    >
                        Settings
                    </Menu.Item>
                    <Link
                        to="/auth/logout"
                        reloadDocument
                        style={{ textDecoration: "none" }}
                    >
                        <Menu.Item
                            icon={<IconLogout size={rem(14)} stroke={1.5} />}
                        >
                            Logout
                        </Menu.Item>
                    </Link>
                </Menu.Dropdown>
            </Menu>
        ) : (
            <Link to="/auth/google/login" reloadDocument>
                <Button variant="white">Login</Button>
            </Link>
        )
    }
    return null
}
