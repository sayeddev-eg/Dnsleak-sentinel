export const USERS = [
  {
    id: 1,
    username: "admin",
    password: "admin123",
    role: "admin",
    name: "Admin User",
  },
  {
    id: 2,
    username: "analyst",
    password: "analyst123",
    role: "analyst",
    name: "Sara Analyst",
  },
  {
    id: 3,
    username: "viewer",
    password: "viewer123",
    role: "viewer",
    name: "Guest Viewer",
  },
]

export function login(username, password) {
  const user = USERS.find(
    (u) => u.username === username && u.password === password
  )
  if (!user) return null
  const { password: _, ...safe } = user
  return safe
}
