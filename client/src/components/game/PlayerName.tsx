interface PlayerNameProps {
  name: string | null | undefined
  maxLength?: number
}

export function PlayerName({ name, maxLength = 12 }: PlayerNameProps) {
  if (!name) return null
  const display = name.length > maxLength ? name.slice(0, maxLength) + '…' : name
  return <>{display}</>
}
