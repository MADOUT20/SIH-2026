/**
 * Deduplication & Deterministic Identity Utility for NetGuard
 * Provides safe helpers to deduplicate entity lists and warn in development
 * if duplicate entity IDs are encountered from APIs.
 */

/**
 * Deduplicates an array of items by a key extractor function or property name.
 * Preserves insertion order of the first occurrence.
 */
export function deduplicateBy<T>(
  items: T[] | null | undefined,
  keyFn: (item: T, index: number) => string | number | null | undefined,
  collectionName?: string
): T[] {
  if (!items || !Array.isArray(items) || items.length === 0) {
    return []
  }

  const seen = new Set<string>()
  const result: T[] = []
  const duplicates: Array<{ key: string; index: number }> = []

  for (let i = 0; i < items.length; i++) {
    const rawKey = keyFn(items[i], i)
    const key = rawKey !== null && rawKey !== undefined && rawKey !== "" 
      ? String(rawKey) 
      : `item-${i}`

    if (seen.has(key)) {
      duplicates.push({ key, index: i })
      continue
    }

    seen.add(key)
    result.push(items[i])
  }

  // Development-only diagnostic warning
  if (process.env.NODE_ENV === "development" && duplicates.length > 0 && collectionName) {
    console.debug(
      `[NetGuard Deduplication] Filtered ${duplicates.length} duplicate items in collection "${collectionName}":`,
      duplicates.map((d) => d.key).slice(0, 5)
    )
  }

  return result
}

/**
 * Deterministically formats a stable React key from entity identity components.
 * Fallbacks never use Math.random() or dynamic timestamps.
 */
export function createEntityKey(
  prefix: string,
  primaryId: string | number | null | undefined,
  fallbackParts?: Array<string | number | null | undefined>
): string {
  const parts: string[] = [prefix]

  if (primaryId !== null && primaryId !== undefined && String(primaryId).trim() !== "") {
    parts.push(String(primaryId).trim())
  }

  if (fallbackParts && fallbackParts.length > 0) {
    for (const p of fallbackParts) {
      if (p !== null && p !== undefined && String(p).trim() !== "") {
        const cleanPart = String(p).trim().replace(/[^a-zA-Z0-9_-]/g, "_")
        if (cleanPart.length > 0) {
          parts.push(cleanPart)
        }
      }
    }
  }

  if (parts.length === 1) {
    return `${prefix}-unknown`
  }

  return parts.join("-")
}
