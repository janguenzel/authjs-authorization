interface CacheEntry<V> {
  value: V;
  expiresAt: number;
}

export interface LRUCacheOptions {
  maxSize?: number;
  ttlMs?: number;
}

/**
 * Simple LRU cache backed by a Map (insertion-order = LRU order).
 * Evicts the oldest entry when maxSize is reached.
 * Entries expire after ttlMs milliseconds.
 */
export class LRUCache<K, V> {
  private readonly cache = new Map<K, CacheEntry<V>>();
  private readonly maxSize: number;
  private readonly ttlMs: number;

  constructor(options: LRUCacheOptions = {}) {
    this.maxSize = options.maxSize ?? 1000;
    this.ttlMs = options.ttlMs ?? 5 * 60 * 1000; // 5 minutes default
  }

  get(key: K): V | undefined {
    const entry = this.cache.get(key);
    if (entry === undefined) return undefined;

    if (Date.now() > entry.expiresAt) {
      this.cache.delete(key);
      return undefined;
    }

    // Move to end (most recently used)
    this.cache.delete(key);
    this.cache.set(key, entry);
    return entry.value;
  }

  set(key: K, value: V): void {
    if (this.cache.has(key)) {
      this.cache.delete(key);
    } else if (this.cache.size >= this.maxSize) {
      // Evict oldest (first entry in Map)
      const oldest = this.cache.keys().next().value;
      if (oldest !== undefined) {
        this.cache.delete(oldest);
      }
    }

    this.cache.set(key, {
      value,
      expiresAt: Date.now() + this.ttlMs,
    });
  }

  delete(key: K): boolean {
    return this.cache.delete(key);
  }

  clear(): void {
    this.cache.clear();
  }

  get size(): number {
    return this.cache.size;
  }

  has(key: K): boolean {
    const entry = this.cache.get(key);
    if (entry === undefined) return false;
    if (Date.now() > entry.expiresAt) {
      this.cache.delete(key);
      return false;
    }
    return true;
  }
}
