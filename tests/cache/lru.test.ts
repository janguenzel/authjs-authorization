import { describe, it, expect, vi } from 'vitest';
import { LRUCache } from '../../src/cache/lru.js';

describe('LRUCache', () => {
  it('stores and retrieves values', () => {
    const cache = new LRUCache<string, number>();
    cache.set('a', 1);
    expect(cache.get('a')).toBe(1);
  });

  it('returns undefined for missing keys', () => {
    const cache = new LRUCache<string, number>();
    expect(cache.get('missing')).toBeUndefined();
  });

  it('evicts the oldest entry when maxSize is reached', () => {
    const cache = new LRUCache<string, number>({ maxSize: 3 });
    cache.set('a', 1);
    cache.set('b', 2);
    cache.set('c', 3);
    cache.set('d', 4); // should evict 'a'
    expect(cache.get('a')).toBeUndefined();
    expect(cache.get('b')).toBe(2);
    expect(cache.get('d')).toBe(4);
  });

  it('moves accessed entries to the end (LRU order)', () => {
    const cache = new LRUCache<string, number>({ maxSize: 3 });
    cache.set('a', 1);
    cache.set('b', 2);
    cache.set('c', 3);
    cache.get('a'); // access 'a' → moves to end
    cache.set('d', 4); // should evict 'b' (now oldest)
    expect(cache.get('a')).toBe(1);
    expect(cache.get('b')).toBeUndefined();
  });

  it('expires entries after ttlMs', () => {
    vi.useFakeTimers();
    const cache = new LRUCache<string, number>({ ttlMs: 1000 });
    cache.set('x', 42);
    expect(cache.get('x')).toBe(42);

    vi.advanceTimersByTime(1001);
    expect(cache.get('x')).toBeUndefined();
    vi.useRealTimers();
  });

  it('reports correct size', () => {
    const cache = new LRUCache<string, number>({ maxSize: 10 });
    cache.set('a', 1);
    cache.set('b', 2);
    expect(cache.size).toBe(2);
  });

  it('deletes entries', () => {
    const cache = new LRUCache<string, number>();
    cache.set('a', 1);
    cache.delete('a');
    expect(cache.get('a')).toBeUndefined();
  });

  it('clears all entries', () => {
    const cache = new LRUCache<string, number>();
    cache.set('a', 1);
    cache.set('b', 2);
    cache.clear();
    expect(cache.size).toBe(0);
  });
});
