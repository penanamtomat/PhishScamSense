/**
 * Counting Bloom Filter implementation for client-side URL blacklist management.
 * Provides O(1) lookups with configurable false positive rate.
 */
export class BloomFilter {
  private buckets: Uint8Array;
  private numHashes: number;

  constructor(size: number, numHashes: number) {
    this.buckets = new Uint8Array(size);
    this.numHashes = numHashes;
  }

  private hash(value: string, seed: number): number {
    let h = seed;
    for (let i = 0; i < value.length; i++) {
      h = (h * 31 + value.charCodeAt(i)) >>> 0;
    }
    return h % this.buckets.length;
  }

  add(value: string): void {
    for (let i = 0; i < this.numHashes; i++) {
      const index = this.hash(value, i);
      if (this.buckets[index] < 255) {
        this.buckets[index]++;
      }
    }
  }

  contains(value: string): boolean {
    for (let i = 0; i < this.numHashes; i++) {
      const index = this.hash(value, i);
      if (this.buckets[index] === 0) return false;
    }
    return true;
  }

  remove(value: string): void {
    if (!this.contains(value)) return;
    for (let i = 0; i < this.numHashes; i++) {
      const index = this.hash(value, i);
      if (this.buckets[index] > 0) {
        this.buckets[index]--;
      }
    }
  }

  loadFromData(data: number[]): void {
    this.buckets = new Uint8Array(data);
  }

  exportData(): number[] {
    return Array.from(this.buckets);
  }
}
