/**
 * PERFORMANCE OPTIMIZATIONS
 * =========================
 * Central caching and performance utilities
 */

class PerformanceCache {
    constructor() {
        this.cache = new Map();
        this.stats = { hits: 0, misses: 0 };
    }

    // Get cached value or compute and cache
    async getOrCompute(key, computeFn, ttlMs = 60000) {
        const cached = this.cache.get(key);
        if (cached && Date.now() < cached.expires) {
            this.stats.hits++;
            return cached.value;
        }
        
        this.stats.misses++;
        const value = await computeFn();
        this.cache.set(key, { value, expires: Date.now() + ttlMs });
        return value;
    }

    // Sync version
    getOrComputeSync(key, computeFn, ttlMs = 60000) {
        const cached = this.cache.get(key);
        if (cached && Date.now() < cached.expires) {
            this.stats.hits++;
            return cached.value;
        }
        
        this.stats.misses++;
        const value = computeFn();
        this.cache.set(key, { value, expires: Date.now() + ttlMs });
        return value;
    }

    invalidate(key) {
        this.cache.delete(key);
    }

    invalidatePattern(pattern) {
        const regex = new RegExp(pattern);
        for (const key of this.cache.keys()) {
            if (regex.test(key)) this.cache.delete(key);
        }
    }

    clear() {
        this.cache.clear();
    }

    getStats() {
        const hitRate = this.stats.hits + this.stats.misses > 0 
            ? ((this.stats.hits / (this.stats.hits + this.stats.misses)) * 100).toFixed(1)
            : 0;
        return {
            ...this.stats,
            hitRate: `${hitRate}%`,
            size: this.cache.size
        };
    }

    // Auto-cleanup expired entries every 5 minutes
    startCleanup() {
        setInterval(() => {
            const now = Date.now();
            for (const [key, entry] of this.cache.entries()) {
                if (now > entry.expires) this.cache.delete(key);
            }
        }, 300000);
    }
}

// Debounce function for reducing rapid fire calls
function debounce(fn, delay = 300) {
    let timeoutId;
    return function (...args) {
        clearTimeout(timeoutId);
        timeoutId = setTimeout(() => fn.apply(this, args), delay);
    };
}

// Throttle function for rate limiting
function throttle(fn, limit = 1000) {
    let lastCall = 0;
    return function (...args) {
        const now = Date.now();
        if (now - lastCall >= limit) {
            lastCall = now;
            return fn.apply(this, args);
        }
    };
}

// Batch processor for grouping operations
class BatchProcessor {
    constructor(processFn, maxBatchSize = 10, maxWaitMs = 100) {
        this.processFn = processFn;
        this.maxBatchSize = maxBatchSize;
        this.maxWaitMs = maxWaitMs;
        this.queue = [];
        this.timeout = null;
    }

    add(item) {
        return new Promise((resolve, reject) => {
            this.queue.push({ item, resolve, reject });
            
            if (this.queue.length >= this.maxBatchSize) {
                this.flush();
            } else if (!this.timeout) {
                this.timeout = setTimeout(() => this.flush(), this.maxWaitMs);
            }
        });
    }

    async flush() {
        clearTimeout(this.timeout);
        this.timeout = null;
        
        if (this.queue.length === 0) return;
        
        const batch = this.queue.splice(0, this.maxBatchSize);
        try {
            const results = await this.processFn(batch.map(b => b.item));
            batch.forEach((b, i) => b.resolve(results[i]));
        } catch (err) {
            batch.forEach(b => b.reject(err));
        }
    }
}

// Lazy loader for expensive resources
class LazyLoader {
    constructor(loadFn) {
        this.loadFn = loadFn;
        this.value = null;
        this.loading = null;
    }

    async get() {
        if (this.value !== null) return this.value;
        if (this.loading !== null) return this.loading;
        
        this.loading = this.loadFn().then(val => {
            this.value = val;
            this.loading = null;
            return val;
        });
        
        return this.loading;
    }

    reset() {
        this.value = null;
        this.loading = null;
    }
}

// Request timeout wrapper
function withTimeout(promise, timeoutMs = 5000, errorMessage = 'Operation timed out') {
    return Promise.race([
        promise,
        new Promise((_, reject) => 
            setTimeout(() => reject(new Error(errorMessage)), timeoutMs)
        )
    ]);
}

// Parallel execution with concurrency limit
async function parallelLimit(tasks, limit = 3) {
    const results = [];
    const executing = new Set();
    
    for (const task of tasks) {
        const promise = Promise.resolve().then(() => task()).then(result => {
            executing.delete(promise);
            return result;
        });
        
        results.push(promise);
        executing.add(promise);
        
        if (executing.size >= limit) {
            await Promise.race(executing);
        }
    }
    
    return Promise.all(results);
}

// Create singleton cache instances
const modelListCache = new PerformanceCache();
const knowledgeCache = new PerformanceCache();
const metricsCache = new PerformanceCache();

modelListCache.startCleanup();
knowledgeCache.startCleanup();
metricsCache.startCleanup();

module.exports = {
    PerformanceCache,
    BatchProcessor,
    LazyLoader,
    debounce,
    throttle,
    withTimeout,
    parallelLimit,
    // Shared cache instances
    modelListCache,
    knowledgeCache,
    metricsCache
};
