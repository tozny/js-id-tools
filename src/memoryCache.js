class MemoryCache {
  /**
   * Creates a simple memory cache
   *
   * This cache will store items in memory until they reach the expires date, or
   * if no expires date is defined, indefinitely. Items are expired on access.
   *
   * Setting items will overwrite an item stored with the previous key.
   */
  constructor() {
    this._items = {}
  }
  /**
   * Get an item out of the cache.
   *
   * If the item is not in the cache or expired, undefined is returned. On an
   * expired item, the cache entry is removed.
   *
   * @param {string} key The key address to find an item at.
   * @returns {mixed} The cached object, or undefined if the items is not present.
   */
  get(key) {
    // if it is expired, clean it up
    if (
      this._items[key] &&
      this._items[key].expires &&
      new Date() > this._items[key].expires
    ) {
      delete this._items[key]
    }
    return this._items[key] ? this._items[key].value : undefined
  }
  /**
   * Determine if an item is available for a specific key and not expired.
   *
   * @param {string} key The key address to check is in the cache.
   * @returns {bool} Whether or not the key is available in the cache.
   */
  has(key) {
    return !!this.get(key)
  }
  /**
   * Set or reset a key in the cache to thee specified value.
   *
   * If expiration is sent, the item will expire after that date/time is reached.
   * Items are ejected on access through `get` or `has`.
   *
   * Calling set with the same key more than once will overwrite the old item
   * with the new value and expiration date.
   *
   * @param {string} key The key to store the cached item under
   * @param {mixed} value The value to store in the cache, any type is accepted
   * @param {Date} expires A JS Date representing when the cached item will expire
   */
  set(key, value, expires) {
    if (!(expires instanceof Date || expires === undefined)) {
      throw new Error('expires must be a Date or undefined')
    }
    this._items[key] = {
      value,
      expires,
    }
  }
  /**
   * Clear all items in the cache.
   */
  clear() {
    this._items = {}
  }
}

module.exports = MemoryCache
