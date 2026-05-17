/**
 * Subscribe/notify store for cross-module shared state.
 *
 * Each accessor is `{ get, set, subscribe }`:
 *   - `get()` returns the current value
 *   - `set(v)` updates the value and synchronously fans out to all
 *     subscribers; identical-value writes are deduplicated and don't
 *     fire (Object.is comparison)
 *   - `subscribe(cb)` registers a listener and returns an unsubscribe
 *     function — call it to detach
 *
 * Lives alongside state.js, which still owns the legacy `state` object
 * and the shared Maps. Migration is incremental: fields move into the
 * store as their mutators get refactored — there's no flag-day cutover
 * and store + state can coexist while the move is in progress. Once a
 * field's last `state.X` reference is gone, drop it from state.js.
 *
 * Don't reach for Redux. The whole API surface here is one factory and
 * three methods per field; this is enough for the app's scale and lets
 * any future component layer subscribe without owning the source of
 * truth.
 */

/** Read-only listener invoked with the latest value on every change. */
export type Subscriber<T> = (value: T) => void;
/** Returned by `subscribe` — call to detach. */
export type Unsubscribe = () => void;

/** Reactive value with subscribe/notify semantics. The reference is
 *  identity-stable; only `value` changes via `set`. */
export interface Accessor<T> {
  get: () => T;
  set: (newValue: T) => void;
  subscribe: (callback: Subscriber<T>) => Unsubscribe;
}

function makeAccessor<T>(initial: T): Accessor<T> {
  let value = initial;
  const subscribers = new Set<Subscriber<T>>();
  return {
    get: () => value,
    set: (newValue: T) => {
      if (Object.is(value, newValue)) return;
      value = newValue;
      for (const cb of subscribers) cb(value);
    },
    subscribe: (callback: Subscriber<T>) => {
      subscribers.add(callback);
      return () => {
        subscribers.delete(callback);
      };
    },
  };
}

/**
 * IP of the device currently selected in the camera dropdown / device
 * list. `null` when nothing is selected. Mutated from devices.js (item
 * click) and network.js (dropdown change); read by the render path to
 * decide which list item gets the .selected class.
 */
export const selectedDevice: Accessor<string | null> = makeAccessor<string | null>(null);
