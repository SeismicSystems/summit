System.register(['jotai/vanilla/internals'], (function (exports) {
  'use strict';
  var INTERNAL_buildStoreRev2;
  return {
    setters: [function (module) {
      INTERNAL_buildStoreRev2 = module.INTERNAL_buildStoreRev2;
    }],
    execute: (function () {

      exports({
        INTERNAL_overrideCreateStore: INTERNAL_overrideCreateStore,
        atom: atom,
        createStore: createStore,
        getDefaultStore: getDefaultStore
      });

      let keyCount = 0;
      function atom(read, write) {
        const key = `atom${++keyCount}`;
        const config = {
          toString() {
            return this.debugLabel ? key + ":" + this.debugLabel : key;
          }
        };
        if (typeof read === "function") {
          config.read = read;
        } else {
          config.init = read;
          config.read = defaultRead;
          config.write = defaultWrite;
        }
        if (write) {
          config.write = write;
        }
        return config;
      }
      function defaultRead(get) {
        return get(this);
      }
      function defaultWrite(get, set, arg) {
        return set(
          this,
          typeof arg === "function" ? arg(get(this)) : arg
        );
      }

      let overiddenCreateStore;
      function INTERNAL_overrideCreateStore(fn) {
        overiddenCreateStore = fn(overiddenCreateStore);
      }
      function createStore() {
        if (overiddenCreateStore) {
          return overiddenCreateStore();
        }
        return INTERNAL_buildStoreRev2();
      }
      let defaultStore;
      function getDefaultStore() {
        if (!defaultStore) {
          defaultStore = createStore();
          {
            globalThis.__JOTAI_DEFAULT_STORE__ || (globalThis.__JOTAI_DEFAULT_STORE__ = defaultStore);
            if (globalThis.__JOTAI_DEFAULT_STORE__ !== defaultStore) {
              console.warn(
                "Detected multiple Jotai instances. It may cause unexpected behavior with the default store. https://github.com/pmndrs/jotai/discussions/2044"
              );
            }
          }
        }
        return defaultStore;
      }

    })
  };
}));
