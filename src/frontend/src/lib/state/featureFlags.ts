import { writable, type Writable } from "svelte/store";
import { FeatureFlag } from "$lib/utils/featureFlags";
import { isNullish, nonNullish } from "@dfinity/utils";
import { canisterConfig } from "$lib/globals";

declare global {
  interface Window {
    __featureFlags: Record<string, FeatureFlag>;
  }
}

type FeatureFlagStore = Writable<boolean> & {
  getFeatureFlag: () => FeatureFlag | undefined;
  initialize: () => void;
};

const LOCALSTORAGE_FEATURE_FLAGS_PREFIX = "ii-localstorage-feature-flags__";

const createFeatureFlagStore = (
  name: string,
  defaultValue: boolean,
  getInitValue?: () => boolean | undefined,
): FeatureFlagStore => {
  const { subscribe, set, update } = writable(defaultValue);

  // We cannot use browser because this is also imported in our showcase
  if (isNullish(globalThis.window)) {
    return {
      subscribe,
      set,
      update,
      getFeatureFlag: () => undefined,
      initialize: () => undefined,
    };
  }

  // Initialize feature flag object with value from localstorage
  const initializedFeatureFlag = new FeatureFlag(
    window.localStorage,
    LOCALSTORAGE_FEATURE_FLAGS_PREFIX + name,
    defaultValue,
    { subscribe, set, update },
  );

  // Make feature flags configurable from browser console
  // eslint-disable-next-line @typescript-eslint/ban-ts-comment
  // @ts-ignore
  if (typeof window.__featureFlags === "undefined") {
    window.__featureFlags = {};
  }
  window.__featureFlags[name] = initializedFeatureFlag;

  const getFeatureFlag = () => {
    return initializedFeatureFlag;
  };
  const initialize = (): void => {
    if (nonNullish(getInitValue)) {
      initializedFeatureFlag.set(getInitValue() ?? defaultValue);
    }
  };

  return {
    subscribe,
    set,
    update,
    getFeatureFlag,
    initialize,
  };
};

export const DOMAIN_COMPATIBILITY = createFeatureFlagStore(
  "DOMAIN_COMPATIBILITY",
  true,
);

export const OPENID_AUTHENTICATION = createFeatureFlagStore(
  "OPENID_AUTHENTICATION",
  false,
);

export const HARDWARE_KEY_TEST = createFeatureFlagStore(
  "HARDWARE_KEY_TEST",
  false,
);

export const DISCOVERABLE_PASSKEY_FLOW = createFeatureFlagStore(
  "DISCOVERABLE_PASSKEY_FLOW",
  false,
);

export const ENABLE_MIGRATE_FLOW = createFeatureFlagStore(
  "ENABLE_MIGRATE_FLOW",
  false,
);
export const ADD_ACCESS_METHOD = createFeatureFlagStore(
  "ADD_ACCESS_METHOD",
  true,
);

export const CONTINUE_FROM_ANOTHER_DEVICE = createFeatureFlagStore(
  "CONTINUE_FROM_ANOTHER_DEVICE",
  false,
  () => canisterConfig.feature_flag_continue_from_another_device[0],
);

export const FLAIR = createFeatureFlagStore("FLAIR", true);

export default {
  DOMAIN_COMPATIBILITY,
  OPENID_AUTHENTICATION,
  HARDWARE_KEY_TEST,
  DISCOVERABLE_PASSKEY_FLOW,
  ENABLE_MIGRATE_FLOW,
  ADD_ACCESS_METHOD,
  CONTINUE_FROM_ANOTHER_DEVICE,
  FLAIR,
} as Record<string, FeatureFlagStore>;
