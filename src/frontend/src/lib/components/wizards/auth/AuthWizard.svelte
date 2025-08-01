<script lang="ts">
  import { nonNullish } from "@dfinity/utils";
  import { AuthFlow } from "$lib/flows/authFlow.svelte";
  import type { Snippet } from "svelte";
  import SolveCaptcha from "$lib/components/wizards/auth/views/SolveCaptcha.svelte";
  import PickAuthenticationMethod from "$lib/components/wizards/auth/views/PickAuthenticationMethod.svelte";
  import Dialog from "$lib/components/ui/Dialog.svelte";
  import SetupOrUseExistingPasskey from "$lib/components/wizards/auth/views/SetupOrUseExistingPasskey.svelte";
  import CreatePasskey from "$lib/components/wizards/auth/views/CreatePasskey.svelte";
  import SystemOverlayBackdrop from "$lib/components/utils/SystemOverlayBackdrop.svelte";
  import { RegisterAccessMethodWizard } from "$lib/components/wizards/registerAccessMethod";

  interface Props {
    isAuthenticating?: boolean;
    onSignIn: (identityNumber: bigint) => void;
    onSignUp: (identityNumber: bigint) => void;
    onOtherDevice?: (identityNumber: bigint) => void; // TODO: Remove once we can sign in directly
    onError: (error: unknown) => void;
    withinDialog?: boolean;
    children?: Snippet;
  }

  let {
    isAuthenticating = $bindable(),
    onSignIn,
    onSignUp,
    onOtherDevice = () => {},
    onError,
    withinDialog = false,
    children,
  }: Props = $props();

  const authFlow = new AuthFlow();

  let isContinueFromAnotherDeviceVisible = $state(false);

  const handleContinueWithExistingPasskey = async () => {
    isAuthenticating = true;
    try {
      onSignIn(await authFlow.continueWithExistingPasskey());
    } catch (error) {
      onError(error);
    } finally {
      isAuthenticating = false;
    }
  };
  const handleCreatePasskey = async (name: string) => {
    isAuthenticating = true;
    try {
      onSignUp(await authFlow.createPasskey(name));
    } catch (error) {
      onError(error);
    } finally {
      isAuthenticating = false;
    }
  };
  const handleContinueWithGoogle = async () => {
    isAuthenticating = true;
    try {
      const { identityNumber, type } = await authFlow.continueWithGoogle();
      (type === "signUp" ? onSignUp : onSignIn)(identityNumber);
    } catch (error) {
      onError(error);
    } finally {
      isAuthenticating = false;
    }
  };
</script>

{#snippet dialogContent()}
  {#if authFlow.view === "setupOrUseExistingPasskey"}
    <SetupOrUseExistingPasskey
      setupNew={authFlow.setupNewPasskey}
      useExisting={handleContinueWithExistingPasskey}
    />
  {:else if authFlow.view === "setupNewPasskey"}
    <CreatePasskey create={handleCreatePasskey} />
  {/if}
{/snippet}

{#if isContinueFromAnotherDeviceVisible}
  <RegisterAccessMethodWizard onRegistered={onOtherDevice} {onError} />
{:else if nonNullish(authFlow.captcha)}
  <SolveCaptcha {...authFlow.captcha} />
{:else}
  {#if authFlow.view === "chooseMethod" || !withinDialog}
    {@render children?.()}
    <PickAuthenticationMethod
      setupOrUseExistingPasskey={authFlow.setupOrUseExistingPasskey}
      continueWithGoogle={handleContinueWithGoogle}
      continueFromAnotherDevice={() =>
        (isContinueFromAnotherDeviceVisible = true)}
    />
  {/if}
  {#if authFlow.view !== "chooseMethod"}
    {#if !withinDialog}
      <Dialog
        onClose={authFlow.chooseMethod}
        showCloseButton={!isAuthenticating}
        closeOnOutsideClick={!isAuthenticating}
      >
        {@render dialogContent()}
      </Dialog>
    {:else}
      {@render dialogContent()}
    {/if}
  {/if}
{/if}

{#if authFlow.systemOverlay}
  <SystemOverlayBackdrop />
{/if}
