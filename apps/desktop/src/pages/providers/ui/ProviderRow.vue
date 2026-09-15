<script setup lang="ts">
import { computed } from 'vue'

import {
  credentialActionLabel,
  isManualOAuthProvider,
  providerCatalogDisplayName,
  providerHasSubscription,
} from '@/pages/providers/model/providerPageHelpers'
import { isCredentialProvider, isEnrollableProvider } from '@/shared/api/platform/providerCatalog'
import type {
  ProviderCatalogSnapshot,
  ProviderCredentialProjection,
  ProviderId,
  ProviderStatusSnapshot,
} from '@/shared/api/platform/providers'
import { translate } from '@/shared/i18n'
import type { ProviderQuotaAvailability, ProviderQuotaSource } from '@/pages/providers/model/providerQuota'

const props = defineProps<{
  readonly status: ProviderStatusSnapshot
  readonly catalog: ProviderCatalogSnapshot | undefined
  readonly credential: ProviderCredentialProjection | undefined
  readonly quotaSummary: string | undefined
  readonly quotaSource: ProviderQuotaSource | undefined
  readonly quotaAvailability: ProviderQuotaAvailability | undefined
  readonly quotaWindows: readonly string[]
  readonly quotaRefreshSupported: boolean
  readonly readiness: string
  readonly readinessSource: string
  readonly busy: boolean
  readonly note: string | undefined
}>()

const emit = defineEmits<{
  credentialAction: [action: 'pair' | 'revoke' | 'verify']
}>()

const hasCredential = computed(() => props.credential?.credentialState === 'configured')
const canEnroll = computed(() => isEnrollableProvider(props.status.providerId))
const canRefreshQuota = computed(() => props.quotaRefreshSupported && hasCredential.value)
const actionLabel = computed(() => credentialActionLabel(props.status.providerId, hasCredential.value))
const isOAuth = computed(() => isManualOAuthProvider(props.status.providerId))

function actionAriaLabel(action: 'pair' | 'revoke' | 'verify'): string {
  const label = action === 'revoke'
    ? translate('providers.revokeCredential')
    : action === 'verify' ? translate('providers.refreshQuota') : actionLabel.value
  return `${label} (${props.status.providerId})`
}

function providerName(providerId: ProviderId): string {
  return props.catalog?.displayName ?? providerCatalogDisplayName(providerId)
}
</script>

<template>
  <li :data-provider-id="status.providerId">
    <strong>{{ providerName(status.providerId) }}</strong>
    <span v-if="catalog?.implementation === 'catalog_only'">
      {{ translate('providers.integrationPlanned') }}
    </span>
    <span>{{ status.selected ? translate('providers.selected') : translate('providers.notSelected') }}</span>
    <span
      data-readiness="true"
      :data-readiness-source="readinessSource"
    >
      {{ readiness }} ({{ readinessSource }})
    </span>
    <span
      v-if="quotaSummary"
      data-quota="true"
      :data-quota-source="quotaSource"
      :data-quota-availability="quotaAvailability"
    >
      {{ quotaSummary }}
      <span
        v-for="window in quotaWindows"
        :key="window"
      >{{ window }}</span>
    </span>
    <span v-if="providerHasSubscription(status.providerId)">
      {{ translate('providers.subscriptionLimited') }}
    </span>
    <p v-if="isOAuth && isCredentialProvider(status.providerId)">
      <strong>{{ translate('providers.connection.oauthTitle') }}</strong>
      {{ translate('providers.connection.oauthHint') }}
    </p>
    <p v-else-if="isCredentialProvider(status.providerId)">
      <strong>{{ translate('providers.connection.apiKeyTitle') }}</strong>
      {{ translate('providers.connection.apiKeyHint') }}
    </p>
    <template v-if="canEnroll">
      <button
        type="button"
        :aria-label="actionAriaLabel('pair')"
        :disabled="busy"
        @click="emit('credentialAction', 'pair')"
      >
        {{ actionLabel }}
      </button>
      <button
        v-if="hasCredential"
        type="button"
        :aria-label="actionAriaLabel('revoke')"
        :disabled="busy"
        @click="emit('credentialAction', 'revoke')"
      >
        {{ translate('providers.revokeCredential') }}
      </button>
      <button
        v-if="canRefreshQuota"
        type="button"
        :aria-label="actionAriaLabel('verify')"
        :disabled="busy"
        @click="emit('credentialAction', 'verify')"
      >
        {{ translate('providers.refreshQuota') }}
      </button>
      <span
        v-if="note"
        role="status"
      >{{ note }}</span>
    </template>
  </li>
</template>
