import { translate } from '@/shared/i18n'
import type { ConversationSnapshot } from '@/entities/conversation'

export function conversationRecoveryCopy(state: ConversationSnapshot['recovery'] | 'live') {
  switch (state) {
    case 'live':
      return null
    case 'reconnecting':
      return translate('conversation.reconnecting')
    case 'incompatible':
      return translate('conversation.incompatible')
    case 'revoked':
      return translate('conversation.revoked')
    case 'resync_required':
      return translate('conversation.resyncRequired')
    case 'fatal':
      return translate('conversation.recoveryFailed')
    default:
      return null
  }
}
