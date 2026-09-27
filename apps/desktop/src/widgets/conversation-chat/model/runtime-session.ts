import type { RuntimeSessionContext } from '@/app/providers/runtime-session'
import type { RuntimeConnectionState } from '@/shared/api/platform/bootstrap'

export function sessionCanMutate(session: RuntimeSessionContext | undefined): boolean {
  return session === undefined || (
    session.snapshot.value.status === 'live'
    && session.snapshot.value.canMutate
  )
}

export async function connectThroughSession(
  session: RuntimeSessionContext,
  allowRetry: boolean,
): Promise<RuntimeConnectionState> {
  if (sessionCanMutate(session)) return 'live'
  if (!allowRetry) return 'unconfigured'
  await session.retry()
  return sessionCanMutate(session) ? 'live' : 'unconfigured'
}
