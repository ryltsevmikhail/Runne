const startupStatus = document.querySelector<HTMLElement>('#startup-status')

if (startupStatus !== null) {
  startupStatus.setAttribute('role', 'status')
  startupStatus.setAttribute('aria-live', 'polite')
  startupStatus.querySelector('h1')!.textContent = 'Starting Runne…'
  startupStatus.querySelector('p')!.textContent = 'Loading the app.'

  try {
    await import('../main')
    startupStatus.remove()
  }
  catch {
    startupStatus.setAttribute('role', 'alert')
    startupStatus.setAttribute('aria-live', 'assertive')
    startupStatus.querySelector('h1')!.textContent = 'Runne couldn’t start'
    startupStatus.querySelector('p')!.textContent =
      'Part of the app failed to load. Refresh the page to try again.'
  }
}

export {}
