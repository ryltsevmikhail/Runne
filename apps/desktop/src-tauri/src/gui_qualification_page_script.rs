pub(super) fn build(phase: &str, workspace_id: &str) -> String {
    let workspace = serde_json::to_string(workspace_id).expect("Workspace ID JSON");
    let phase = serde_json::to_string(phase).expect("phase JSON");
    let prompt = if phase.contains("draft-") {
        serde_json::to_string(super::DRAFT_PROMPT).expect("draft prompt JSON")
    } else {
        serde_json::to_string("native lost-ack GUI receipt fixture").expect("prompt JSON")
    };
    format!(
        r#"(() => {{
          const workspace = {workspace}; const phase = {phase}; const prompt = {prompt};
          const probeToken = '018f2e3a-7000-7000-8000-000000000299';
          history.replaceState(null, '', '/workspaces/' + workspace);
          window.dispatchEvent(new PopStateEvent('popstate'));
          let editRendered = false; let sawPendingSave = false;
          const wait = (test, done, count = 0) => {{ if (test()) return done(); if (count > 1200) return; setTimeout(() => wait(test, done, count + 1), 50); }};
          const form = () => document.querySelector('.task-composer');
          const area = () => document.querySelector('#managed-task-prompt');
          const navigatedReceipt = () => {{ try {{ const value = JSON.parse(localStorage.getItem('runne:managed-task-run:' + workspace) || 'null'); return value?.navigated === true && value?.acceptedTaskRunId === location.pathname.split('/').pop(); }} catch {{ return false; }} }};
          const statuses = () => [...document.querySelectorAll('.task-composer [role="status"]')].map(node => node.textContent || '').join(' ');
          const saved = () => /Draft saved\.|Черновик сохранён\./i.test(statuses());
          const saveCycleComplete = () => {{ const text = statuses(); if (/Draft changes have not been saved|Saving draft securely|Изменения черновика ещё не сохранены|Защищённое сохранение черновика/i.test(text)) sawPendingSave = true; return editRendered && sawPendingSave && saved() && area()?.value === prompt; }};
          const noPlainDraft = () => ![...Array(localStorage.length)].some((_, index) => localStorage.getItem(localStorage.key(index) || '')?.includes(prompt));
          const fillPrompt = () => {{ const input = area(); if (!input || input.disabled) return false; if (input.value !== prompt) {{ editRendered = false; sawPendingSave = false; const setter = Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, 'value').set; setter.call(input, prompt); input.dispatchEvent(new Event('input', {{ bubbles: true }})); requestAnimationFrame(() => requestAnimationFrame(() => {{ editRendered = true; }})); }} return input.value === prompt; }};
          const probe = () => window.__TAURI_INTERNALS__?.invoke?.('recover_managed_task_run', {{ recoveryToken: probeToken }});
          const submit = () => {{ const button = form()?.querySelector('button[type="submit"]'); if (button && !button.disabled) button.click(); }};
          const fillAndSubmit = () => wait(() => fillPrompt() && !form()?.querySelector('button[type="submit"]')?.disabled, submit);
          if (phase === 'draft-save') wait(() => fillPrompt() && saveCycleComplete() && noPlainDraft(), probe);
          if (phase === 'draft-reload') wait(() => Boolean(form()) && area()?.value === prompt && saved() && noPlainDraft(), probe);
          if (phase === 'lost-ack') wait(() => Boolean(form()), fillAndSubmit);
          if (phase === 'recover') wait(() => location.pathname.startsWith('/task-runs/') && Boolean(document.querySelector('#task-run-title')) && navigatedReceipt(), async () => {{
            await window.__TAURI_INTERNALS__?.invoke?.('recover_managed_task_run', {{ recoveryToken: '__d2_gui_qualification_previous_token__' }});
          }});
          if (phase === 'fresh') wait(() => [...document.querySelectorAll('.task-composer button')].some(button => /Start a new task|Создать новую задачу/i.test(button.textContent || '')), () => {{
            const next = [...document.querySelectorAll('.task-composer button')].find(button => /Start a new task|Создать новую задачу/i.test(button.textContent || '')); next.click(); fillAndSubmit();
            wait(() => location.pathname.startsWith('/task-runs/'), () => {{ const bridge = window.__TAURI_INTERNALS__; bridge?.invoke?.('recover_managed_task_run', {{ recoveryToken: '__d2_gui_qualification_previous_token__' }}); }});
          }});
        }})();"#
    )
}
