import englishConversationTarget from './english-conversation-target'

const conversationTarget: Record<keyof typeof englishConversationTarget, string> = {
  'workspace.showProjectTree': 'Показать файлы',
  'workspace.hideProjectTree': 'Скрыть файлы',
  'workspace.showDetails': 'Показать детали',
  'workspace.hideDetails': 'Скрыть детали',
  'conversationControls.unavailable': 'Дополнительные элементы чата недоступны',
  'conversationControls.unavailableDescription': 'Для команд, контекста, агента, модели и бюджета нужна capability runtime.',
  'conversationControls.command': 'Команды недоступны',
  'conversationControls.context': 'Контекст недоступен',
  'conversationControls.agent': 'Агент недоступен',
  'conversationControls.model': 'Модель недоступна',
  'conversationControls.budget': 'Бюджет недоступен',
}

export default conversationTarget
