import englishTargetSurfaces from './english-target-surfaces'

const targetSurfaces: Record<keyof typeof englishTargetSurfaces, string> = {
  'targetCapability.unavailable': 'Capability runtime недоступна',
  'targetCapability.unavailableDescription': 'Для этого экрана нужна capability runtime {capability}.',
}

export default targetSurfaces
