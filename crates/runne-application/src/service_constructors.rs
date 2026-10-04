impl<E: EventStore, U: UnitOfWork, I: IdGenerator> TaskRunService<E, U, I, NoAgentLoopAuthorities> {
    pub fn new(
        event_store: E,
        unit_of_work: U,
        id_generator: I,
        runtime_authority_id: RuntimeAuthorityId,
    ) -> Self {
        Self {
            pipeline: Pipeline {
                event_store,
                unit_of_work,
                id_generator,
                runtime_authority_id,
            },
            authorities: NoAgentLoopAuthorities,
            unknown_successor_repository: None,
        }
    }

    pub fn with_agent_loop_authorities<T, R, W, C, V>(
        event_store: E,
        unit_of_work: U,
        id_generator: I,
        runtime_authority_id: RuntimeAuthorityId,
        authorities: AgentLoopAuthorities<T, R, W, C, V>,
    ) -> TaskRunService<E, U, I, AgentLoopAuthorities<T, R, W, C, V>> {
        TaskRunService {
            pipeline: Pipeline {
                event_store,
                unit_of_work,
                id_generator,
                runtime_authority_id,
            },
            authorities,
            unknown_successor_repository: None,
        }
    }
}
