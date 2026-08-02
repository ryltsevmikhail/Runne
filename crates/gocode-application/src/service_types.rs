pub struct NoAgentLoopAuthorities;

pub struct AgentLoopAuthorities<T, R, W, C, V> {
    pub time: T,
    pub retry_schedule: R,
    pub wake_evidence: W,
    pub reconciliation: C,
    pub verification: V,
}

pub struct TaskRunService<E, U, I, A = NoAgentLoopAuthorities> {
    pipeline: Pipeline<E, U, I>,
    authorities: A,
}
