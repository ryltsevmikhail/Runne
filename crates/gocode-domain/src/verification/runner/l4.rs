/// L4 authorization with full budget dimensions.
#[derive(Clone, Debug)]
pub struct L4Authorization {
    pub request_count: u64,
    pub token_budget: u64,
    pub tool_call_count: u64,
    pub wall_time_ms: u64,
    pub cost_budget_micros: u64,
    pub used_requests: u64,
    pub used_tokens: u64,
    pub used_tools: u64,
    pub used_wall_time: u64,
    pub used_cost: u64,
    pub revoked: bool,
}

impl L4Authorization {
    pub fn new(requests: u64, tokens: u64, tools: u64, wall_ms: u64, cost: u64) -> Self {
        Self {
            request_count: requests,
            token_budget: tokens,
            tool_call_count: tools,
            wall_time_ms: wall_ms,
            cost_budget_micros: cost,
            used_requests: 0,
            used_tokens: 0,
            used_tools: 0,
            used_wall_time: 0,
            used_cost: 0,
            revoked: false,
        }
    }

    pub fn reserve(
        &mut self,
        requests: u64,
        tokens: u64,
        tools: u64,
        wall_ms: u64,
        cost: u64,
    ) -> Result<(), String> {
        if self.revoked {
            return Err("revoked".into());
        }
        if self.used_requests + requests > self.request_count {
            return Err("request_count exceeded".into());
        }
        if self.used_tokens + tokens > self.token_budget {
            return Err("token_budget exceeded".into());
        }
        if self.used_tools + tools > self.tool_call_count {
            return Err("tool_call_count exceeded".into());
        }
        if self.used_wall_time + wall_ms > self.wall_time_ms {
            return Err("wall_time_ms exceeded".into());
        }
        if self.used_cost + cost > self.cost_budget_micros {
            return Err("cost_budget exceeded".into());
        }
        self.used_requests += requests;
        self.used_tokens += tokens;
        self.used_tools += tools;
        self.used_wall_time += wall_ms;
        self.used_cost += cost;
        Ok(())
    }

    pub fn revoke(&mut self) {
        self.revoked = true;
    }
}
