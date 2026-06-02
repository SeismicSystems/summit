#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecutionRequestOrigin {
    CurrentBlock,
    Deferred,
}

impl ExecutionRequestOrigin {
    pub fn is_deferred(self) -> bool {
        matches!(self, Self::Deferred)
    }
}
