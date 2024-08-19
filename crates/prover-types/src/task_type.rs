
#[derive(Clone, Debug, PartialEq, Eq, Copy)]
pub enum TaskType {
    Scroll,
    Linea,
    Other(u64),
}

impl From<u64> for TaskType {
    fn from(n: u64) -> Self {
        Self::from_u64(n)
    }
}

impl TaskType {
    pub fn name(&self) -> String {
        match self {
            Self::Scroll => "scroll".into(),
            Self::Linea => "linea".into(),
            Self::Other(n) => format!("task type {}", n),
        }
    }

    pub fn u64(&self) -> u64 {
        match self {
            Self::Scroll => 1,
            Self::Linea => 2,
            Self::Other(n) => *n,
        }
    }

    pub fn from_u64(ty: u64) -> TaskType {
        match ty {
            1 => Self::Scroll,
            2 => Self::Linea,
            n => Self::Other(n),
        }
    }
}
